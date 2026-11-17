package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"testing"
	"time"

	"mcwatch/internal/protocol"
)

func TestHistoryReplaysLast500Lines(t *testing.T) {
	s := NewControlServer("secret", false, nil, discardLog)
	for i := 0; i < HistoryLines+7; i++ {
		s.PublishLine(fmt.Sprintf("line-%03d", i))
	}
	history := s.History()
	if len(history) != HistoryLines {
		t.Fatalf("history length = %d, want %d", len(history), HistoryLines)
	}
	if history[0] != "line-007" || history[len(history)-1] != "line-506" {
		t.Fatalf("unexpected history bounds: first=%q last=%q", history[0], history[len(history)-1])
	}
}

func TestEightClientsFullNinthRejectedAndWrongSecretNoSlot(t *testing.T) {
	s := NewControlServer("a sufficiently long shared secret", false, nil, discardLog)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	serveDone := make(chan error, 1)
	go func() { serveDone <- s.Serve(ctx, listener) }()
	defer func() {
		cancel()
		select {
		case err := <-serveDone:
			if err != nil {
				t.Errorf("Serve() error: %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Error("Serve did not shut down")
		}
	}()

	wrongConn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := protocol.ClientHandshake(wrongConn, "wrong secret"); err == nil {
		t.Fatal("wrong-secret client authenticated")
	}
	if err := wrongConn.Close(); err != nil {
		t.Fatal(err)
	}
	if got := s.ClientCount(); got != 0 {
		t.Fatalf("wrong-secret client consumed a slot: %d", got)
	}

	clients := make([]*protocol.Session, 0, MaxClients)
	for i := 0; i < MaxClients; i++ {
		conn, err := net.Dial("tcp", listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		session, err := protocol.ClientHandshake(conn, "a sufficiently long shared secret")
		if err != nil {
			t.Fatal(err)
		}
		clients = append(clients, session)
	}
	waitFor(t, func() bool { return s.ClientCount() == MaxClients })

	ninthConn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	ninth, err := protocol.ClientHandshake(ninthConn, "a sufficiently long shared secret")
	if err != nil {
		t.Fatal(err)
	}
	msg, err := ninth.Receive()
	if err != nil {
		t.Fatal(err)
	}
	var response protocol.CommandResponse
	if msg.Type != protocol.TypeServerFull || json.Unmarshal(msg.Payload, &response) != nil || response.Text != "server full" {
		t.Fatalf("unexpected full response: type=%d payload=%q", msg.Type, msg.Payload)
	}
	_ = ninth.Close()
	if got := s.ClientCount(); got != MaxClients {
		t.Fatalf("ninth client changed count to %d", got)
	}
	for _, c := range clients {
		_ = c.Close()
	}
}

func TestSlowClientIsDroppedWithoutBlockingPublisher(t *testing.T) {
	s := NewControlServer("secret", false, nil, discardLog)
	left, right := net.Pipe()
	serverResult := make(chan *protocol.Session, 1)
	go func() {
		session, _ := protocol.ServerHandshake(right, "secret")
		serverResult <- session
	}()
	clientSession, err := protocol.ClientHandshake(left, "secret")
	if err != nil {
		t.Fatal(err)
	}
	serverSession := <-serverResult
	c := &client{
		id:      1,
		remote:  "test",
		session: serverSession,
		out:     make(chan outbound, 1),
		done:    make(chan struct{}),
		server:  s,
	}
	s.clients[c.id] = c
	fast := &client{
		id:     2,
		remote: "fast",
		out:    make(chan outbound, 8),
		done:   make(chan struct{}),
		server: s,
	}
	s.clients[fast.id] = fast
	s.PublishLine("queued line")
	start := time.Now()
	s.PublishLine("overflow line")
	if time.Since(start) > 100*time.Millisecond {
		t.Fatal("publishing to a slow client blocked")
	}
	if got := s.ClientCount(); got != 1 {
		t.Fatalf("slow client was not dropped while keeping fast client; count=%d", got)
	}
	for _, expected := range []string{"queued line", "overflow line"} {
		item := <-fast.out
		if item.message.Type != protocol.TypeLogLine || string(item.message.Payload) != expected {
			t.Fatalf("fast client got %q, want %q", item.message.Payload, expected)
		}
	}
	_ = clientSession.Close()
	s.mu.Lock()
	delete(s.clients, fast.id)
	s.mu.Unlock()
}

func TestCommandDisabledAndRateLimited(t *testing.T) {
	var sent []string
	s := NewControlServer("secret", true, func(_ uint64, command string) error {
		sent = append(sent, command)
		return nil
	}, discardLog)
	c := &client{server: s, out: make(chan outbound, 16), done: make(chan struct{})}
	for i := 0; i < 6; i++ {
		c.handleCommand([]byte(fmt.Sprintf("say %d", i)))
	}
	if len(sent) != 5 {
		t.Fatalf("commands passed through = %d, want 5", len(sent))
	}
	var last protocol.CommandResponse
	item := <-c.out
	for len(c.out) > 0 {
		item = <-c.out
	}
	if err := json.Unmarshal(item.message.Payload, &last); err != nil {
		t.Fatal(err)
	}
	if last.Text != "rate limit exceeded (5 commands per 10 seconds)" {
		t.Fatalf("last response = %q", last.Text)
	}

	disabled := NewControlServer("secret", false, nil, discardLog)
	disabledClient := &client{server: disabled, out: make(chan outbound, 1), done: make(chan struct{})}
	disabledClient.handleCommand([]byte("say no"))
	item = <-disabledClient.out
	if err := json.Unmarshal(item.message.Payload, &last); err != nil {
		t.Fatal(err)
	}
	if last.Text != "commands disabled" {
		t.Fatalf("disabled response = %q", last.Text)
	}
}

func TestHistorySentAtConnect(t *testing.T) {
	s := NewControlServer("history test secret", false, nil, discardLog)
	s.PublishLine("earlier-1")
	s.PublishLine("earlier-2")
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Serve(ctx, listener) }()
	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	session, err := protocol.ClientHandshake(conn, "history test secret")
	if err != nil {
		t.Fatal(err)
	}
	found := map[string]bool{}
	for len(found) < 2 {
		msg, err := session.Receive()
		if err != nil {
			t.Fatal(err)
		}
		if msg.Type == protocol.TypeLogLine {
			found[string(msg.Payload)] = true
		}
	}
	if !found["earlier-1"] || !found["earlier-2"] {
		t.Fatalf("history replay missing lines: %#v", found)
	}
	_ = session.Close()
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Serve did not shut down")
	}
}

func waitFor(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition not met before deadline")
}

func discardLog(string, ...any) {}

// Package server provides bounded client handling and console-log fanout.
package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"mcwatch/internal/protocol"
)

const (
	MaxClients       = 8
	HistoryLines     = 500
	clientQueueSize  = 520
	maxPendingClient = 4
	pingInterval     = 15 * time.Second
	pingTimeout      = protocol.HeartbeatTTL
)

type CommandHandler func(clientID uint64, command string) error
type LogFunc func(format string, args ...any)

type ControlServer struct {
	secret        string
	allowCommands bool
	onCommand     CommandHandler
	logf          LogFunc

	mu        sync.Mutex
	clients   map[uint64]*client
	nextID    uint64
	history   []string
	historyAt int
	historyN  int
	status    protocol.Status
	pending   chan struct{}
	clientWG  sync.WaitGroup
}

type client struct {
	id       uint64
	remote   string
	session  *protocol.Session
	out      chan outbound
	done     chan struct{}
	server   *ControlServer
	closed   sync.Once
	rateMu   sync.Mutex
	commands []time.Time
}

type outbound struct {
	message    protocol.Message
	closeAfter bool
}

func NewControlServer(secret string, allowCommands bool, onCommand CommandHandler, logf LogFunc) *ControlServer {
	if logf == nil {
		logf = log.Printf
	}
	return &ControlServer{
		secret:        secret,
		allowCommands: allowCommands,
		onCommand:     onCommand,
		logf:          logf,
		clients:       make(map[uint64]*client),
		history:       make([]string, HistoryLines),
		pending:       make(chan struct{}, maxPendingClient),
		status:        protocol.Status{State: "starting", CommandsAllowed: allowCommands},
	}
}

// Serve accepts clients until ctx is cancelled. Unauthenticated handshakes
// consume only a bounded handshake slot, never one of the eight client slots.
func (s *ControlServer) Serve(ctx context.Context, listener net.Listener) error {
	var workers sync.WaitGroup
	serveDone := make(chan struct{})
	defer close(serveDone)
	go func() {
		select {
		case <-ctx.Done():
			if err := listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
				s.logf("close control listener: %v", err)
			}
		case <-serveDone:
		}
	}()
	for {
		conn, err := listener.Accept()
		if err != nil {
			workers.Wait()
			s.closeClients()
			s.clientWG.Wait()
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("accept control client: %w", err)
		}
		select {
		case s.pending <- struct{}{}:
			workers.Add(1)
			go func() {
				defer workers.Done()
				defer func() { <-s.pending }()
				s.handleConn(conn)
			}()
		default:
			s.logf("rejected client %s: too many pending handshakes", conn.RemoteAddr())
			if err := conn.Close(); err != nil {
				s.logf("close rejected connection: %v", err)
			}
		}
	}
}

func (s *ControlServer) handleConn(conn net.Conn) {
	remote := conn.RemoteAddr().String()
	session, err := protocol.ServerHandshake(conn, s.secret)
	if err != nil {
		s.logf("rejected client %s: authentication failed", remote)
		if closeErr := conn.Close(); closeErr != nil {
			s.logf("close unauthenticated connection %s: %v", remote, closeErr)
		}
		return
	}

	s.mu.Lock()
	if len(s.clients) >= MaxClients {
		s.mu.Unlock()
		if err := session.SendJSON(protocol.TypeServerFull, protocol.CommandResponse{Text: "server full"}); err != nil {
			s.logf("send full response to %s: %v", remote, err)
		}
		if err := session.Close(); err != nil {
			s.logf("close full connection %s: %v", remote, err)
		}
		s.logf("rejected authenticated client %s: server full (%d/%d)", remote, MaxClients, MaxClients)
		return
	}
	s.nextID++
	c := &client{
		id:      s.nextID,
		remote:  remote,
		session: session,
		out:     make(chan outbound, clientQueueSize),
		done:    make(chan struct{}),
		server:  s,
	}
	s.clients[c.id] = c
	capabilities, err := json.Marshal(protocol.Status{CommandsAllowed: s.allowCommands})
	if err != nil {
		delete(s.clients, c.id)
		s.mu.Unlock()
		if closeErr := session.Close(); closeErr != nil {
			s.logf("close client after capabilities error: %v", closeErr)
		}
		s.logf("encode client capabilities: %v", err)
		return
	}
	status, err := json.Marshal(s.status)
	if err != nil {
		delete(s.clients, c.id)
		s.mu.Unlock()
		if closeErr := session.Close(); closeErr != nil {
			s.logf("close client after status error: %v", closeErr)
		}
		s.logf("encode initial client status: %v", err)
		return
	}
	c.out <- outbound{message: protocol.Message{Type: protocol.TypeCapabilities, Payload: capabilities}}
	c.out <- outbound{message: protocol.Message{Type: protocol.TypeStatus, Payload: status}}
	for _, line := range s.historySnapshotLocked() {
		c.out <- outbound{message: protocol.Message{Type: protocol.TypeLogLine, Payload: []byte(line)}}
	}
	count := len(s.clients)
	s.mu.Unlock()
	s.logf("client %d connected from %s (%d/%d)", c.id, remote, count, MaxClients)
	s.clientWG.Add(2)
	go func() {
		defer s.clientWG.Done()
		c.writer()
	}()
	go func() {
		defer s.clientWG.Done()
		c.reader()
		c.drop("disconnected")
	}()
}

func (c *client) writer() {
	ticker := time.NewTicker(pingInterval)
	defer ticker.Stop()
	for {
		select {
		case <-c.done:
			return
		case <-ticker.C:
			if err := c.session.Send(protocol.TypePing, []byte("ping")); err != nil {
				c.drop("ping failed")
				return
			}
		case item := <-c.out:
			if err := c.session.Send(item.message.Type, item.message.Payload); err != nil {
				c.drop("write failed")
				return
			}
			if item.closeAfter {
				c.drop("kicked by server operator")
				return
			}
		}
	}
}

func (c *client) reader() {
	for {
		if err := c.session.SetReadDeadline(time.Now().Add(pingTimeout)); err != nil {
			c.server.logf("set read deadline for client %d: %v", c.id, err)
			return
		}
		message, err := c.session.Receive()
		if err != nil {
			return
		}
		switch message.Type {
		case protocol.TypePing:
			if string(message.Payload) != "pong" {
				return
			}
		case protocol.TypeCommand:
			c.handleCommand(message.Payload)
		default:
			return
		}
	}
}

func (c *client) handleCommand(payload []byte) {
	command := strings.ReplaceAll(string(payload), "\r", "")
	command = strings.ReplaceAll(command, "\n", "")
	if len(command) > 256 {
		c.respond("command too long (maximum 256 characters)")
		return
	}
	if !c.server.allowCommands {
		c.respond("commands disabled")
		return
	}
	now := time.Now()
	c.rateMu.Lock()
	cutoff := now.Add(-10 * time.Second)
	kept := c.commands[:0]
	for _, sent := range c.commands {
		if sent.After(cutoff) {
			kept = append(kept, sent)
		}
	}
	c.commands = kept
	if len(c.commands) >= 5 {
		c.rateMu.Unlock()
		c.respond("rate limit exceeded (5 commands per 10 seconds)")
		return
	}
	c.commands = append(c.commands, now)
	c.rateMu.Unlock()

	if c.server.onCommand == nil {
		c.respond("command input is unavailable")
		return
	}
	if err := c.server.onCommand(c.id, command); err != nil {
		c.respond("command rejected: " + err.Error())
		return
	}
	c.server.logf("client %d (%s) command: %s", c.id, c.remote, command)
	c.respond("command sent")
}

func (c *client) respond(text string) {
	if !c.enqueueJSON(protocol.TypeCommandResponse, protocol.CommandResponse{Text: text}) {
		c.drop("could not queue command response")
	}
}

func (c *client) enqueueJSON(messageType byte, value any) bool {
	payload, err := marshal(value)
	if err != nil {
		c.server.logf("encode message for client %d: %v", c.id, err)
		return false
	}
	return c.enqueue(protocol.Message{Type: messageType, Payload: payload})
}

func (c *client) enqueue(message protocol.Message) bool {
	return c.enqueueItem(outbound{message: message})
}

func (c *client) enqueueItem(item outbound) bool {
	select {
	case <-c.done:
		return false
	case c.out <- item:
		return true
	default:
		c.drop("send buffer full")
		return false
	}
}

func (c *client) drop(reason string) {
	c.closed.Do(func() {
		if err := c.session.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			c.server.logf("close client %d connection: %v", c.id, err)
		}
		close(c.done)
		s := c.server
		s.mu.Lock()
		delete(s.clients, c.id)
		count := len(s.clients)
		s.mu.Unlock()
		s.logf("client %d disconnected from %s: %s (%d/%d)", c.id, c.remote, reason, count, MaxClients)
	})
}

func (s *ControlServer) closeClients() {
	s.mu.Lock()
	clients := make([]*client, 0, len(s.clients))
	for _, c := range s.clients {
		clients = append(clients, c)
	}
	s.mu.Unlock()
	for _, c := range clients {
		c.drop("server shutting down")
	}
}

func (s *ControlServer) PublishLine(line string) {
	if len(line) > protocol.MaxPlaintext-64 {
		line = line[:protocol.MaxPlaintext-64] + " [line truncated]"
	}
	s.mu.Lock()
	s.history[s.historyAt] = line
	s.historyAt = (s.historyAt + 1) % len(s.history)
	if s.historyN < len(s.history) {
		s.historyN++
	}
	dropped := s.broadcastLocked(protocol.Message{Type: protocol.TypeLogLine, Payload: []byte(line)})
	s.mu.Unlock()
	for _, c := range dropped {
		c.drop("send buffer full")
	}
}

func (s *ControlServer) SetStatus(status protocol.Status) {
	status.CommandsAllowed = s.allowCommands
	payload, err := json.Marshal(status)
	if err != nil {
		s.logf("encode server status: %v", err)
		return
	}
	s.mu.Lock()
	s.status = status
	dropped := s.broadcastLocked(protocol.Message{Type: protocol.TypeStatus, Payload: payload})
	s.mu.Unlock()
	for _, c := range dropped {
		c.drop("send buffer full")
	}
}

func (s *ControlServer) broadcastLocked(message protocol.Message) []*client {
	var dropped []*client
	for _, c := range s.clients {
		select {
		case c.out <- outbound{message: message}:
		default:
			dropped = append(dropped, c)
		}
	}
	return dropped
}

func (s *ControlServer) historySnapshotLocked() []string {
	out := make([]string, s.historyN)
	start := (s.historyAt - s.historyN + len(s.history)) % len(s.history)
	for i := range out {
		out[i] = s.history[(start+i)%len(s.history)]
	}
	return out
}

func (s *ControlServer) History() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.historySnapshotLocked()
}

func (s *ControlServer) ClientCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.clients)
}

func (s *ControlServer) CurrentStatus() protocol.Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.status
}

type ClientInfo struct {
	ID     uint64
	Remote string
}

func (s *ControlServer) Clients() []ClientInfo {
	s.mu.Lock()
	defer s.mu.Unlock()
	clients := make([]ClientInfo, 0, len(s.clients))
	for _, c := range s.clients {
		clients = append(clients, ClientInfo{ID: c.id, Remote: c.remote})
	}
	return clients
}

func (s *ControlServer) Kick(id uint64) bool {
	s.mu.Lock()
	c := s.clients[id]
	s.mu.Unlock()
	if c == nil {
		return false
	}
	payload, err := marshal(protocol.CommandResponse{Text: "kicked by server operator"})
	if err != nil {
		return false
	}
	return c.enqueueItem(outbound{
		message:    protocol.Message{Type: protocol.TypeKick, Payload: payload},
		closeAfter: true,
	})
}

func marshal(value any) ([]byte, error) {
	return json.Marshal(value)
}

func (s *ControlServer) ListenAndServe(ctx context.Context, address string) error {
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", address, err)
	}
	return s.Serve(ctx, listener)
}

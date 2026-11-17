//go:build linux

package main

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"mcwatch/internal/protocol"
	mcserver "mcwatch/internal/server"
)

func TestFakePaperWithAuthenticatedClientLimitAndConsoleInput(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "fake-java")
	body := `#!/bin/sh
echo "fake-paper-ready"
while IFS= read -r line; do
  if [ "$line" = "stop" ]; then
    echo "fake-paper-stopped"
    exit 0
  fi
  echo "fake-paper-command:$line"
done
`
	if err := os.WriteFile(script, []byte(body), 0700); err != nil {
		t.Fatal(err)
	}

	lineCh := make(chan string, 16)
	var stdin io.WriteCloser
	control := mcserver.NewControlServer("integration shared secret", true, func(_ uint64, command string) error {
		return writeConsole(stdin, command)
	}, func(string, ...any) {})
	writer := &consoleLineWriter{onLine: func(line string) {
		control.PublishLine(line)
		select {
		case lineCh <- line:
		default:
		}
	}}
	cfg := config{MCDir: dir, Jar: "fake.jar", Java: script, XMS: "1G", XMX: "2G"}
	cmd, paperStdin, wait, err := startPaper(cfg, writer)
	if err != nil {
		t.Fatal(err)
	}
	stdin = paperStdin
	paperStopped := false
	t.Cleanup(func() {
		if !paperStopped {
			if err := gracefulStop(cmd, paperStdin, wait); err != nil {
				t.Errorf("stop fake PaperMC: %v", err)
			}
		}
	})
	awaitLine(t, lineCh, "fake-paper-ready")

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	serveDone := make(chan error, 1)
	go func() { serveDone <- control.Serve(ctx, listener) }()
	serveFinished := false
	t.Cleanup(func() {
		if serveFinished {
			return
		}
		cancel()
		select {
		case err := <-serveDone:
			if err != nil {
				t.Errorf("control server stopped with error: %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Error("control server did not stop")
		}
	})

	wrongConn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := protocol.ClientHandshake(wrongConn, "incorrect secret"); err == nil {
		t.Fatal("wrong-secret client connected")
	}
	if err := wrongConn.Close(); err != nil {
		t.Fatal(err)
	}
	if control.ClientCount() != 0 {
		t.Fatal("wrong-secret client consumed a client slot")
	}

	clients := make([]*protocol.Session, 0, mcserver.MaxClients)
	for i := 0; i < mcserver.MaxClients; i++ {
		clients = append(clients, connectTestClient(t, listener.Addr().String(), "integration shared secret"))
	}
	waitServerClients(t, control, mcserver.MaxClients)

	ninth := connectTestClient(t, listener.Addr().String(), "integration shared secret")
	message, err := ninth.Receive()
	if err != nil {
		t.Fatal(err)
	}
	var full protocol.CommandResponse
	if message.Type != protocol.TypeServerFull || json.Unmarshal(message.Payload, &full) != nil || full.Text != "server full" {
		t.Fatalf("ninth client response: type=%d payload=%q", message.Type, message.Payload)
	}
	if err := ninth.Close(); err != nil {
		t.Fatal(err)
	}

	if err := clients[0].Send(protocol.TypeCommand, []byte("say client-test")); err != nil {
		t.Fatal(err)
	}
	awaitLine(t, lineCh, "fake-paper-command:say client-test")
	for _, client := range clients {
		if err := client.Close(); err != nil {
			t.Error(err)
		}
	}
	cancel()
	select {
	case err := <-serveDone:
		serveFinished = true
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("control server did not stop")
	}
	if err := gracefulStop(cmd, paperStdin, wait); err != nil {
		t.Fatal(err)
	}
	paperStopped = true
}

func TestConfigFlagsOverrideJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	data := []byte(`{"bind":"127.0.0.1","port":9100,"mc_dir":"/minecraft","jar":"paper-test.jar","allow_commands":true}`)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := parseConfig([]string{"--config", path, "--port", "9200", "--allow-commands=false"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Bind != "127.0.0.1" || cfg.Port != 9200 || cfg.MCDir != "/minecraft" || cfg.Jar != "paper-test.jar" || cfg.AllowCommands {
		t.Fatalf("unexpected merged config: %+v", cfg)
	}
}

func TestSecretFileMustBeMode0600(t *testing.T) {
	t.Setenv("MCWATCH_SECRET", "")
	path := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(path, []byte("a long test secret"), 0600); err != nil {
		t.Fatal(err)
	}
	secret, err := loadSecret(path)
	if err != nil || secret != "a long test secret" {
		t.Fatalf("loadSecret() = %q, %v", secret, err)
	}
	if err := os.Chmod(path, 0640); err != nil {
		t.Fatal(err)
	}
	if _, err := loadSecret(path); err == nil {
		t.Fatal("secret file with group permissions was accepted")
	}
}

func TestEULAIsNeverWrittenAndDetected(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "eula.txt")
	if eulaAccepted(dir) {
		t.Fatal("missing EULA file was accepted")
	}
	contents := "# reviewed by operator\neula=true\n"
	if err := os.WriteFile(path, []byte(contents), 0600); err != nil {
		t.Fatal(err)
	}
	if !eulaAccepted(dir) {
		t.Fatal("eula=true was not detected")
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, []byte(contents)) {
		t.Fatal("EULA file was modified")
	}
}

func connectTestClient(t *testing.T, address, secret string) *protocol.Session {
	t.Helper()
	conn, err := net.Dial("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	session, err := protocol.ClientHandshake(conn, secret)
	if err != nil {
		if closeErr := conn.Close(); closeErr != nil {
			t.Errorf("close client connection: %v", closeErr)
		}
		t.Fatal(err)
	}
	return session
}

func awaitLine(t *testing.T, lines <-chan string, expected string) {
	t.Helper()
	timer := time.NewTimer(3 * time.Second)
	defer timer.Stop()
	for {
		select {
		case line := <-lines:
			if line == expected {
				return
			}
		case <-timer.C:
			t.Fatalf("did not receive console line %q", expected)
		}
	}
}

func waitServerClients(t *testing.T, control *mcserver.ControlServer, count int) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if control.ClientCount() == count {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("client count = %d, want %d", control.ClientCount(), count)
}

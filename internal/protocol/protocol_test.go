package protocol

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

func TestHandshakeAndRoundTrip(t *testing.T) {
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()

	type result struct {
		session *Session
		err     error
	}
	serverResult := make(chan result, 1)
	go func() {
		session, err := ServerHandshake(right, "a sufficiently long test secret")
		serverResult <- result{session: session, err: err}
	}()
	client, err := ClientHandshake(left, "a sufficiently long test secret")
	if err != nil {
		t.Fatal(err)
	}
	server := <-serverResult
	if server.err != nil {
		t.Fatal(server.err)
	}

	got := make(chan Message, 1)
	go func() {
		message, _ := server.session.Receive()
		got <- message
	}()
	if err := client.Send(TypeLogLine, []byte("hello world")); err != nil {
		t.Fatal(err)
	}
	message := <-got
	if message.Type != TypeLogLine || string(message.Payload) != "hello world" {
		t.Fatalf("unexpected message: %#v", message)
	}
}

func TestWrongSecretRejected(t *testing.T) {
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	errs := make(chan error, 1)
	go func() {
		defer right.Close()
		_, err := ServerHandshake(right, "server secret")
		errs <- err
	}()
	_, clientErr := ClientHandshake(left, "wrong secret")
	if clientErr == nil {
		t.Fatal("client handshake unexpectedly succeeded")
	}
	select {
	case err := <-errs:
		if err == nil {
			t.Fatal("server handshake unexpectedly succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("server handshake did not finish")
	}
}

func TestTamperedCiphertextRejected(t *testing.T) {
	sender, receiver := net.Pipe()
	defer sender.Close()
	defer receiver.Close()
	serverSalt := bytes.Repeat([]byte{1}, SaltSize)
	clientSalt := bytes.Repeat([]byte{2}, SaltSize)
	client, err := newSession(sender, "test secret", serverSalt, clientSalt, 'C')
	if err != nil {
		t.Fatal(err)
	}
	server, err := newSession(receiver, "test secret", serverSalt, clientSalt, 'S')
	if err != nil {
		t.Fatal(err)
	}

	sendDone := make(chan error, 1)
	go func() {
		sendDone <- client.Send(TypeLogLine, []byte("tamper me"))
	}()
	var header [4]byte
	if _, err := io.ReadFull(receiver, header[:]); err != nil {
		t.Fatal(err)
	}
	n := binary.BigEndian.Uint32(header[:])
	ciphertext := make([]byte, n)
	if _, err := io.ReadFull(receiver, ciphertext); err != nil {
		t.Fatal(err)
	}
	ciphertext[0] ^= 0x80
	go func() {
		_, _ = sender.Write(header[:])
		_, _ = sender.Write(ciphertext)
	}()
	if _, err := server.Receive(); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("Receive() error = %v, want authentication failure", err)
	}
	if err := <-sendDone; err != nil {
		t.Fatal(err)
	}
}

func TestOutOfOrderAndReplayFramesRejected(t *testing.T) {
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	serverSalt := bytes.Repeat([]byte{3}, SaltSize)
	clientSalt := bytes.Repeat([]byte{4}, SaltSize)
	client, err := newSession(left, "test secret", serverSalt, clientSalt, 'C')
	if err != nil {
		t.Fatal(err)
	}
	server, err := newSession(right, "test secret", serverSalt, clientSalt, 'S')
	if err != nil {
		t.Fatal(err)
	}

	makeFrame := func(counter uint64, payload string) []byte {
		plain := append([]byte{TypeLogLine}, []byte(payload)...)
		encrypted := client.aead.Seal(nil, makeNonce('C', counter), plain, nil)
		frame := make([]byte, 4+len(encrypted))
		binary.BigEndian.PutUint32(frame[:4], uint32(len(encrypted)))
		copy(frame[4:], encrypted)
		return frame
	}
	frame0 := makeFrame(0, "first")
	frame1 := makeFrame(1, "second")
	go func() {
		_, _ = left.Write(frame1)
	}()
	if _, err := server.Receive(); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("out-of-order Receive() error = %v, want authentication failure", err)
	}

	// A fresh receiver accepts the first counter once and rejects its replay.
	left2, right2 := net.Pipe()
	defer left2.Close()
	defer right2.Close()
	server2, err := newSession(right2, "test secret", serverSalt, clientSalt, 'S')
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		go func() {
			_, _ = left2.Write(frame0)
		}()
		_, err := server2.Receive()
		if i == 0 && err != nil {
			t.Fatalf("first frame rejected: %v", err)
		}
		if i == 1 && !errors.Is(err, ErrAuthentication) {
			t.Fatalf("replayed frame error = %v, want authentication failure", err)
		}
	}
}

func TestOversizedFrameRejectedBeforeBodyRead(t *testing.T) {
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	session, err := newSession(left, "test secret", make([]byte, SaltSize), make([]byte, SaltSize), 'C')
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		var header [4]byte
		binary.BigEndian.PutUint32(header[:], MaxPlaintext+chacha20poly1305.Overhead+1)
		_, _ = right.Write(header[:])
	}()
	if _, err := session.Receive(); !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("Receive() error = %v, want ErrFrameTooLarge", err)
	}
}

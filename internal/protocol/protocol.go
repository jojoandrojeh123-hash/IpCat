// Package protocol implements the authenticated, encrypted mcwatch wire format.
//
// The client first sends a random client salt; the server replies with its own
// random server salt. Both derive the same 32-byte key with scrypt(secret,
// serverSalt || clientSalt). Each then authenticates with an encrypted hello.
// Thereafter every frame is a 4-byte big-endian ciphertext length followed by
// an AEAD ciphertext whose plaintext starts with one message-type byte.
package protocol

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/scrypt"
)

const (
	MaxPlaintext = 16 * 1024
	SaltSize     = 16
	HandshakeTTL = 10 * time.Second
	HeartbeatTTL = 45 * time.Second
	helloText    = "mcwatch/1"
)

const (
	TypeHello byte = iota + 1
	TypeLogLine
	TypeStatus
	TypeServerFull
	TypeKick
	TypeCommand
	TypeCommandResponse
	TypeCapabilities
	TypePing
)

var (
	ErrFrameTooLarge  = errors.New("protocol: frame exceeds maximum size")
	ErrAuthentication = errors.New("protocol: authentication failed")
)

// Message's first wire byte is Type; Payload is JSON except for log lines,
// which are UTF-8 bytes. The fixed per-direction nonce counter makes replayed
// or reordered ciphertext fail authentication.
type Message struct {
	Type    byte
	Payload []byte
}

type Status struct {
	State           string `json:"state"`
	UptimeSeconds   int64  `json:"uptimeSeconds"`
	CommandsAllowed bool   `json:"commandsAllowed"`
}

type CommandResponse struct {
	Text string `json:"text"`
}

type Session struct {
	conn       net.Conn
	aead       cipher.AEAD
	sendPrefix byte
	recvPrefix byte
	sendCount  uint64
	recvCount  uint64
	sendMu     sync.Mutex
	recvMu     sync.Mutex
}

// ClientHandshake exchanges fresh salts and authenticates the peer with an
// encrypted hello before returning a usable session.
func ClientHandshake(conn net.Conn, secret string) (result *Session, retErr error) {
	if err := conn.SetDeadline(time.Now().Add(HandshakeTTL)); err != nil {
		return nil, fmt.Errorf("set handshake deadline: %w", err)
	}
	defer func() {
		if err := conn.SetDeadline(time.Time{}); err != nil && retErr == nil {
			retErr = fmt.Errorf("clear handshake deadline: %w", err)
		}
	}()

	clientSalt := make([]byte, SaltSize)
	if _, err := rand.Read(clientSalt); err != nil {
		return nil, fmt.Errorf("create client salt: %w", err)
	}
	if err := writeFull(conn, clientSalt); err != nil {
		return nil, fmt.Errorf("send client salt: %w", err)
	}
	serverSalt := make([]byte, SaltSize)
	if _, err := io.ReadFull(conn, serverSalt); err != nil {
		return nil, fmt.Errorf("read server salt: %w", err)
	}

	session, err := newSession(conn, secret, serverSalt, clientSalt, 'C')
	if err != nil {
		return nil, err
	}
	if err := session.Send(TypeHello, []byte(helloText)); err != nil {
		return nil, fmt.Errorf("send hello: %w", err)
	}
	msg, err := session.Receive()
	if err != nil {
		return nil, err
	}
	if msg.Type != TypeHello || string(msg.Payload) != helloText {
		return nil, ErrAuthentication
	}
	return session, nil
}

// ServerHandshake exchanges fresh salts and verifies the client's encrypted
// hello. A caller should impose a separate limit on concurrent handshakes.
func ServerHandshake(conn net.Conn, secret string) (result *Session, retErr error) {
	if err := conn.SetDeadline(time.Now().Add(HandshakeTTL)); err != nil {
		return nil, fmt.Errorf("set handshake deadline: %w", err)
	}
	defer func() {
		if err := conn.SetDeadline(time.Time{}); err != nil && retErr == nil {
			retErr = fmt.Errorf("clear handshake deadline: %w", err)
		}
	}()

	clientSalt := make([]byte, SaltSize)
	if _, err := io.ReadFull(conn, clientSalt); err != nil {
		return nil, fmt.Errorf("read client salt: %w", err)
	}
	serverSalt := make([]byte, SaltSize)
	if _, err := rand.Read(serverSalt); err != nil {
		return nil, fmt.Errorf("create server salt: %w", err)
	}
	if err := writeFull(conn, serverSalt); err != nil {
		return nil, fmt.Errorf("send server salt: %w", err)
	}

	session, err := newSession(conn, secret, serverSalt, clientSalt, 'S')
	if err != nil {
		return nil, err
	}
	msg, err := session.Receive()
	if err != nil {
		return nil, err
	}
	if msg.Type != TypeHello || string(msg.Payload) != helloText {
		return nil, ErrAuthentication
	}
	if err := session.Send(TypeHello, []byte(helloText)); err != nil {
		return nil, fmt.Errorf("send hello: %w", err)
	}
	return session, nil
}

func newSession(conn net.Conn, secret string, serverSalt, clientSalt []byte, localDirection byte) (*Session, error) {
	salt := make([]byte, 0, len(serverSalt)+len(clientSalt))
	salt = append(salt, serverSalt...)
	salt = append(salt, clientSalt...)
	key, err := scrypt.Key([]byte(secret), salt, 1<<15, 8, 1, chacha20poly1305.KeySize)
	if err != nil {
		return nil, fmt.Errorf("derive session key: %w", err)
	}
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}
	remoteDirection := byte('S')
	if localDirection == 'S' {
		remoteDirection = 'C'
	}
	return &Session{conn: conn, aead: aead, sendPrefix: localDirection, recvPrefix: remoteDirection}, nil
}

// Send serializes one message. The nonce counter starts at zero independently
// in each direction and advances only after the complete frame is written.
func (s *Session) Send(messageType byte, payload []byte) error {
	if len(payload)+1 > MaxPlaintext {
		return ErrFrameTooLarge
	}
	s.sendMu.Lock()
	defer s.sendMu.Unlock()
	if s.sendCount == ^uint64(0) {
		return errors.New("protocol: send counter exhausted")
	}
	plain := make([]byte, 1+len(payload))
	plain[0] = messageType
	copy(plain[1:], payload)
	nonce := makeNonce(s.sendPrefix, s.sendCount)
	ciphertext := s.aead.Seal(nil, nonce, plain, nil)
	if len(ciphertext) > MaxPlaintext+s.aead.Overhead() {
		return ErrFrameTooLarge
	}
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(ciphertext)))
	if err := writeFull(s.conn, length[:]); err != nil {
		return err
	}
	if err := writeFull(s.conn, ciphertext); err != nil {
		return err
	}
	s.sendCount++
	return nil
}

// Receive validates the announced size before allocating, then opens the
// ciphertext using the next expected nonce. A replay or reordering therefore
// fails authentication rather than delivering a message twice or out of order.
func (s *Session) Receive() (Message, error) {
	s.recvMu.Lock()
	defer s.recvMu.Unlock()
	if s.recvCount == ^uint64(0) {
		return Message{}, errors.New("protocol: receive counter exhausted")
	}
	var length [4]byte
	if _, err := io.ReadFull(s.conn, length[:]); err != nil {
		return Message{}, err
	}
	size := binary.BigEndian.Uint32(length[:])
	if size < uint32(s.aead.Overhead()+1) {
		return Message{}, errors.New("protocol: invalid frame length")
	}
	if size > MaxPlaintext+uint32(s.aead.Overhead()) {
		return Message{}, ErrFrameTooLarge
	}
	ciphertext := make([]byte, int(size))
	if _, err := io.ReadFull(s.conn, ciphertext); err != nil {
		return Message{}, err
	}
	nonce := makeNonce(s.recvPrefix, s.recvCount)
	plain, err := s.aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return Message{}, ErrAuthentication
	}
	s.recvCount++
	if len(plain) == 0 || len(plain) > MaxPlaintext {
		return Message{}, errors.New("protocol: invalid plaintext size")
	}
	return Message{Type: plain[0], Payload: append([]byte(nil), plain[1:]...)}, nil
}

func (s *Session) Close() error { return s.conn.Close() }

func (s *Session) SetReadDeadline(deadline time.Time) error {
	if err := s.conn.SetReadDeadline(deadline); err != nil {
		return fmt.Errorf("set protocol read deadline: %w", err)
	}
	return nil
}

func (s *Session) SendJSON(messageType byte, value any) error {
	payload, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("encode protocol message: %w", err)
	}
	return s.Send(messageType, payload)
}

func DecodeJSON[T any](message Message) (T, error) {
	var value T
	if err := json.Unmarshal(message.Payload, &value); err != nil {
		return value, fmt.Errorf("decode protocol message: %w", err)
	}
	return value, nil
}

func makeNonce(direction byte, counter uint64) []byte {
	// ChaCha20-Poly1305 needs a 12-byte nonce: direction, three zero bytes, and
	// the monotonically increasing 64-bit counter.
	nonce := make([]byte, chacha20poly1305.NonceSize)
	nonce[0] = direction
	binary.BigEndian.PutUint64(nonce[4:], counter)
	return nonce
}

func writeFull(w io.Writer, data []byte) error {
	for len(data) > 0 {
		n, err := w.Write(data)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	return nil
}

package message

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/octagono/skink/src/comm"
	"github.com/octagono/skink/src/crypt"
	log "github.com/schollz/logger"
	"github.com/stretchr/testify/assert"
)

var TypeMessage Type = "message"

func TestMessage(t *testing.T) {
	log.SetLevel("debug")
	m := Message{Type: TypeMessage, Message: "hello, world"}
	e, salt, err := crypt.New([]byte("pass"), nil)
	assert.Nil(t, err)
	fmt.Println(string(salt))
	b, err := Encode(e, m)
	assert.Nil(t, err)
	fmt.Printf("%x\n", b)

	m2, err := Decode(e, b)
	assert.Nil(t, err)
	assert.Equal(t, m, m2)
	assert.Equal(t, `{"t":"message","m":"hello, world"}`, m.String())
	_, err = Decode([]byte("not pass"), b)
	assert.NotNil(t, err)
	_, err = Encode([]byte("0"), m)
	assert.NotNil(t, err)
}

func TestMessageNoPass(t *testing.T) {
	log.SetLevel("debug")
	m := Message{Type: TypeMessage, Message: "hello, world"}
	b, err := Encode(nil, m)
	assert.Nil(t, err)
	fmt.Printf("%x\n", b)

	m2, err := Decode(nil, b)
	assert.Nil(t, err)
	assert.Equal(t, m, m2)
	assert.Equal(t, `{"t":"message","m":"hello, world"}`, m.String())
}

// TestSendError verifies that Send returns the Encode error when given an
// invalid key, without dereferencing the comm (Encode fails before c.Send).
func TestSendError(t *testing.T) {
	err := Send(nil, []byte("x"), Message{Type: TypeMessage, Message: "bad key"})
	assert.NotNil(t, err)
}

// TestSend verifies the full message roundtrip through the comm layer:
// message.Send (encode + comm framing) → comm.Receive → message.Decode.
// It uses a random TCP port and channel-based synchronization so the
// result is deterministic regardless of goroutine scheduling.
func TestSend(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	assert.Nil(t, err)
	defer ln.Close()

	key, _, err := crypt.New([]byte("test-password"), nil)
	assert.Nil(t, err)

	original := Message{Type: TypeMessage, Message: "hello, world"}

	// Server: accept, receive, decode, return the decoded message via channel.
	result := make(chan Message, 1)
	errc := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			errc <- err
			return
		}
		defer conn.Close()
		c := comm.New(conn)
		data, err := c.Receive()
		if err != nil {
			errc <- err
			return
		}
		decoded, err := Decode(key, data)
		if err != nil {
			errc <- err
			return
		}
		result <- decoded
	}()

	// Client: connect and send the encrypted message.
	client, err := comm.NewConnection(ln.Addr().String(), 10*time.Second)
	assert.Nil(t, err)
	defer client.Close()

	err = Send(client, key, original)
	assert.Nil(t, err)

	// Wait for the server goroutine and verify the roundtrip.
	select {
	case got := <-result:
		assert.Equal(t, original, got)
	case err := <-errc:
		t.Fatalf("server error: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("timeout waiting for server to process message")
	}
}

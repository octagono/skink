package tunnel

import (
	"net"
	"sync"

	"github.com/hashicorp/yamux"
)

// StreamSession abstracts stream multiplexing over a single connection.
// Both yamux (TCP/WSS) and QUIC (native streams) implement this interface,
// allowing the tunnel client/server to work with either transparently.
type StreamSession interface {
	// OpenStream opens a new bidirectional stream.
	OpenStream() (net.Conn, error)

	// AcceptStream waits for and returns the next incoming stream.
	AcceptStream() (net.Conn, error)

	// Ping sends a keepalive/ping and returns nil if the session is alive.
	Ping() error

	// Close shuts down the session and all streams.
	Close() error

	// IsClosed returns whether the session has been closed.
	IsClosed() bool
}

// This is the default multiplexer for TCP and WSS transports.
type YamuxSessionWrapper struct {
	session *yamux.Session
}

func NewYamuxSessionWrapper(session *yamux.Session) *YamuxSessionWrapper {
	return &YamuxSessionWrapper{session: session}
}

func YamuxClient(conn net.Conn, cfg *yamux.Config) (StreamSession, error) {
	if cfg == nil {
		cfg = yamux.DefaultConfig()
	}
	session, err := yamux.Client(conn, cfg)
	if err != nil {
		return nil, err
	}
	return &YamuxSessionWrapper{session: session}, nil
}

func YamuxServer(conn net.Conn, cfg *yamux.Config) (StreamSession, error) {
	if cfg == nil {
		cfg = yamux.DefaultConfig()
	}
	session, err := yamux.Server(conn, cfg)
	if err != nil {
		return nil, err
	}
	return &YamuxSessionWrapper{session: session}, nil
}

func (w *YamuxSessionWrapper) OpenStream() (net.Conn, error) {
	return w.session.Open()
}

func (w *YamuxSessionWrapper) AcceptStream() (net.Conn, error) {
	return w.session.Accept()
}

func (w *YamuxSessionWrapper) Ping() error {
	_, err := w.session.Ping()
	return err
}

func (w *YamuxSessionWrapper) Close() error {
	return w.session.Close()
}

func (w *YamuxSessionWrapper) IsClosed() bool {
	return w.session.IsClosed()
}

// Ensure sync is imported (used by session management elsewhere).
var _ sync.Locker = (*sync.Mutex)(nil)

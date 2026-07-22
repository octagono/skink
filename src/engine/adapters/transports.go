// Package adapters provides concrete implementations of the engine plugin
// interfaces, wrapping Skink's existing transports and protocols behind
// the standardized contracts defined in src/engine/engine.go.
//
// These adapters enable incremental migration: existing code continues
// to work as-is, while new code can use the engine.Registry to discover
// and instantiate transports/protocols dynamically.
package adapters

import (
	"context"
	"net"
	"time"

	"github.com/octagono/skink/src/engine"
)

// --- TRANSPORT ADAPTERS ---

// TCPTransport implements engine.Transport for raw TCP.
type TCPTransport struct{}

func (t *TCPTransport) Dial(ctx context.Context, addr string) (net.Conn, error) {
	d := net.Dialer{Timeout: 10 * time.Second}
	return d.DialContext(ctx, "tcp", addr)
}

func (t *TCPTransport) Listen(addr string) (net.Listener, error) {
	return net.Listen("tcp", addr)
}

func (t *TCPTransport) Name() string        { return "tcp" }
func (t *TCPTransport) IsStreamBased() bool { return false } // needs yamux

// WSSTransport implements engine.Transport for WebSocket Secure.
type WSSTransport struct{}

func (t *WSSTransport) Dial(ctx context.Context, addr string) (net.Conn, error) {
	// Delegates to the existing WSS dialer in transport_ws.go
	// via a function pointer to avoid import cycles.
	return dialWSS(addr)
}

func (t *WSSTransport) Listen(addr string) (net.Listener, error) {
	return listenWSS(addr)
}

func (t *WSSTransport) Name() string        { return "wss" }
func (t *WSSTransport) IsStreamBased() bool { return false }

// QUICTransport implements engine.Transport for QUIC.
type QUICTransport struct{}

func (t *QUICTransport) Dial(ctx context.Context, addr string) (net.Conn, error) {
	// QUIC returns a connection that provides native streams.
	// The first stream is used as the primary connection.
	conn, err := dialQUIC(ctx, addr)
	if err != nil {
		return nil, err
	}
	return conn.OpenStreamSync(ctx)
}

func (t *QUICTransport) Listen(addr string) (net.Listener, error) {
	return listenQUIC(addr)
}

func (t *QUICTransport) Name() string        { return "quic" }
func (t *QUICTransport) IsStreamBased() bool { return true } // native streams, no yamux

// --- REGISTRATION ---

// RegisterAll registers all built-in transport adapters with the engine registry.
func RegisterAll(r *engine.Registry) {
	r.RegisterTransport("tcp", func(cfg map[string]interface{}) (engine.Transport, error) {
		return &TCPTransport{}, nil
	})
	r.RegisterTransport("wss", func(cfg map[string]interface{}) (engine.Transport, error) {
		return &WSSTransport{}, nil
	})
	r.RegisterTransport("quic", func(cfg map[string]interface{}) (engine.Transport, error) {
		return &QUICTransport{}, nil
	})
}

// --- DIAL/LISTEN HOOKS ---
// These are set by the tunnel package during init() to avoid import cycles.
// The tunnel package calls SetDialFuncs() to wire its implementations.

var (
	dialWSS    func(addr string) (net.Conn, error)
	listenWSS  func(addr string) (net.Listener, error)
	dialQUIC   func(ctx context.Context, addr string) (quicConn, error)
	listenQUIC func(addr string) (net.Listener, error)
)

type quicConn interface {
	OpenStreamSync(context.Context) (net.Conn, error)
}

// SetWSSDial sets the WSS dial function (called by tunnel package init).
func SetWSSDial(fn func(string) (net.Conn, error)) { dialWSS = fn }

func SetWSSListen(fn func(string) (net.Listener, error)) { listenWSS = fn }

func SetQUICDial(fn func(context.Context, string) (quicConn, error)) { dialQUIC = fn }

func SetQUICListen(fn func(string) (net.Listener, error)) { listenQUIC = fn }

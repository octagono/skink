// Package engine defines the plugin interfaces for Skink's modular
// architecture. Transports, protocols, crypto providers, and proxy drivers
// all implement these interfaces, enabling runtime registration and
// compile-time selection of features.
//
// Status: interface definitions only. Existing code uses adapters
// (src/engine/adapters/) that shim the current implementations behind
// these contracts. Full migration is a incremental process.
package engine

import (
	"context"
	"io"
	"net"
)

// Transport is the interface for network transport layers.
// Implementations: TCP, WSS, QUIC, named pipe.
type Transport interface {
	// Dial connects to a remote address.
	Dial(ctx context.Context, addr string) (net.Conn, error)

	// Listen creates a listener on the given address.
	Listen(addr string) (net.Listener, error)

	// Name returns the transport identifier (e.g., "tcp", "wss", "quic").
	Name() string

	// IsStreamBased returns true if this transport provides native
	// stream multiplexing (like QUIC). When true, the yamux layer
	// is bypassed and streams are used directly.
	IsStreamBased() bool
}

// StreamMultiplexer abstracts stream multiplexing over a single connection.
// Implementations: yamux (for TCP/WSS), native QUIC streams.
type StreamMultiplexer interface {
	// AcceptStream waits for an incoming stream.
	AcceptStream() (net.Conn, error)

	// OpenStream creates a new outgoing stream.
	OpenStream() (net.Conn, error)

	// Close shuts down the multiplexer.
	Close() error

	// IsClosed returns whether the session is closed.
	IsClosed() bool
}

// TunnelProtocol handles a specific type of data stream on the relay.
// Implementations: reverse proxy, forward proxy (SOCKS5), exec,
// private access, relay hop.
type TunnelProtocol interface {
	// Prefix returns the stream identifier (e.g., "FWD|", "ACCESS|").
	Prefix() string

	// HandleStream processes a single data stream with the given header.
	HandleStream(conn net.Conn, header string) error

	// Name returns the protocol name for logging.
	Name() string
}

// CryptoProvider abstracts encryption layers.
// Implementations: PAKE+NaCl, Noise Protocol, PQNoise.
type CryptoProvider interface {
	// Handshake performs the key exchange over the given connection.
	Handshake(conn net.Conn, isServer bool) (SecureConn, error)

	// Name returns the crypto provider identifier.
	Name() string
}

// SecureConn is a connection that has been encrypted by a CryptoProvider.
type SecureConn interface {
	net.Conn
	// Key returns the negotiated session key.
	Key() []byte
}

// ProxyDriver handles incoming public connections for a registered tunnel.
// Implementations: HTTP reverse proxy, TCP forwarder, UDP datagram relay.
type ProxyDriver interface {
	// HandleConnection processes a public connection destined for a tunnel.
	HandleConnection(publicConn net.Conn, tunnelID string) error

	// PortType returns "tcp" or "udp" for listener allocation.
	PortType() string

	// Name returns the driver identifier.
	Name() string
}

type Registry struct {
	transports map[string]TransportFactory
	protocols  map[string]ProtocolFactory
	crypto     map[string]CryptoFactory
	proxies    map[string]ProxyFactory
}

// TransportFactory creates a Transport instance from configuration.
type TransportFactory func(config map[string]interface{}) (Transport, error)

type ProtocolFactory func(server interface{}) (TunnelProtocol, error)

type CryptoFactory func(config map[string]interface{}) (CryptoProvider, error)

type ProxyFactory func(server interface{}) (ProxyDriver, error)

func NewRegistry() *Registry {
	return &Registry{
		transports: make(map[string]TransportFactory),
		protocols:  make(map[string]ProtocolFactory),
		crypto:     make(map[string]CryptoFactory),
		proxies:    make(map[string]ProxyFactory),
	}
}

func (r *Registry) RegisterTransport(name string, f TransportFactory) {
	r.transports[name] = f
}

func (r *Registry) RegisterProtocol(name string, f ProtocolFactory) {
	r.protocols[name] = f
}

func (r *Registry) RegisterCrypto(name string, f CryptoFactory) {
	r.crypto[name] = f
}

func (r *Registry) RegisterProxy(name string, f ProxyFactory) {
	r.proxies[name] = f
}

func (r *Registry) GetTransport(name string) (TransportFactory, bool) {
	f, ok := r.transports[name]
	return f, ok
}

func (r *Registry) GetProtocol(name string) (ProtocolFactory, bool) {
	f, ok := r.protocols[name]
	return f, ok
}

func (r *Registry) ListTransports() []string {
	names := make([]string, 0, len(r.transports))
	for n := range r.transports {
		names = append(names, n)
	}
	return names
}

func (r *Registry) ListProtocols() []string {
	names := make([]string, 0, len(r.protocols))
	for n := range r.protocols {
		names = append(names, n)
	}
	return names
}

// Ensure io is imported (used in future SecureConn implementations)
var _ = io.Copy

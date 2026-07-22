package tunnel

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"log"
	"math/big"
	"net"
	"time"

	"github.com/quic-go/quic-go"
)

type QuicConfig struct {
	Address            string
	TLSConfig          *tls.Config
	MaxIncomingStreams int64
	KeepAlive          time.Duration
}

func DefaultQuicConfig(addr string) QuicConfig {
	return QuicConfig{
		Address:            addr,
		MaxIncomingStreams: 1000,
		KeepAlive:          30 * time.Second,
	}
}

// QuicDial establishes a QUIC connection. Returns *quic.Conn which
// provides native stream multiplexing (no yamux needed).
func QuicDial(ctx context.Context, addr string, tlsConf *tls.Config) (*quic.Conn, error) {
	if tlsConf == nil {
		tlsConf = &tls.Config{
			InsecureSkipVerify: true,
			NextProtos:         []string{"skink"},
		}
	}

	conn, err := quic.DialAddr(ctx, addr, tlsConf, &quic.Config{
		MaxIncomingStreams: 1000,
		KeepAlivePeriod:    30 * time.Second,
	})
	if err != nil {
		return nil, err
	}
	return conn, nil
}

func QuicListen(addr string, tlsConf *tls.Config) (*quic.Listener, error) {
	if tlsConf == nil {
		cert, err := GenerateEphemeralCert()
		if err != nil {
			return nil, err
		}
		tlsConf = &tls.Config{
			Certificates: []tls.Certificate{cert},
			NextProtos:   []string{"skink"},
		}
	}

	return quic.ListenAddr(addr, tlsConf, &quic.Config{
		MaxIncomingStreams: 1000,
		KeepAlivePeriod:    30 * time.Second,
	})
}

// QuicSessionWrapper wraps a quic.Conn to provide Accept/OpenStream methods
// similar to yamux.Session, enabling drop-in replacement.
type QuicSessionWrapper struct {
	conn *quic.Conn
}

func NewQuicSessionWrapper(conn *quic.Conn) *QuicSessionWrapper {
	return &QuicSessionWrapper{conn: conn}
}

func (w *QuicSessionWrapper) AcceptStream() (net.Conn, error) {
	stream, err := w.conn.AcceptStream(context.Background())
	if err != nil {
		return nil, err
	}
	return &QuicStreamConn{Stream: stream, conn: w.conn}, nil
}

func (w *QuicSessionWrapper) OpenStream() (net.Conn, error) {
	stream, err := w.conn.OpenStream()
	if err != nil {
		return nil, err
	}
	return &QuicStreamConn{Stream: stream, conn: w.conn}, nil
}

func (w *QuicSessionWrapper) Close() error {
	return w.conn.CloseWithError(0, "closed")
}

func (w *QuicSessionWrapper) IsClosed() bool {
	return w.conn.Context().Err() != nil
}

func (w *QuicSessionWrapper) SendDatagram(p []byte) error {
	return w.conn.SendDatagram(p)
}

func (w *QuicSessionWrapper) ReceiveDatagram() ([]byte, error) {
	return w.conn.ReceiveDatagram(w.conn.Context())
}

func (w *QuicSessionWrapper) Ping() error {
	if w.IsClosed() {
		return errQuicClosed
	}
	return nil
}

var errQuicClosed = netClosedError{}

type netClosedError struct{}

func (netClosedError) Error() string { return "quic: connection closed" }

type QuicStreamConn struct {
	*quic.Stream
	conn *quic.Conn
}

func (q *QuicStreamConn) LocalAddr() net.Addr  { return q.conn.LocalAddr() }
func (q *QuicStreamConn) RemoteAddr() net.Addr { return q.conn.RemoteAddr() }

// GenerateEphemeralCert creates a self-signed ECDSA P-256 TLS certificate
// for QUIC. Used when the operator doesn't provide a cert.
func GenerateEphemeralCert() (tls.Certificate, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{Organization: []string{"Skink"}},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"*"},
		IPAddresses:  []net.IP{net.ParseIP("0.0.0.0")},
	}

	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}

	return tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  priv,
	}, nil
}

// Silence unused import warning for log if not otherwise used
var _ = log.Printf

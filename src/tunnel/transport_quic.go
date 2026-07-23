package tunnel

import (
	"context"
	"crypto/tls"
	"net"
	"time"

	"github.com/quic-go/quic-go"
)

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

package tunnel

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/octagono/skink/src/comm"
	utls "github.com/refraction-networking/utls"
	log "github.com/schollz/logger"
)

const (
	WSPath             = "/tunnel"
	WSBufferSize       = 32 * 1024
	WSHandshakeTimeout = 10 * time.Second
)

type wsAddr struct {
	addr string
}

func (a *wsAddr) Network() string { return "ws" }
func (a *wsAddr) String() string  { return a.addr }

// wsConn wraps a gorilla/websocket.Conn as a net.Conn with optional Noise encryption.
// When Noise keys are set, all WebSocket messages are encrypted/decrypted transparently.
type wsConn struct {
	conn   *websocket.Conn
	reader io.Reader
	rmu    sync.Mutex
	wmu    sync.Mutex
	dmu    sync.Mutex

	localAddr  net.Addr
	remoteAddr net.Addr

	readDeadline  time.Time
	writeDeadline time.Time
	deadlineMu    sync.Mutex

	closed bool

	// Optional Noise encryption layer
	noiseEncrypt func([]byte) ([]byte, error)
	noiseDecrypt func([]byte) ([]byte, error)
}

func NewWSConn(conn *websocket.Conn) *wsConn {
	remoteAddr := &wsAddr{addr: "ws://remote"}
	localAddr := &wsAddr{addr: "ws://local"}
	if rawConn := conn.UnderlyingConn(); rawConn != nil {
		if ra := rawConn.RemoteAddr(); ra != nil {
			remoteAddr = &wsAddr{addr: ra.String()}
		}
		if la := rawConn.LocalAddr(); la != nil {
			localAddr = &wsAddr{addr: la.String()}
		}
	}
	return &wsConn{
		conn:       conn,
		localAddr:  localAddr,
		remoteAddr: remoteAddr,
	}
}

// SetNoiseKeys configures Noise encryption for the WebSocket connection.
// After this, all messages are encrypted before sending and decrypted after receiving.
func (w *wsConn) SetNoiseKeys(encrypt, decrypt func([]byte) ([]byte, error)) {
	w.noiseEncrypt = encrypt
	w.noiseDecrypt = decrypt
}

// Read implements net.Conn.Read using WebSocket binary messages.
func (w *wsConn) Read(b []byte) (int, error) {
	w.rmu.Lock()
	defer w.rmu.Unlock()

	w.applyReadDeadline()

	for {
		if w.reader != nil {
			n, err := w.reader.Read(b)
			if err == io.EOF {
				w.reader = nil
				if n > 0 {
					return n, nil
				}
				continue
			}
			return n, err
		}

		msgType, data, err := w.conn.ReadMessage()
		if err != nil {
			return 0, err
		}

		if msgType == websocket.CloseMessage {
			return 0, io.EOF
		}
		if msgType != websocket.BinaryMessage {
			continue
		}

		// Decrypt if Noise is configured
		if w.noiseDecrypt != nil {
			data, err = w.noiseDecrypt(data)
			if err != nil {
				log.Debugf("ws noise decrypt: %v", err)
				continue
			}
		}

		if len(data) <= len(b) {
			return copy(b, data), nil
		}

		n := copy(b, data)
		w.reader = strings.NewReader(string(data[n:]))
		return n, nil
	}
}

// Write implements net.Conn.Write using WebSocket binary messages.
func (w *wsConn) Write(b []byte) (int, error) {
	w.wmu.Lock()
	defer w.wmu.Unlock()

	w.applyWriteDeadline()

	data := b
	var err error
	if w.noiseEncrypt != nil {
		data, err = w.noiseEncrypt(b)
		if err != nil {
			return 0, fmt.Errorf("noise encrypt: %w", err)
		}
	}

	if err := w.conn.WriteMessage(websocket.BinaryMessage, data); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (w *wsConn) Close() error {
	w.dmu.Lock()
	defer w.dmu.Unlock()
	if w.closed {
		return nil
	}
	w.closed = true
	return w.conn.Close()
}

func (w *wsConn) LocalAddr() net.Addr  { return w.localAddr }
func (w *wsConn) RemoteAddr() net.Addr { return w.remoteAddr }

func (w *wsConn) SetDeadline(t time.Time) error {
	w.deadlineMu.Lock()
	w.readDeadline = t
	w.writeDeadline = t
	w.deadlineMu.Unlock()
	return nil
}

func (w *wsConn) SetReadDeadline(t time.Time) error {
	w.deadlineMu.Lock()
	w.readDeadline = t
	w.deadlineMu.Unlock()
	return nil
}

func (w *wsConn) SetWriteDeadline(t time.Time) error {
	w.deadlineMu.Lock()
	w.writeDeadline = t
	w.deadlineMu.Unlock()
	return nil
}

func (w *wsConn) applyReadDeadline() {
	w.deadlineMu.Lock()
	deadline := w.readDeadline
	w.deadlineMu.Unlock()
	if !deadline.IsZero() {
		w.conn.SetReadDeadline(deadline)
	} else {
		w.conn.SetReadDeadline(time.Time{})
	}
}

func (w *wsConn) applyWriteDeadline() {
	w.deadlineMu.Lock()
	deadline := w.writeDeadline
	w.deadlineMu.Unlock()
	if !deadline.IsZero() {
		w.conn.SetWriteDeadline(deadline)
	} else {
		w.conn.SetWriteDeadline(time.Time{})
	}
}

// utlsWSSDialer dials a WebSocket endpoint using utls to mimic a browser TLS fingerprint.
// This produces a JA3 hash identical to Chrome/Firefox instead of Go's distinctive TLS stack.
func utlsWSSDialer(addr, path string, tlsSkipVerify bool, noisePrivKey string) (*wsConn, error) {
	if path == "" {
		path = WSPath
	}

	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
		addr = net.JoinHostPort(addr, "443")
	}

	// Dial raw TCP (honors --socks5 / --connect via comm.Dial)
	tcpConn, err := comm.Dial(addr, WSHandshakeTimeout)
	if err != nil {
		return nil, fmt.Errorf("tcp dial %s: %w", addr, err)
	}

	// Wrap in utls with Chrome fingerprint
	tlsCfg := &utls.Config{
		ServerName:         host,
		InsecureSkipVerify: tlsSkipVerify,
		MinVersion:         utls.VersionTLS12,
	}

	// Use Chrome Auto fingerprint — matches standard Chrome Chrome Hello
	tlsConn := utls.UClient(tcpConn, tlsCfg, utls.HelloChrome_Auto)
	if err := tlsConn.Handshake(); err != nil {
		tcpConn.Close()
		return nil, fmt.Errorf("utls handshake: %w", err)
	}

	header := http.Header{}
	header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")
	header.Set("Origin", fmt.Sprintf("https://%s", host))

	// Use ws:// scheme with the already-TLS connection to prevent gorilla from
	// double-wrapping with TLS. NetDial returns the utls-wrapped connection.
	url := fmt.Sprintf("ws://%s%s", addr, path)
	dialer := &websocket.Dialer{
		NetDial: func(network, addr string) (net.Conn, error) {
			return tlsConn, nil
		},
		HandshakeTimeout: WSHandshakeTimeout,
		ReadBufferSize:   WSBufferSize,
		WriteBufferSize:  WSBufferSize,
	}

	wssConn, _, err := dialer.Dial(url, header)
	if err != nil {
		tlsConn.Close()
		return nil, fmt.Errorf("ws dial %s: %w", url, err)
	}

	return NewWSConn(wssConn), nil
}

func wsGenerateKey() string {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		for i := range b {
			b[i] = byte(time.Now().UnixNano() >> (i * 8))
		}
	}
	return strings.TrimRight(
		base64.StdEncoding.EncodeToString(b), "=")
}

// WSClientDialer dials a WebSocket endpoint and returns a net.Conn adapter.
// Uses utls for browser fingerprint cloaking by default.
func WSClientDialer(addr, path string, tlsSkipVerify bool) (net.Conn, error) {
	return utlsWSSDialer(addr, path, tlsSkipVerify, "")
}

// WSServerHandler returns an HTTP handler that upgrades WebSocket connections.
func WSServerHandler(upgrader *websocket.Upgrader, handler func(net.Conn)) http.HandlerFunc {
	if upgrader == nil {
		upgrader = &websocket.Upgrader{
			ReadBufferSize:  WSBufferSize,
			WriteBufferSize: WSBufferSize,
			CheckOrigin: func(r *http.Request) bool {
				return true
			},
		}
	}

	return func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			log.Debugf("ws upgrade: %v", err)
			return
		}
		ws := NewWSConn(conn)
		handler(ws)
	}
}

func StartWSServer(addr string, handler func(net.Conn)) (*http.Server, error) {
	mux := http.NewServeMux()
	mux.HandleFunc(WSPath, WSServerHandler(nil, handler))

	srv := &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  0,
		WriteTimeout: 0,
	}

	go func() {
		log.Infof("WSS transport listening on %s%s", addr, WSPath)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Debugf("WSS server error: %v", err)
		}
	}()

	return srv, nil
}

func AddWSSToHTTPServer(srv *http.Server, handler func(net.Conn)) {
	mux, ok := srv.Handler.(*http.ServeMux)
	if ok {
		mux.HandleFunc(WSPath, WSServerHandler(nil, handler))
	}
}

func HasWSSPrefix(addr string) bool {
	return strings.HasPrefix(addr, "ws://") || strings.HasPrefix(addr, "wss://")
}

func StripWSSPrefix(addr string) string {
	addr = strings.TrimPrefix(addr, "wss://")
	addr = strings.TrimPrefix(addr, "ws://")
	return addr
}

// DialNoiseWSS dials a WSS endpoint and wraps the connection in Noise encryption.
// The Noise handshake is performed over the WebSocket before any tunnel data flows.
func DialNoiseWSS(addr, path string, tlsSkipVerify bool, noisePubKey string) (net.Conn, error) {
	ws, err := utlsWSSDialer(addr, path, tlsSkipVerify, "")
	if err != nil {
		return nil, err
	}

	// Perform Noise NK handshake over the WebSocket
	// The server's public key is the Noise public key configured by the user
	if noisePubKey != "" {
		result, err := noiseHandshakeInitiator(ws, noisePubKey)
		if err != nil {
			ws.Close()
			return nil, fmt.Errorf("noise handshake: %w", err)
		}

		nc := NewNoiseConn(ws, result)
		ws.SetNoiseKeys(nc.NoiseEncryptFunc(), nc.NoiseDecryptFunc())
		log.Debugf("noise-wss: encryption enabled")
	}

	return ws, nil
}

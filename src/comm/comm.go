package comm

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/magisterquis/connectproxy"
	"github.com/octagono/skink/src/utils"
	log "github.com/schollz/logger"
	"golang.org/x/net/proxy"
)

var Socks5Proxy = ""
var HttpProxy = ""

var MAGIC_BYTES = [5]byte{'S', 'k', 'i', 'n', 'k'}

const maxReadMessageSize = 64 * 1024 * 1024

// Large resume requests can contain hundreds of thousands of missing chunk
// ranges. Keep the guard against malformed streams, but give legitimate large
// control messages enough time to arrive through a relay.
const messageBodyReadTimeout = 10 * time.Minute

type Comm struct {
	connection net.Conn
}

// Dial connects to address (host:port). When Socks5Proxy or HttpProxy is set
// (via the global --socks5 / --connect flags) and the address is not a local
// IP, the connection is routed through that proxy, including a timeout-bounded
// proxy handshake. Local addresses always bypass the proxy.
//
// This is the shared dialer used by file transfer (NewConnection) and the
// tunnel client (control, data, WSS, and multi-hop upstream dials) so that
// --socks5 / --connect apply uniformly across all network egress. QUIC and
// UDP-based P2P paths cannot traverse a TCP proxy and dial directly.
func Dial(address string, timeout time.Duration) (net.Conn, error) {
	if Socks5Proxy != "" && !utils.IsLocalIP(address) {
		return dialViaProxy(Socks5Proxy, address, timeout, false)
	}
	if HttpProxy != "" && !utils.IsLocalIP(address) {
		return dialViaProxy(HttpProxy, address, timeout, true)
	}
	log.Debugf("dialing %s with timeout %s", address, timeout)
	return net.DialTimeout("tcp", address, timeout)
}

// dialViaProxy normalizes the proxy URL, builds a proxy.Dialer, and dials the
// target with a context-bounded timeout. http=false selects a SOCKS5 dialer
// (golang.org/x/net/proxy), http=true selects an HTTP CONNECT dialer
// (connectproxy). Both perform remote DNS resolution, so .onion targets resolve
// correctly through a Tor SOCKS5 listener (default 127.0.0.1:9050).
func dialViaProxy(rawProxy, address string, timeout time.Duration, http bool) (net.Conn, error) {
	scheme := "socks5"
	if http {
		scheme = "http"
	}
	p := rawProxy
	if !strings.Contains(p, "://") {
		p = scheme + "://" + p
	}
	proxyURL, err := url.Parse(p)
	if err != nil {
		return nil, fmt.Errorf("unable to parse %s proxy url: %w", scheme, err)
	}
	var d proxy.Dialer
	if http {
		d, err = connectproxy.New(proxyURL, proxy.Direct)
	} else {
		d, err = proxy.FromURL(proxyURL, proxy.Direct)
	}
	if err != nil {
		return nil, fmt.Errorf("proxy failed: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	// proxy.FromURL returns a proxy.ContextDialer for SOCKS5; fall back to Dial
	// if a particular dialer does not implement DialContext.
	if cd, ok := d.(proxy.ContextDialer); ok {
		conn, derr := cd.DialContext(ctx, "tcp", address)
		if derr != nil {
			return nil, fmt.Errorf("proxy dial %s: %w", address, derr)
		}
		log.Debugf("dialed %s via %s proxy", address, scheme)
		return conn, nil
	}
	conn, derr := d.Dial("tcp", address)
	if derr != nil {
		return nil, fmt.Errorf("proxy dial %s: %w", address, derr)
	}
	log.Debugf("dialed %s via %s proxy", address, scheme)
	return conn, nil
}

func NewConnection(address string, timelimit ...time.Duration) (c *Comm, err error) {
	tlimit := 30 * time.Second
	if len(timelimit) > 0 {
		tlimit = timelimit[0]
	}
	connection, err := Dial(address, tlimit)
	if err != nil {
		err = fmt.Errorf("comm.NewConnection failed: %w", err)
		log.Debug(err)
		return
	}
	c = New(connection)
	log.Debugf("connected to '%s'", address)
	return
}

func New(c net.Conn) *Comm {
	if err := c.SetReadDeadline(time.Now().Add(3 * time.Hour)); err != nil {
		log.Warnf("error setting read deadline: %v", err)
	}
	if err := c.SetDeadline(time.Now().Add(3 * time.Hour)); err != nil {
		log.Warnf("error setting overall deadline: %v", err)
	}
	if err := c.SetWriteDeadline(time.Now().Add(3 * time.Hour)); err != nil {
		log.Errorf("error setting write deadline: %v", err)
	}
	comm := new(Comm)
	comm.connection = c
	return comm
}

func (c *Comm) Connection() net.Conn {
	return c.connection
}

func (c *Comm) Close() {
	if err := c.connection.Close(); err != nil {
		if errors.Is(err, net.ErrClosed) {
			return
		}
		log.Warnf("error closing connection: %v", err)
	}
}

func (c *Comm) Write(b []byte) (n int, err error) {
	header := new(bytes.Buffer)
	err = binary.Write(header, binary.LittleEndian, uint32(len(b)))
	if err != nil {
		fmt.Println("binary.Write failed:", err)
	}
	tmpCopy := append(header.Bytes(), b...)
	tmpCopy = append(MAGIC_BYTES[:], tmpCopy...)
	n, err = c.connection.Write(tmpCopy)
	if err != nil {
		err = fmt.Errorf("connection.Write failed: %w", err)
		return
	}
	if n != len(tmpCopy) {
		err = fmt.Errorf("wanted to write %d but wrote %d", len(b), n)
		return
	}
	return
}

func (c *Comm) Read() (buf []byte, numBytes int, bs []byte, err error) {
	// long read deadline in case waiting for file
	if err = c.connection.SetReadDeadline(time.Now().Add(3 * time.Hour)); err != nil {
		log.Warnf("error setting read deadline: %v", err)
	}
	// must clear the timeout setting
	if err := c.connection.SetDeadline(time.Time{}); err != nil {
		log.Warnf("failed to clear deadline: %v", err)
	}

	// read until we get the magic bytes (len(MAGIC_BYTES))
	header := make([]byte, len(MAGIC_BYTES))
	_, err = io.ReadFull(c.connection, header)
	if err != nil {
		log.Debugf("initial read error: %v", err)
		return
	}
	if !bytes.Equal(header, MAGIC_BYTES[:]) {
		err = fmt.Errorf("initial bytes are not magic: %x", header)
		return
	}

	// read until we get 4 bytes for the header
	header = make([]byte, 4)
	_, err = io.ReadFull(c.connection, header)
	if err != nil {
		log.Debugf("initial read error: %v", err)
		return
	}

	var numBytesUint32 uint32
	rbuf := bytes.NewReader(header)
	err = binary.Read(rbuf, binary.LittleEndian, &numBytesUint32)
	if err != nil {
		err = fmt.Errorf("binary.Read failed: %w", err)
		log.Debug(err.Error())
		return
	}
	if numBytesUint32 > uint32(maxReadMessageSize) {
		err = fmt.Errorf("message too large: %d > %d", numBytesUint32, maxReadMessageSize)
		log.Debug(err.Error())
		return
	}
	numBytes = int(numBytesUint32)

	// Shorten the reading deadline in case getting weird data, while still
	// allowing large resume-control messages to cross slower relays.
	if err = c.connection.SetReadDeadline(time.Now().Add(messageBodyReadTimeout)); err != nil {
		log.Warnf("error setting read deadline: %v", err)
	}
	buf = make([]byte, numBytes)
	_, err = io.ReadFull(c.connection, buf)
	if err != nil {
		log.Debugf("consecutive read error: %v", err)
		return
	}
	return
}

func (c *Comm) Send(message []byte) (err error) {
	_, err = c.Write(message)
	return
}

func (c *Comm) Receive() (b []byte, err error) {
	b, _, _, err = c.Read()
	return
}

package tunnel

import (
	"context"
	"crypto/ecdh"
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/yamux"
	"github.com/octagono/skink/src/comm"
	"github.com/octagono/skink/src/crypt"
	"github.com/octagono/skink/src/message"
	log "github.com/schollz/logger"
	"github.com/schollz/pake/v3"
)

const udpMaxDatagram = 65507

// localConnPool reuses TCP connections to the local service for HTTP tunnel mode.
// Idle connections are kept up to idleTimeout, then closed on next attempt to use.
type localConnPool struct {
	addr        string
	mu          sync.Mutex
	idle        []net.Conn
	maxIdle     int
	idleTimeout time.Duration
	closed      bool
}

func newLocalConnPool(addr string) *localConnPool {
	return &localConnPool{
		addr:        addr,
		maxIdle:     16,
		idleTimeout: 30 * time.Second,
	}
}

func (p *localConnPool) Get() (net.Conn, error) {
	p.mu.Lock()
	for len(p.idle) > 0 {
		conn := p.idle[len(p.idle)-1]
		p.idle = p.idle[:len(p.idle)-1]
		p.mu.Unlock()
		// Test if connection is still alive with a non-blocking peek
		if err := conn.SetReadDeadline(time.Now()); err == nil {
			if n, _ := conn.Read(make([]byte, 1)); n > 0 {
				// Data available — this connection has residual data, discard it
				conn.Close()
				continue
			}
		}
		// Clear deadline and return the connection
		conn.SetReadDeadline(time.Time{})
		return conn, nil
	}
	p.mu.Unlock()
	return net.DialTimeout("tcp", p.addr, 10*time.Second)
}

func (p *localConnPool) Put(conn net.Conn) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || len(p.idle) >= p.maxIdle {
		conn.Close()
		return
	}
	conn.SetReadDeadline(time.Now().Add(p.idleTimeout))
	p.idle = append(p.idle, conn)
}

func (p *localConnPool) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closed = true
	for _, conn := range p.idle {
		conn.Close()
	}
	p.idle = nil
}

// Client manages a tunnel connection to a remote relay server.
type Client struct {
	config      Config
	configMu    sync.Mutex // protects hot-reloadable config fields
	state       TunnelState
	stateMu     sync.RWMutex
	controlConn *comm.Comm
	controlKey  []byte

	// Stream session over the data port (yamux for TCP/WSS, native for QUIC)
	dataSession   StreamSession
	dataSessionMu sync.Mutex

	// Tunnel info from server
	tunnelID  string
	publicURL string
	subdomain string
	token     string

	// Data port number (server port + 1)
	dataPort int

	// SOCKS5 proxy listener
	socks5Listener net.Listener

	// Split tunnel route rule
	routeRule *RouteRule

	// Connection pool for HTTP tunnel mode (reuses local service connections)
	localPool *localConnPool

	reconnectAttempt int
	pendingRekeyKey  *ecdh.PrivateKey
	socks5Started    bool

	stopOnce sync.Once
	quit     chan struct{}
	wg       sync.WaitGroup // tracks Start() goroutine; wg.Wait() in Stop() returns immediately if Start() never called
}

// NewClient creates a new tunnel client.
func NewClient(config Config) *Client {
	c := &Client{
		config: config,
		state:  TunnelStateDisconnected,
		quit:   make(chan struct{}),
	}

	// Initialize route rules from config
	if len(config.Routes) > 0 || len(config.BypassRoutes) > 0 {
		rule, err := NewRouteRule(config.Routes, config.BypassRoutes)
		if err == nil {
			c.routeRule = rule
		}
	}

	if config.TunnelType == TunnelTypeHTTP {
		c.localPool = newLocalConnPool(config.LocalAddr)
	}

	return c
}

// Start establishes the tunnel connection and runs the event loop.
// Blocks until the tunnel is closed or an irrecoverable error occurs.
func (c *Client) Start() error {
	c.wg.Add(1)
	defer c.wg.Done()

	for {
		select {
		case <-c.quit:
			return nil
		default:
		}

		c.setState(TunnelStateConnecting)

		err := c.connect()
		if err != nil {
			log.Debugf("tunnel connect failed: %v", err)
			c.setState(TunnelStateDisconnected)

			// Exponential backoff for reconnection
			c.reconnectAttempt++
			delay := c.backoffDuration()
			log.Infof("reconnecting in %s (attempt %d)", delay, c.reconnectAttempt)

			select {
			case <-time.After(delay):
				continue
			case <-c.quit:
				return nil
			}
		}

		c.reconnectAttempt = 0
		c.setState(TunnelStateConnected)

		// Start SOCKS5 proxy listener for SOCKS5 tunnel mode (once per client lifetime)
		if c.config.TunnelType == TunnelTypeSOCKS5 && !c.socks5Started {
			socks5Addr := fmt.Sprintf("127.0.0.1:%d", c.config.SOCKS5Port)
			if c.config.SOCKS5Port <= 0 {
				socks5Addr = "127.0.0.1:1080"
			}
			listener, err := c.startSOCKS5(socks5Addr)
			if err != nil {
				log.Errorf("start SOCKS5 proxy: %v", err)
			} else {
				c.socks5Listener = listener
				c.socks5Started = true
			}
		}

		// Run the control loop
		err = c.controlLoop()
		if err != nil {
			log.Debugf("control loop error: %v", err)
		}

		c.cleanup()
	}
}

// Stop gracefully closes the tunnel. Safe to call multiple times.
func (c *Client) Stop() {
	c.stopOnce.Do(func() {
		close(c.quit)
	})

	if c.controlConn != nil {
		SendTunnelMessage(c.controlConn, c.controlKey, message.TypeTunnelClose, TunnelCloseMessage{
			TunnelID: c.tunnelID,
			Reason:   "client shutdown",
		})
	}

	c.wg.Wait()
	c.clearResumeState()
}

// State returns the current tunnel state.
func (c *Client) State() TunnelState {
	c.stateMu.RLock()
	defer c.stateMu.RUnlock()
	return c.state
}

// TunnelID returns the assigned tunnel ID.
func (c *Client) TunnelID() string {
	return c.tunnelID
}

// startSOCKS5 starts a local SOCKS5 proxy server that forwards connections
// through the tunnel relay. Each SOCKS5 CONNECT request opens a yamux stream
// to the relay with a forward proxy prefix.
func (c *Client) startSOCKS5(addr string) (net.Listener, error) {
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("socks5 listen %s: %w", addr, err)
	}

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go c.handleSOCKS5Conn(conn)
		}
	}()

	log.Infof("SOCKS5 proxy listening on %s", addr)
	return listener, nil
}

// handleSOCKS5Conn handles a single SOCKS5 client connection.
// Implements minimal SOCKS5 protocol (no auth, CONNECT only).
func (c *Client) handleSOCKS5Conn(conn net.Conn) {
	defer conn.Close()

	// Set a handshake deadline
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	// SOCKS5 handshake: read auth methods
	var handshake [2]byte
	if _, err := io.ReadFull(conn, handshake[:]); err != nil {
		return
	}
	nMethods := int(handshake[1])
	if nMethods < 1 || nMethods > 255 {
		return
	}
	methods := make([]byte, nMethods)
	if _, err := io.ReadFull(conn, methods); err != nil {
		return
	}

	// Reply with no auth (0x00)
	if _, err := conn.Write([]byte{0x05, 0x00}); err != nil {
		return
	}

	// Read CONNECT request (RFC 1928 §4)
	var header [4]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		return
	}
	if header[0] != 0x05 || header[1] != 0x01 { // ver=5, cmd=connect
		conn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}) // cmd not supported
		return
	}

	// Parse target address
	targetAddr, err := parseSOCKS5Addr(conn, header[3])
	if err != nil {
		conn.Write([]byte{0x05, 0x04, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}) // host unreachable
		return
	}

	// Clear deadline for data transfer
	conn.SetDeadline(time.Time{})

	log.Debugf("SOCKS5 CONNECT %s", targetAddr)

	// Check split tunnel routing
	if c.routeRule != nil && !c.routeRule.Route(targetAddr) {
		log.Debugf("SOCKS5 bypassing tunnel for %s (direct connect)", targetAddr)
		c.handleSOCKS5Direct(conn, targetAddr)
		return
	}

	// Open a forward proxy stream to the relay
	stream, err := c.openForwardStream(targetAddr)
	if err != nil {
		log.Debugf("SOCKS5 forward stream error: %v", err)
		conn.Write([]byte{0x05, 0x04, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
		return
	}
	defer stream.Close()

	// Send SOCKS5 success response (bind address = 0.0.0.0:0)
	reply := []byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	if _, err := conn.Write(reply); err != nil {
		return
	}

	// Pipe bidirectionally
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		io.Copy(stream, conn)
		stream.Close()
		conn.Close()
	}()
	go func() {
		defer wg.Done()
		io.Copy(conn, stream)
		stream.Close()
		conn.Close()
	}()
	wg.Wait()
}

// handleSOCKS5Direct handles a SOCKS5 CONNECT request by connecting directly
// to the target (bypasses the tunnel). Used for split tunnel bypass routes.
func (c *Client) handleSOCKS5Direct(conn net.Conn, targetAddr string) {
	defer conn.Close()

	target, err := net.DialTimeout("tcp", targetAddr, 10*time.Second)
	if err != nil {
		log.Debugf("SOCKS5 direct connect %s failed: %v", targetAddr, err)
		conn.Write([]byte{0x05, 0x04, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
		return
	}
	defer target.Close()

	reply := []byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	conn.Write(reply)

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		io.Copy(target, conn)
		target.Close()
		conn.Close()
	}()
	go func() {
		defer wg.Done()
		io.Copy(conn, target)
		target.Close()
		conn.Close()
	}()
	wg.Wait()
}

// parseSOCKS5Addr reads a SOCKS5 address from the connection.
// addrType: 0x01 = IPv4, 0x03 = domain, 0x04 = IPv6
func parseSOCKS5Addr(conn io.Reader, addrType byte) (string, error) {
	switch addrType {
	case 0x01: // IPv4
		var ip [4]byte
		if _, err := io.ReadFull(conn, ip[:]); err != nil {
			return "", err
		}
		var port [2]byte
		if _, err := io.ReadFull(conn, port[:]); err != nil {
			return "", err
		}
		return fmt.Sprintf("%d.%d.%d.%d:%d", ip[0], ip[1], ip[2], ip[3],
			int(port[0])<<8|int(port[1])), nil

	case 0x03: // Domain name
		var lenByte [1]byte
		if _, err := io.ReadFull(conn, lenByte[:]); err != nil {
			return "", err
		}
		host := make([]byte, lenByte[0])
		if _, err := io.ReadFull(conn, host); err != nil {
			return "", err
		}
		var port [2]byte
		if _, err := io.ReadFull(conn, port[:]); err != nil {
			return "", err
		}
		return fmt.Sprintf("%s:%d", string(host), int(port[0])<<8|int(port[1])), nil

	case 0x04: // IPv6
		var ip [16]byte
		if _, err := io.ReadFull(conn, ip[:]); err != nil {
			return "", err
		}
		var port [2]byte
		if _, err := io.ReadFull(conn, port[:]); err != nil {
			return "", err
		}
		return fmt.Sprintf("[%x:%x:%x:%x:%x:%x:%x:%x]:%d",
			ip[0:2], ip[2:4], ip[4:6], ip[6:8], ip[8:10], ip[10:12], ip[12:14], ip[14:16],
			int(port[0])<<8|int(port[1])), nil

	default:
		return "", fmt.Errorf("unknown SOCKS5 address type: %d", addrType)
	}
}

// openForwardStream opens a yamux stream to the relay for forward proxying.
// Writes "FWD|targetAddr" as the stream identifier so the server knows
// to connect to the target address.
func (c *Client) openForwardStream(targetAddr string) (net.Conn, error) {
	// Ensure data session exists
	if c.dataSession == nil {
		if err := c.ensureDataSession(); err != nil {
			return nil, fmt.Errorf("ensure data session: %w", err)
		}
	}

	stream, err := c.dataSession.OpenStream()
	if err != nil {
		return nil, fmt.Errorf("open stream: %w", err)
	}

	proxyID := "FWD|" + targetAddr
	idBytes := []byte(proxyID)
	lenBytes := []byte{byte(len(idBytes) >> 8), byte(len(idBytes))}
	if _, err := stream.Write(lenBytes); err != nil {
		stream.Close()
		return nil, fmt.Errorf("write id length: %w", err)
	}
	if _, err := stream.Write(idBytes); err != nil {
		stream.Close()
		return nil, fmt.Errorf("write proxy id: %w", err)
	}

	return stream, nil
}

// ensureDataSession ensures the yamux data session is established.
func (c *Client) ensureDataSession() error {
	c.dataSessionMu.Lock()
	defer c.dataSessionMu.Unlock()

	if c.dataSession != nil {
		// Check if session is still alive
		if err := c.dataSession.Ping(); err != nil {
			c.dataSession.Close()
			c.dataSession = nil
		} else {
			return nil
		}
	}

	// Derive data port (host:port+1) from server address
	host, portStr, err := net.SplitHostPort(c.config.ServerAddr)
	if err != nil {
		host = ""
		portStr = fmt.Sprint(DefaultTunnelPort)
	}
	var port int
	fmt.Sscanf(portStr, "%d", &port)
	dataAddr := net.JoinHostPort(host, fmt.Sprint(port+1))

	tcpConn, err := comm.Dial(dataAddr, 10*time.Second)
	if err != nil {
		return fmt.Errorf("dial data port: %w", err)
	}

	cfg := yamux.DefaultConfig()
	cfg.MaxStreamWindowSize = 16 * 1024 * 1024
	if c.config.YamuxWindowSize > 0 {
		cfg.MaxStreamWindowSize = uint32(c.config.YamuxWindowSize)
	}
	cfg.LogOutput = io.Discard

	session, err := YamuxClient(tcpConn, cfg)
	if err != nil {
		tcpConn.Close()
		return fmt.Errorf("yamux client: %w", err)
	}

	c.dataSession = session
	c.dataPort = port
	return nil
}

// PublicURL returns the public URL of the tunnel.
func (c *Client) PublicURL() string {
	return c.publicURL
}

// Subdomain returns the assigned subdomain.
func (c *Client) Subdomain() string {
	return c.subdomain
}

// Token returns the assigned auth token (if any).
func (c *Client) Token() string {
	return c.token
}

func (c *Client) setState(state TunnelState) {
	c.stateMu.Lock()
	defer c.stateMu.Unlock()
	c.state = state
}

func (c *Client) connect() error {
	addrs := c.parseServerAddresses()
	if len(addrs) == 0 {
		return fmt.Errorf("server address required")
	}
	var lastErr error
	for _, addr := range addrs {
		if err := c.tryConnect(addr); err == nil {
			return nil
		} else {
			lastErr = err
			log.Debugf("connect to %s failed: %v", addr, err)
		}
	}
	return fmt.Errorf("all tunnel servers unreachable: %w", lastErr)
}

func (c *Client) parseServerAddresses() []string {
	raw := c.config.ServerAddr
	if raw == "" {
		return nil
	}
	var addrs []string
	for _, a := range strings.Split(raw, ",") {
		a = strings.TrimSpace(a)
		if a == "" {
			continue
		}
		if HasWSSPrefix(a) {
			addrs = append(addrs, a)
			continue
		}
		if _, _, err := net.SplitHostPort(a); err != nil {
			a = net.JoinHostPort(a, fmt.Sprint(DefaultTunnelPort))
		}
		addrs = append(addrs, a)
	}
	return addrs
}

func (c *Client) tryConnect(serverAddr string) error {
	if c.config.Transport == "pipe" {
		return c.connectPipe()
	}
	if HasWSSPrefix(serverAddr) {
		return c.connectWS(serverAddr)
	}
	_, portStr, err := net.SplitHostPort(serverAddr)
	if err == nil {
		var port int
		fmt.Sscanf(portStr, "%d", &port)
		c.dataPort = port + 1
	}
	log.Debugf("connecting to tunnel server at %s", serverAddr)
	var tcpConn net.Conn
	tcpConn, err = comm.Dial(serverAddr, 10*time.Second)
	if err != nil {
		return fmt.Errorf("dial tunnel server: %w", err)
	}
	if c.config.TLS.Enable {
		tlsConn, err := wrapTLS(tcpConn, serverAddr, c.config.TLS)
		if err != nil {
			tcpConn.Close()
			return fmt.Errorf("tls wrap: %w", err)
		}
		tcpConn = tlsConn
	}
	c.controlConn = comm.New(tcpConn)
	key, err := c.pakeHandshake(c.controlConn)
	if err != nil {
		c.controlConn.Close()
		c.controlConn = nil
		return fmt.Errorf("pake handshake: %w", err)
	}
	c.controlKey = key

	if c.config.ResumeFile != "" {
		resumeID, resumeToken := c.loadResumeState()
		if resumeID != "" {
			rm := TunnelResumeMessage{TunnelID: resumeID, Token: resumeToken}
			if err := SendTunnelMessage(c.controlConn, c.controlKey, message.TypeTunnelResume, rm); err != nil {
				c.controlConn.Close()
				c.controlConn = nil
				return fmt.Errorf("send tunnel resume: %w", err)
			}
			msgType, payload, err := ReceiveTunnelMessage(c.controlConn, c.controlKey)
			if err != nil {
				c.controlConn.Close()
				c.controlConn = nil
				return fmt.Errorf("receive resume response: %w", err)
			}
			if msgType == message.TypeTunnelRegistered {
				var info TunnelInfo
				if err := DecodePayload(payload, &info); err != nil {
					c.controlConn.Close()
					c.controlConn = nil
					return fmt.Errorf("decode resume info: %w", err)
				}
				c.tunnelID = info.TunnelID
				c.publicURL = info.PublicURL
				c.subdomain = info.Subdomain
				c.token = info.Token
				log.Infof("tunnel resumed: %s → %s", info.PublicURL, c.config.LocalAddr)
				return nil
			}
			c.clearResumeState()
			log.Debugf("tunnel resume rejected, registering fresh")
		}
	}

	reg := TunnelRegistration{
		Version:        CurrentProtocolVersion,
		Subdomain:      c.config.Subdomain,
		LocalAddr:      c.config.LocalAddr,
		Type:           c.config.TunnelType,
		Password:       c.config.Password,
		Token:          c.config.Token,
		MaxConns:       c.config.MaxConns,
		BandwidthLimit: c.config.BandwidthLimit,
		IdleTimeout:    c.config.IdleTimeout,
		ACLAllow:       c.config.ACLAllow,
		ACLDeny:        c.config.ACLDeny,
	}
	if err := SendTunnelMessage(c.controlConn, c.controlKey, message.TypeTunnelRegister, reg); err != nil {
		c.controlConn.Close()
		c.controlConn = nil
		return fmt.Errorf("send tunnel register: %w", err)
	}
	msgType, payload, err := ReceiveTunnelMessage(c.controlConn, c.controlKey)
	if err != nil {
		c.controlConn.Close()
		c.controlConn = nil
		return fmt.Errorf("receive tunnel response: %w", err)
	}
	switch msgType {
	case message.TypeTunnelRegistered:
		var info TunnelInfo
		if err := DecodePayload(payload, &info); err != nil {
			c.controlConn.Close()
			c.controlConn = nil
			return fmt.Errorf("decode tunnel info: %w", err)
		}
		c.tunnelID = info.TunnelID
		c.publicURL = info.PublicURL
		c.subdomain = info.Subdomain
		c.token = info.Token
		log.Infof("tunnel established: %s → %s", info.PublicURL, c.config.LocalAddr)
		if info.Token != "" {
			log.Infof("auth token: %s", info.Token)
		}
		if c.config.ResumeFile != "" {
			c.saveResumeState(info.TunnelID, info.Token)
		}
	case message.TypeTunnelError:
		c.controlConn.Close()
		c.controlConn = nil
		return fmt.Errorf("tunnel registration failed")
	default:
		c.controlConn.Close()
		c.controlConn = nil
		return fmt.Errorf("unexpected response type: %s", msgType)
	}
	return nil
}

// connectWS establishes a control connection over WebSocket.
func (c *Client) connectWS(addr string) error {
	rawAddr := StripWSSPrefix(addr)
	path := WSPath

	// Check if the address includes a custom path
	if parts := strings.SplitN(rawAddr, "/", 2); len(parts) == 2 {
		rawAddr = parts[0]
		path = "/" + parts[1]
	}

	// Add default port if not specified
	if _, _, err := net.SplitHostPort(rawAddr); err != nil {
		rawAddr = net.JoinHostPort(rawAddr, fmt.Sprint(DefaultTunnelPort))
	}

	// Derive data port from server address
	if _, pStr, err := net.SplitHostPort(rawAddr); err == nil {
		if p, err := strconv.Atoi(pStr); err == nil {
			c.dataPort = p + 1
		}
	}

	log.Debugf("connecting to tunnel server via WebSocket at %s%s", rawAddr, path)

	wsNetConn, err := WSClientDialer(rawAddr, path, false)
	if err != nil {
		return fmt.Errorf("ws dial: %w", err)
	}

	c.controlConn = comm.New(wsNetConn)

	// PAKE handshake
	key, err := c.pakeHandshake(c.controlConn)
	if err != nil {
		c.controlConn.Close()
		c.controlConn = nil
		return fmt.Errorf("pake handshake: %w", err)
	}

	c.controlKey = key

	// Send tunnel registration
	reg := TunnelRegistration{
		Version:        CurrentProtocolVersion,
		Subdomain:      c.config.Subdomain,
		LocalAddr:      c.config.LocalAddr,
		Type:           c.config.TunnelType,
		Password:       c.config.Password,
		Token:          c.config.Token,
		MaxConns:       c.config.MaxConns,
		BandwidthLimit: c.config.BandwidthLimit,
		IdleTimeout:    c.config.IdleTimeout,
		ACLAllow:       c.config.ACLAllow,
		ACLDeny:        c.config.ACLDeny,
	}

	if err := SendTunnelMessage(c.controlConn, c.controlKey, message.TypeTunnelRegister, reg); err != nil {
		c.controlConn.Close()
		c.controlConn = nil
		return fmt.Errorf("send tunnel register: %w", err)
	}

	// Wait for response
	msgType, payload, err := ReceiveTunnelMessage(c.controlConn, c.controlKey)
	if err != nil {
		c.controlConn.Close()
		c.controlConn = nil
		return fmt.Errorf("receive tunnel response: %w", err)
	}

	switch msgType {
	case message.TypeTunnelRegistered:
		var info TunnelInfo
		if err := DecodePayload(payload, &info); err != nil {
			c.controlConn.Close()
			c.controlConn = nil
			return fmt.Errorf("decode tunnel info: %w", err)
		}

		c.tunnelID = info.TunnelID
		c.publicURL = info.PublicURL
		c.subdomain = info.Subdomain
		c.token = info.Token

		log.Infof("tunnel established (WS): %s → %s", info.PublicURL, c.config.LocalAddr)

	case message.TypeTunnelError:
		var errMsg TunnelErrorMessage
		if err := DecodePayload(payload, &errMsg); err == nil {
			c.controlConn.Close()
			c.controlConn = nil
			return fmt.Errorf("tunnel registration failed (code %d): %s", errMsg.Code, errMsg.Message)
		}
		c.controlConn.Close()
		c.controlConn = nil
		return fmt.Errorf("tunnel registration failed")

	default:
		c.controlConn.Close()
		c.controlConn = nil
		return fmt.Errorf("unexpected response type: %s", msgType)
	}

	return nil
}

// connectPipe establishes a control connection over a named pipe (Windows SMB).
func (c *Client) connectPipe() error {
	pipeName := c.config.PipeName
	serverAddr := c.config.ServerAddr
	if pipeName == "" {
		pipeName = "skink-tunnel"
	}

	log.Debugf("connecting via named pipe to %s/%s", serverAddr, pipeName)

	pipeConn, err := DialPipe(serverAddr, pipeName)
	if err != nil {
		return fmt.Errorf("dial pipe: %w", err)
	}

	c.controlConn = comm.New(pipeConn)

	// PAKE handshake
	key, err := c.pakeHandshake(c.controlConn)
	if err != nil {
		c.controlConn.Close()
		c.controlConn = nil
		return fmt.Errorf("pake handshake: %w", err)
	}

	c.controlKey = key

	// Register tunnel
	reg := TunnelRegistration{
		Version:        CurrentProtocolVersion,
		Subdomain:      c.config.Subdomain,
		LocalAddr:      c.config.LocalAddr,
		Type:           c.config.TunnelType,
		Password:       c.config.Password,
		Token:          c.config.Token,
		MaxConns:       c.config.MaxConns,
		BandwidthLimit: c.config.BandwidthLimit,
		IdleTimeout:    c.config.IdleTimeout,
		ACLAllow:       c.config.ACLAllow,
		ACLDeny:        c.config.ACLDeny,
	}

	if err := SendTunnelMessage(c.controlConn, c.controlKey, message.TypeTunnelRegister, reg); err != nil {
		c.controlConn.Close()
		c.controlConn = nil
		return fmt.Errorf("send tunnel register: %w", err)
	}

	msgType, payload, err := ReceiveTunnelMessage(c.controlConn, c.controlKey)
	if err != nil {
		c.controlConn.Close()
		c.controlConn = nil
		return fmt.Errorf("receive response: %w", err)
	}

	switch msgType {
	case message.TypeTunnelRegistered:
		var info TunnelInfo
		if err := DecodePayload(payload, &info); err != nil {
			c.controlConn.Close()
			c.controlConn = nil
			return fmt.Errorf("decode info: %w", err)
		}
		c.tunnelID = info.TunnelID
		c.publicURL = info.PublicURL
		c.subdomain = info.Subdomain
		c.token = info.Token
		log.Infof("tunnel established (pipe): %s → %s", info.PublicURL, c.config.LocalAddr)

	case message.TypeTunnelError:
		var errMsg TunnelErrorMessage
		if err := DecodePayload(payload, &errMsg); err == nil {
			c.controlConn.Close()
			c.controlConn = nil
			return fmt.Errorf("tunnel registration failed (code %d): %s", errMsg.Code, errMsg.Message)
		}
		c.controlConn.Close()
		c.controlConn = nil
		return fmt.Errorf("tunnel registration failed")

	default:
		c.controlConn.Close()
		c.controlConn = nil
		return fmt.Errorf("unexpected response type: %s", msgType)
	}

	return nil
}

func (c *Client) controlLoop() error {
	hbCfg := c.config.Heartbeat
	if hbCfg.Interval <= 0 {
		hbCfg = DefaultHeartbeatConfig()
	}

	heartbeatTicker := time.NewTicker(hbCfg.NextInterval())
	defer heartbeatTicker.Stop()

	var rekeyTicker *time.Ticker
	var rekeyCh <-chan time.Time
	if c.config.RekeyInterval > 0 {
		rekeyTicker = time.NewTicker(time.Duration(c.config.RekeyInterval) * time.Second)
		rekeyCh = rekeyTicker.C
		defer rekeyTicker.Stop()
	}

	for {
		select {
		case <-c.quit:
			return nil
		case <-heartbeatTicker.C:
			if err := SendTunnelMessage(c.controlConn, c.controlKey, message.TypeHeartbeat, HeartbeatMessage{
				Timestamp: time.Now().Unix(),
			}); err != nil {
				return fmt.Errorf("heartbeat: %w", err)
			}
			heartbeatTicker.Stop()
			heartbeatTicker = time.NewTicker(hbCfg.NextInterval())

		case <-rekeyCh:
			if err := c.initiateRekey(); err != nil {
				log.Debugf("rekey failed: %v", err)
			}

		default:
			// Try to receive a message with a deadline
			rawConn := c.controlConn.Connection()
			if err := rawConn.SetReadDeadline(time.Now().Add(DefaultHeartbeatInterval)); err != nil {
				log.Debugf("set read deadline: %v", err)
			}

			msgType, payload, err := ReceiveTunnelMessage(c.controlConn, c.controlKey)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue
				}
				return fmt.Errorf("receive: %w", err)
			}

			// Clear deadline
			rawConn.SetReadDeadline(time.Time{})

			if err := c.handleMessage(msgType, payload); err != nil {
				return err
			}
		}
	}
}

// handleMessage processes a single tunnel control message.
func (c *Client) initiateRekey() error {
	priv, err := generateECDHKey()
	if err != nil {
		return err
	}
	c.pendingRekeyKey = priv
	rm := RekeyMessage{PublicKey: priv.PublicKey().Bytes()}
	if err := SendTunnelMessage(c.controlConn, c.controlKey, message.TypeRekey, rm); err != nil {
		c.pendingRekeyKey = nil
		return fmt.Errorf("send rekey: %w", err)
	}
	return nil
}

func (c *Client) handleRekeyAck(payload []byte) error {
	var rm RekeyMessage
	if err := DecodePayload(payload, &rm); err != nil {
		return fmt.Errorf("decode rekey ack: %w", err)
	}
	if c.pendingRekeyKey == nil {
		return fmt.Errorf("rekey ack without pending key")
	}
	newKey, err := deriveRekeyKey(c.pendingRekeyKey, c.controlKey, rm.PublicKey)
	c.pendingRekeyKey = nil
	if err != nil {
		return fmt.Errorf("derive rekey key: %w", err)
	}
	c.controlKey = newKey
	log.Debugf("tunnel rekeyed")
	return nil
}

func (c *Client) handleMessage(msgType message.Type, payload []byte) error {
	switch msgType {
	case message.TypeHeartbeat:
		return nil

	case message.TypeRekeyAck:
		return c.handleRekeyAck(payload)

	case message.TypeReqProxy:
		var req ReqProxyMessage
		if err := DecodePayload(payload, &req); err != nil {
			return fmt.Errorf("decode req-proxy: %w", err)
		}

		log.Debugf("received req-proxy: %s (client: %s)", req.TunnelID, req.ClientAddr)
		return c.handleProxyRequest(req)

	case message.TypeTunnelClose:
		var tc TunnelCloseMessage
		if err := DecodePayload(payload, &tc); err == nil {
			log.Infof("tunnel closed by server: %s", tc.Reason)
		}
		return fmt.Errorf("tunnel closed by server")

	case message.TypeTunnelError:
		var errMsg TunnelErrorMessage
		if err := DecodePayload(payload, &errMsg); err == nil {
			log.Errorf("tunnel error from server: %s", errMsg.Message)
		}
		return fmt.Errorf("tunnel error from server")

	default:
		log.Debugf("unexpected message type: %s", msgType)
	}

	return nil
}

// handleProxyRequest handles a ReqProxy from the server.
func (c *Client) handleProxyRequest(req ReqProxyMessage) error {
	proxyConn, err := c.openProxyConnection(req)
	if err != nil {
		return fmt.Errorf("open proxy connection: %w", err)
	}
	defer proxyConn.Close()

	if c.config.TunnelType == TunnelTypeUDP {
		return c.handleUDPProxy(proxyConn)
	}

	// Use connection pool for HTTP tunnels, dial fresh for others
	var localConn net.Conn
	if c.localPool != nil {
		localConn, err = c.localPool.Get()
		if err != nil {
			return fmt.Errorf("connect to local service %s: %w", c.config.LocalAddr, err)
		}
	} else {
		localConn, err = net.DialTimeout("tcp", c.config.LocalAddr, 10*time.Second)
		if err != nil {
			return fmt.Errorf("connect to local service %s: %w", c.config.LocalAddr, err)
		}
	}
	defer func() {
		if c.localPool != nil {
			c.localPool.Put(localConn)
		} else {
			localConn.Close()
		}
	}()

	log.Debugf("proxy established: local %s ↔ relay (proxy %s)", c.config.LocalAddr, req.ProxyID)

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		io.Copy(localConn, proxyConn)
		localConn.Close()
		proxyConn.Close()
	}()
	go func() {
		defer wg.Done()
		io.Copy(proxyConn, localConn)
		localConn.Close()
		proxyConn.Close()
	}()
	wg.Wait()
	log.Debugf("proxy %s finished", req.ProxyID)
	return nil
}

// handleUDPProxy handles a UDP proxy connection with datagram framing.
// Reads framed datagrams from the yamux stream, writes them as UDP datagrams
// to the local service, and sends responses back through the stream.
func (c *Client) handleUDPProxy(stream net.Conn) error {
	localAddr := c.config.LocalAddr
	udpAddr, err := net.ResolveUDPAddr("udp", localAddr)
	if err != nil {
		return fmt.Errorf("resolve udp addr %s: %w", localAddr, err)
	}

	localConn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		return fmt.Errorf("dial udp %s: %w", localAddr, err)
	}
	defer localConn.Close()

	log.Debugf("UDP proxy established: local %s ↔ relay", localAddr)

	var wg sync.WaitGroup
	wg.Add(2)

	// Read framed datagrams from stream → local UDP
	go func() {
		defer wg.Done()
		for {
			var lenBuf [4]byte
			if _, err := io.ReadFull(stream, lenBuf[:]); err != nil {
				return
			}
			dLen := int(lenBuf[0])<<24 | int(lenBuf[1])<<16 | int(lenBuf[2])<<8 | int(lenBuf[3])
			if dLen < 1 || dLen > udpMaxDatagram {
				return
			}

			data := make([]byte, dLen)
			if _, err := io.ReadFull(stream, data); err != nil {
				return
			}

			if _, err := localConn.Write(data); err != nil {
				log.Debugf("udp local write: %v", err)
				return
			}
		}
	}()

	// Read UDP responses → framed datagrams to stream
	go func() {
		defer wg.Done()
		buf := make([]byte, udpMaxDatagram)
		for {
			n, err := localConn.Read(buf)
			if err != nil {
				return
			}

			data := buf[:n]
			lenBuf := []byte{
				byte(len(data) >> 24),
				byte(len(data) >> 16),
				byte(len(data) >> 8),
				byte(len(data)),
			}
			if _, err := stream.Write(lenBuf); err != nil {
				return
			}
			if _, err := stream.Write(data); err != nil {
				return
			}
		}
	}()

	wg.Wait()
	log.Debugf("UDP proxy finished")
	return nil
}

// openProxyConnection opens a new yamux stream over the data port session
// and identifies it with the proxyID. The data port session is lazily established
// on first call and reused for all subsequent proxy connections (multiplexing).
func (c *Client) openProxyConnection(req ReqProxyMessage) (net.Conn, error) {
	session, err := c.getOrCreateDataSession()
	if err != nil {
		return nil, fmt.Errorf("get data session: %w", err)
	}

	// Open a new stream for this proxy connection
	stream, err := session.OpenStream()
	if err != nil {
		return nil, fmt.Errorf("open stream: %w", err)
	}

	// Set a deadline for the initial handshake
	_ = stream.SetWriteDeadline(time.Now().Add(10 * time.Second))
	defer stream.SetWriteDeadline(time.Time{})

	// Send length-prefixed proxyID
	idBytes := []byte(req.ProxyID)
	header := []byte{byte(len(idBytes) >> 8), byte(len(idBytes))}
	if _, err := stream.Write(header); err != nil {
		stream.Close()
		return nil, fmt.Errorf("send proxy id header: %w", err)
	}
	if _, err := stream.Write(idBytes); err != nil {
		stream.Close()
		return nil, fmt.Errorf("send proxy id body: %w", err)
	}

	// Notify server via control connection that proxy is established
	SendTunnelMessage(c.controlConn, c.controlKey, message.TypeProxyConnected, ProxyConnectedMessage{
		TunnelID: req.TunnelID,
		ProxyID:  req.ProxyID,
	})

	log.Debugf("proxy stream established for %s", req.ProxyID)
	return stream, nil
}

// getOrCreateDataSession lazily establishes the stream session over the data port.
// The session is reused for all proxy connections (HTTP request multiplexing).
func (c *Client) getOrCreateDataSession() (StreamSession, error) {
	c.dataSessionMu.Lock()
	defer c.dataSessionMu.Unlock()

	if c.dataSession != nil && !c.dataSession.IsClosed() {
		return c.dataSession, nil
	}

	// Determine the data port address
	serverAddr := c.config.ServerAddr
	host, portStr, err := net.SplitHostPort(serverAddr)
	if err != nil {
		host = serverAddr
		portStr = fmt.Sprint(DefaultTunnelPort)
	}
	var port int
	fmt.Sscanf(portStr, "%d", &port)
	dataAddr := net.JoinHostPort(host, fmt.Sprint(port+1))

	// QUIC transport: use native QUIC streams instead of yamux
	if c.config.Transport == "quic" {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		qconn, err := QuicDial(ctx, dataAddr, nil)
		if err != nil {
			return nil, fmt.Errorf("QUIC dial data port %s: %w", dataAddr, err)
		}
		c.dataSession = NewQuicSessionWrapper(qconn)
		log.Debugf("established QUIC data session to %s", dataAddr)
		return c.dataSession, nil
	}

	// Default: TCP + yamux
	conn, err := comm.Dial(dataAddr, 10*time.Second)
	if err != nil {
		return nil, fmt.Errorf("dial data port %s: %w", dataAddr, err)
	}

	// Apply TCP optimizations
	if tcp, ok := conn.(*net.TCPConn); ok {
		_ = tcp.SetNoDelay(true)
		_ = tcp.SetKeepAlive(true)
		_ = tcp.SetKeepAlivePeriod(30 * time.Second)
	}

	cfg := yamux.DefaultConfig()
	cfg.MaxStreamWindowSize = 16 * 1024 * 1024 // 16MB
	if c.config.YamuxWindowSize > 0 {
		cfg.MaxStreamWindowSize = uint32(c.config.YamuxWindowSize)
	}
	cfg.LogOutput = io.Discard

	session, err := YamuxClient(conn, cfg)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("yamux client init: %w", err)
	}

	c.dataSession = session
	log.Debugf("established yamux data session to %s", dataAddr)
	return session, nil
}

// pakeHandshake performs PAKE authentication with the relay.
// Derives the PAKE weak key from the password (SHA-256) to prevent MITM.
func (c *Client) pakeHandshake(conn *comm.Comm) ([]byte, error) {
	pass := c.config.ServerPass
	if pass == "" {
		pass = "pass123" // default — must match server
	}
	weakKey := sha256.Sum256([]byte(pass))

	A, err := pake.InitCurve(weakKey[:], 0, "siec")
	if err != nil {
		return nil, fmt.Errorf("pake init: %w", err)
	}

	if err := conn.Send(A.Bytes()); err != nil {
		return nil, fmt.Errorf("send pake A: %w", err)
	}

	Bbytes, err := conn.Receive()
	if err != nil {
		return nil, fmt.Errorf("receive pake B: %w", err)
	}

	if err := A.Update(Bbytes); err != nil {
		return nil, fmt.Errorf("pake update: %w", err)
	}

	strongKey, err := A.SessionKey()
	if err != nil {
		return nil, fmt.Errorf("pake session key: %w", err)
	}

	// Generate salt
	encKey, salt, err := crypt.New(strongKey, nil)
	if err != nil {
		return nil, fmt.Errorf("crypt new: %w", err)
	}

	// Send salt
	if err := conn.Send(salt); err != nil {
		return nil, fmt.Errorf("send salt: %w", err)
	}

	// Send password (pass variable from earlier in pakeHandshake)
	passEnc, err := crypt.Encrypt([]byte(pass), encKey)
	if err != nil {
		return nil, fmt.Errorf("encrypt password: %w", err)
	}

	if err := conn.Send(passEnc); err != nil {
		return nil, fmt.Errorf("send password: %w", err)
	}

	// Receive OK
	okData, err := conn.Receive()
	if err != nil {
		return nil, fmt.Errorf("receive ok: %w", err)
	}

	// The OK data is just the encKey sent back as confirmation
	_ = okData

	return encKey, nil
}

// cleanup closes the control connection and SOCKS5 listener.
func (c *Client) cleanup() {
	if c.controlConn != nil {
		c.controlConn.Close()
		c.controlConn = nil
	}
	c.dataSessionMu.Lock()
	if c.dataSession != nil {
		c.dataSession.Close()
		c.dataSession = nil
	}
	c.dataSessionMu.Unlock()
	if c.socks5Listener != nil {
		c.socks5Listener.Close()
	}
	if c.localPool != nil {
		c.localPool.Close()
	}
	c.controlKey = nil
	c.setState(TunnelStateDisconnected)
}

// backoffDuration returns the reconnection delay using exponential backoff.
func (c *Client) backoffDuration() time.Duration {
	if c.reconnectAttempt <= 0 {
		return 0
	}

	delay := DefaultReconnectBase
	for i := 1; i < c.reconnectAttempt; i++ {
		delay *= 2
		if delay >= DefaultReconnectMax {
			return DefaultReconnectMax
		}
	}

	// Add jitter (±20%)
	jitter := time.Duration(int64(float64(delay) * 0.2))
	if jitter == 0 {
		jitter = 100 * time.Millisecond
	}

	return delay + time.Duration(int64(jitter))
}

// wrapTLS wraps a TCP connection in TLS.
func wrapTLS(conn net.Conn, serverAddr string, cfg TLSConfig) (net.Conn, error) {
	host, _, err := net.SplitHostPort(serverAddr)
	if err != nil {
		host = serverAddr
	}

	tlsCfg := &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: cfg.InsecureSkipVerify,
		MinVersion:         tls.VersionTLS12,
	}

	if cfg.CertFile != "" && cfg.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("load client cert: %w", err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	}

	tlsConn := tls.Client(conn, tlsCfg)
	if err := tlsConn.Handshake(); err != nil {
		conn.Close()
		return nil, fmt.Errorf("tls handshake: %w", err)
	}

	return tlsConn, nil
}

// StartAccess runs the client in private tunnel access mode.
func (c *Client) Migrate(targetAddr, targetPass string) error {
	oldConn := c.controlConn
	oldKey := c.controlKey
	savedAddr := c.config.ServerAddr
	savedPass := c.config.ServerPass

	c.config.ServerAddr = targetAddr
	c.config.ServerPass = targetPass
	c.controlConn = nil
	c.controlKey = nil

	err := c.connect()
	if err != nil {
		c.config.ServerAddr = savedAddr
		c.config.ServerPass = savedPass
		c.controlConn = oldConn
		c.controlKey = oldKey
		return fmt.Errorf("migrate connect: %w", err)
	}

	if oldConn != nil {
		log.Infof("migrated tunnel %s → %s", savedAddr, targetAddr)
		oldConn.Close()
	}

	if c.dataSession != nil {
		c.dataSession.Close()
		c.dataSession = nil
	}
	_, err = c.getOrCreateDataSession()
	if err != nil {
		log.Warnf("migrate: new data session: %v", err)
	}
	return nil
}

func (c *Client) StartAccess() error {
	serverAddr := c.config.ServerAddr

	// Parse server address for data port
	host, portStr, err := net.SplitHostPort(serverAddr)
	if err != nil {
		serverAddr = net.JoinHostPort(serverAddr, fmt.Sprint(DefaultTunnelPort))
		host = serverAddr
		portStr = fmt.Sprint(DefaultTunnelPort)
	}
	var basePort int
	fmt.Sscanf(portStr, "%d", &basePort)
	dataAddr := net.JoinHostPort(host, fmt.Sprintf("%d", basePort+1))

	log.Infof("private access: connecting to relay data port %s", dataAddr)

	// Connect to data port
	conn, err := comm.Dial(dataAddr, 10*time.Second)
	if err != nil {
		return fmt.Errorf("access dial data port: %w", err)
	}

	// Establish yamux session
	cfg := yamux.DefaultConfig()
	cfg.LogOutput = io.Discard
	session, err := yamux.Client(conn, cfg)
	if err != nil {
		conn.Close()
		return fmt.Errorf("access yamux client: %w", err)
	}
	defer session.Close()

	// In access mode with a dedicated local listener:
	if c.config.LocalAddr != "" && c.config.AccessToken != "" {
		log.Infof("private access: listening on %s → tunnel token %s...", c.config.LocalAddr, c.config.AccessToken[:8])
		return c.accessListenLoop(session, c.config.LocalAddr, c.config.AccessToken)
	}

	return fmt.Errorf("private access requires --local address")
}

// accessListenLoop listens on a local address and bridges each connection
// through a yamux stream with the ACCESS| prefix.
func (c *Client) accessListenLoop(session *yamux.Session, localAddr, accessToken string) error {
	listener, err := net.Listen("tcp", localAddr)
	if err != nil {
		return fmt.Errorf("access listen %s: %w", localAddr, err)
	}
	defer listener.Close()

	log.Infof("private access: local listener on %s", localAddr)

	for {
		localConn, err := listener.Accept()
		if err != nil {
			select {
			case <-c.quit:
				return nil
			default:
				log.Debugf("access accept error: %v", err)
				continue
			}
		}
		go c.accessHandleConn(session, localConn, accessToken)
	}
}

// accessHandleConn handles a single local connection in access mode.
func (c *Client) accessHandleConn(session *yamux.Session, localConn net.Conn, accessToken string) {
	defer localConn.Close()

	stream, err := session.OpenStream()
	if err != nil {
		log.Debugf("access open stream: %v", err)
		return
	}
	defer stream.Close()

	// Send ACCESS|token header (length-prefixed)
	header := "ACCESS|" + accessToken
	idLen := len(header)
	lenBytes := []byte{byte(idLen >> 8), byte(idLen & 0xff)}
	if _, err := stream.Write(lenBytes); err != nil {
		return
	}
	if _, err := io.WriteString(stream, header); err != nil {
		return
	}

	// Pipe bidirectional
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		io.Copy(stream, localConn)
		stream.Close()
		localConn.Close()
	}()
	go func() {
		defer wg.Done()
		io.Copy(localConn, stream)
		stream.Close()
		localConn.Close()
	}()
	wg.Wait()
}

func (c *Client) clearResumeState() {
	if c.config.ResumeFile != "" {
		os.Remove(c.config.ResumeFile)
	}
}

type resumeState struct {
	TunnelID string `json:"tunnel_id"`
	Token    string `json:"token"`
}

func (c *Client) loadResumeState() (string, string) {
	data, err := os.ReadFile(c.config.ResumeFile)
	if err != nil {
		return "", ""
	}
	var rs resumeState
	if err := json.Unmarshal(data, &rs); err != nil {
		return "", ""
	}
	return rs.TunnelID, rs.Token
}

func (c *Client) saveResumeState(tunnelID, token string) {
	rs := resumeState{TunnelID: tunnelID, Token: token}
	data, err := json.Marshal(rs)
	if err != nil {
		return
	}
	if err := os.WriteFile(c.config.ResumeFile, data, 0o600); err != nil {
		log.Warnf("save resume state: %v", err)
	}
}

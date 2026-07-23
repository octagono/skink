package tunnel

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os/exec"
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

// TunnelEventHandler is called when tunnels are registered or unregistered.
type TunnelEventHandler interface {
	OnTunnelRegister(entry *TunnelEntry)
	OnTunnelUnregister(entry *TunnelEntry)
}

// TunnelEventHandlerFunc is a function-based adapter for TunnelEventHandler.
type TunnelEventHandlerFunc struct {
	RegisterFn   func(entry *TunnelEntry)
	UnregisterFn func(entry *TunnelEntry)
}

func (f *TunnelEventHandlerFunc) OnTunnelRegister(entry *TunnelEntry) {
	if f.RegisterFn != nil {
		f.RegisterFn(entry)
	}
}

func (f *TunnelEventHandlerFunc) OnTunnelUnregister(entry *TunnelEntry) {
	if f.UnregisterFn != nil {
		f.UnregisterFn(entry)
	}
}

// Server handles tunnel control connections from clients.
type Server struct {
	host        string
	port        int
	dataPort    int
	password    string
	relayDomain string
	httpPort    int
	tcpPortBase int
	registry    *Registry
	metrics     *Metrics
	store       *TunnelStore // persisted tunnel state, nil if not enabled

	// next available TCP port for TCP tunnels
	tcpPortMu   sync.Mutex
	tcpPortNext int

	listener     net.Listener
	dataListener net.Listener
	wssListener  *http.Server
	pipeListener net.Listener
	pipeName     string
	quit         chan struct{}
	wg           sync.WaitGroup

	// Queue of pending proxy connections: proxyID → chan net.Conn
	pendingProxy sync.Map

	// Queue of pending exec requests: execID → chan ExecResponse
	pendingExec sync.Map

	// Event handler for tunnel lifecycle
	eventHandler TunnelEventHandler

	// Multi-hop relay chaining
	upstreamAddr string
	relayHop     *RelayHop

	// Configurable yamux window size (bytes)
	yamuxWindowSize int

	apiServer *APIServer
	apiToken  string

	// HA sync peers
	syncPeers    []string
	syncPort     int
	syncListener net.Listener

	// allowExec gates remote command execution via EXEC| streams. Off by default.
	allowExec bool
}

// NewServer creates a new tunnel server.
// The data port for proxy connections is set to port+1 by default.
func NewServer(host string, port int, password, relayDomain string, httpPort, tcpPortBase int) *Server {
	s := &Server{
		host:        host,
		port:        port,
		dataPort:    port + 1,
		password:    password,
		relayDomain: relayDomain,
		httpPort:    httpPort,
		tcpPortBase: tcpPortBase,
		tcpPortNext: tcpPortBase,
		registry:    NewRegistry(),
		metrics:     NewMetrics(),
		quit:        make(chan struct{}),
	}

	// Wire metrics registry reference
	s.metrics.SetRegistry(s.registry)

	// Wire registry to use the server's event handler for cleanup/unregister events
	s.registry.SetEventHandler(&TunnelEventHandlerFunc{
		UnregisterFn: func(entry *TunnelEntry) {
			s.metrics.RecordTunnelUnregistered()
			if s.store != nil {
				s.store.Delete(entry.ID)
			}
			s.pushSync(entry.ID, "unregister")
			if s.eventHandler != nil {
				s.eventHandler.OnTunnelUnregister(entry)
			}
		},
	})

	return s
}

// Registry returns the tunnel registry.
func (s *Server) Registry() *Registry {
	return s.registry
}

// SetEventHandler sets a lifecycle event handler for tunnel registrations.
func (s *Server) SetEventHandler(h TunnelEventHandler) {
	s.eventHandler = h
}

// SetUpstream configures an upstream relay for chaining.
// The server will connect to the upstream and register tunnels on it.
func (s *Server) SetUpstream(addr string) error {
	s.upstreamAddr = addr
	hop := NewRelayHop(s, addr)
	if err := hop.Start(); err != nil {
		return fmt.Errorf("connect upstream %s: %w", addr, err)
	}
	s.relayHop = hop
	log.Infof("relay hopping enabled: upstream %s", addr)
	return nil
}

func (s *Server) SetStore(store *TunnelStore) {
	s.store = store
}

func (s *Server) SetSync(peers []string, syncPort int) {
	s.syncPeers = peers
	s.syncPort = syncPort
}

func (s *Server) pushSync(tunnelID string, action string) {
	if len(s.syncPeers) == 0 {
		return
	}
	var msg TunnelSyncMessage
	msg.Action = action
	msg.RelayAddr = fmt.Sprintf("%s:%d", s.host, s.port)
	if action == "register" {
		entry := s.registry.LookupByID(tunnelID)
		if entry == nil {
			return
		}
		msg.Tunnel = &PersistedTunnel{
			TunnelID:    entry.ID,
			Subdomain:   entry.Subdomain,
			Type:        entry.Type,
			LocalAddr:   entry.LocalAddr,
			Password:    entry.Password,
			Token:       entry.Token,
			AccessToken: entry.AccessToken,
			Private:     entry.Private,
			PublicPort:  entry.PublicPort,
			RemoteAddr:  entry.RemoteAddr,
			CreatedAt:   entry.CreatedAt,
		}
		msg.TunnelID = entry.ID
	} else {
		msg.TunnelID = tunnelID
	}
	data, err := json.Marshal(msg)
	if err != nil {
		return
	}
	for _, peer := range s.syncPeers {
		go s.sendSyncToPeer(peer, data)
	}
}

func (s *Server) sendSyncToPeer(peer string, data []byte) {
	conn, err := net.DialTimeout("tcp", peer, 5*time.Second)
	if err != nil {
		log.Debugf("sync dial peer %s: %v", peer, err)
		return
	}
	defer conn.Close()
	if s.password != "" {
		h := sha256.Sum256([]byte(s.password))
		enc, err := encryptAESGCM(data, h[:])
		if err == nil {
			data = enc
		}
	}
	lenBuf := []byte{byte(len(data) >> 8), byte(len(data))}
	if _, err := conn.Write(lenBuf); err != nil {
		return
	}
	if _, err := conn.Write(data); err != nil {
		return
	}
}

func (s *Server) syncAcceptLoop() {
	defer s.wg.Done()
	for {
		conn, err := s.syncListener.Accept()
		if err != nil {
			select {
			case <-s.quit:
				return
			default:
				continue
			}
		}
		go s.handleSyncConn(conn)
	}
}

func (s *Server) handleSyncConn(conn net.Conn) {
	defer conn.Close()
	var lenBuf [2]byte
	if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
		return
	}
	length := int(lenBuf[0])<<8 | int(lenBuf[1])
	if length > 1<<20 {
		return
	}
	data := make([]byte, length)
	if _, err := io.ReadFull(conn, data); err != nil {
		return
	}
	if s.password != "" {
		h := sha256.Sum256([]byte(s.password))
		dec, err := decryptAESGCM(data, h[:])
		if err == nil {
			data = dec
		}
	}
	var msg TunnelSyncMessage
	if err := json.Unmarshal(data, &msg); err != nil {
		return
	}
	switch msg.Action {
	case "register":
		if msg.Tunnel == nil {
			return
		}
		pt := msg.Tunnel
		entry := &TunnelEntry{
			ID:          pt.TunnelID,
			Subdomain:   pt.Subdomain,
			Type:        pt.Type,
			LocalAddr:   pt.LocalAddr,
			Password:    pt.Password,
			Token:       pt.Token,
			AccessToken: pt.AccessToken,
			Private:     pt.Private,
			PublicPort:  pt.PublicPort,
			RemoteAddr:  pt.RemoteAddr,
			CreatedAt:   pt.CreatedAt,
			LastSeen:    time.Now(),
		}
		if err := s.registry.Register(entry); err != nil {
			log.Debugf("sync register tunnel %s: %v", pt.TunnelID, err)
			return
		}
		if s.store != nil {
			s.store.Save(pt)
		}
		log.Debugf("sync: tunnel %s registered from %s", pt.Subdomain, msg.RelayAddr)
	case "unregister":
		s.registry.Unregister(msg.TunnelID)
		if s.store != nil {
			s.store.Delete(msg.TunnelID)
		}
		log.Debugf("sync: tunnel %s unregistered from %s", msg.TunnelID, msg.RelayAddr)
	}
}

// SetPipeName configures the named pipe name for Windows SMB transport.
// Call before Start().
func (s *Server) SetPipeName(name string) {
	if name == "" {
		name = "skink-tunnel"
	}
	s.pipeName = name
}

// Metrics returns the server's metrics instance.
func (s *Server) Metrics() *Metrics {
	return s.metrics
}

// Start begins listening for tunnel client connections.
func (s *Server) Start() error {
	// Start named pipe listener if configured (Windows SMB lateral movement)
	if s.pipeName != "" {
		pl, err := ListenPipe(s.pipeName)
		if err != nil {
			return fmt.Errorf("listen pipe %s: %w", s.pipeName, err)
		}
		s.pipeListener = pl
		s.wg.Add(1)
		go s.pipeAcceptLoop()
		log.Infof("tunnel server listening on named pipe %s", s.pipeName)
	}

	addr := fmt.Sprintf("%s:%d", s.host, s.port)
	if s.host == "" || s.host == "0.0.0.0" {
		addr = fmt.Sprintf(":%d", s.port)
	}

	var err error
	s.listener, err = net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("tunnel server listen on %s: %w", addr, err)
	}

	log.Infof("tunnel server listening on %s (control)", addr)

	// Start data port listener for proxy connections
	dataAddr := fmt.Sprintf("%s:%d", s.host, s.dataPort)
	if s.host == "" || s.host == "0.0.0.0" {
		dataAddr = fmt.Sprintf(":%d", s.dataPort)
	}

	s.dataListener, err = net.Listen("tcp", dataAddr)
	if err != nil {
		s.listener.Close()
		return fmt.Errorf("tunnel server listen on data port %s: %w", dataAddr, err)
	}

	log.Infof("tunnel server listening on %s (data)", dataAddr)

	// Start cleanup goroutine
	s.wg.Add(1)
	go s.cleanupLoop()

	// Accept loops
	s.wg.Add(1)
	go s.acceptLoop()

	s.wg.Add(1)
	go s.dataAcceptLoop()

	// WSS is served through the HTTPS proxy when TLS is configured.
	// Without TLS, WebSocket is available on the control port.
	if s.port > 0 {
		wsAddr := fmt.Sprintf("%s:%d", s.host, s.port)
		wsSrv, err := StartWSServer(wsAddr, func(conn net.Conn) {
			s.wg.Add(1)
			s.HandleConnection(conn)
		})
		if err != nil {
			log.Warnf("WSS transport not available: %v", err)
		} else {
			s.wssListener = wsSrv
			log.Infof("tunnel server WSS on %s%s", wsAddr, WSPath)
		}
	}

	// Restore persisted tunnels from the store.
	if s.store != nil {
		for _, pt := range s.store.LoadAll() {
			entry := &TunnelEntry{
				ID:          pt.TunnelID,
				Subdomain:   pt.Subdomain,
				Type:        pt.Type,
				LocalAddr:   pt.LocalAddr,
				Password:    pt.Password,
				Token:       pt.Token,
				AccessToken: pt.AccessToken,
				Private:     pt.Private,
				PublicPort:  pt.PublicPort,
				RemoteAddr:  pt.RemoteAddr,
				CreatedAt:   pt.CreatedAt,
				LastSeen:    time.Now(),
			}
			if err := s.registry.Register(entry); err != nil {
				log.Warnf("restore tunnel %s: %v", pt.TunnelID, err)
				s.store.Delete(pt.TunnelID)
				continue
			}
			if s.eventHandler != nil {
				s.eventHandler.OnTunnelRegister(entry)
			}
			s.metrics.RecordTunnelRegistered()
			log.Infof("restored tunnel: %s (%s) → %s", pt.Subdomain, pt.Type, pt.LocalAddr)
		}
	}

	if s.syncPort > 0 {
		addr := fmt.Sprintf(":%d", s.syncPort)
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			log.Warnf("sync listen on %s: %v", addr, err)
		} else {
			s.syncListener = ln
			s.wg.Add(1)
			go s.syncAcceptLoop()
			log.Infof("sync listener on %s", addr)
		}
	}

	return nil
}

func (s *Server) Stop() {
	close(s.quit)
	if s.relayHop != nil {
		s.relayHop.Stop()
	}
	if s.listener != nil {
		s.listener.Close()
	}
	if s.syncListener != nil {
		s.syncListener.Close()
	}
	if s.dataListener != nil {
		s.dataListener.Close()
	}
	if s.wssListener != nil {
		s.wssListener.Close()
	}
	if s.pipeListener != nil {
		s.pipeListener.Close()
	}
	s.wg.Wait()
	if s.store != nil {
		s.store.Close()
	}
	log.Info("tunnel server stopped")
}

func (s *Server) acceptLoop() {
	defer s.wg.Done()
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			select {
			case <-s.quit:
				return
			default:
				log.Errorf("tunnel accept error: %v", err)
				continue
			}
		}

		s.wg.Add(1)
		go s.HandleConnection(conn)
	}
}

// pipeAcceptLoop accepts connections from named pipes.
func (s *Server) pipeAcceptLoop() {
	defer s.wg.Done()
	for {
		conn, err := s.pipeListener.Accept()
		if err != nil {
			select {
			case <-s.quit:
				return
			default:
				log.Errorf("pipe accept error: %v", err)
				continue
			}
		}

		s.wg.Add(1)
		go s.HandleConnection(conn)
	}
}

func (s *Server) cleanupLoop() {
	defer s.wg.Done()
	ttlTicker := time.NewTicker(10 * time.Minute)
	hbTicker := time.NewTicker(30 * time.Second)
	defer ttlTicker.Stop()
	defer hbTicker.Stop()

	for {
		select {
		case <-ttlTicker.C:
			removed := s.registry.Cleanup()
			if removed > 0 {
				log.Infof("cleaned %d stale tunnels", removed)
			}
		case <-hbTicker.C:
			removed := s.registry.CleanupHeartbeats(3 * time.Minute)
			if removed > 0 {
				log.Infof("cleaned %d tunnels with stale heartbeats", removed)
			}
		case <-s.quit:
			return
		}
	}
}

// HandleWSSConnection tracks the connection in the server WaitGroup
// before delegating to HandleConnection. Use this from WSS handlers
// that do not already hold a WaitGroup reference.
func (s *Server) HandleWSSConnection(rawConn net.Conn) {
	s.wg.Add(1)
	go s.HandleConnection(rawConn)
}

// handleConnection handles an incoming tunnel control connection.
// Proxy data connections come through the separate data port instead.
func (s *Server) HandleConnection(rawConn net.Conn) {
	defer s.wg.Done()
	defer rawConn.Close()

	applyProxyTCPOptions(rawConn)

	c := comm.New(rawConn)

	key, err := s.pakeHandshake(c)
	if err != nil {
		log.Debugf("tunnel PAKE handshake failed: %v", err)
		return
	}

	msgType, payload, err := ReceiveTunnelMessage(c, key)
	if err != nil {
		log.Debugf("tunnel receive message failed: %v", err)
		return
	}

	switch msgType {
	case message.TypeTunnelRegister:
		s.handleTunnelRegister(c, key, payload, rawConn)
	case message.TypeTunnelResume:
		s.handleTunnelResume(c, key, payload)
	default:
		log.Debugf("expected tunnel-register or tunnel-resume, got %s", msgType)
	}
}

// dataAcceptLoop accepts proxy data connections on the data port.
// Each TCP connection is wrapped in a yamux session; each yamux stream must
// send a length-prefixed proxyID as the first message.
func (s *Server) dataAcceptLoop() {
	defer s.wg.Done()
	for {
		conn, err := s.dataListener.Accept()
		if err != nil {
			select {
			case <-s.quit:
				return
			default:
				log.Debugf("data accept error: %v", err)
				continue
			}
		}

		go s.handleDataSession(conn)
	}
}

// handleDataSession wraps a TCP connection in a yamux server session and
// accepts streams from it. Each stream carries one proxy data channel.
func (s *Server) handleDataSession(conn net.Conn) {
	applyProxyTCPOptions(conn)

	cfg := yamux.DefaultConfig()
	cfg.MaxStreamWindowSize = 16 * 1024 * 1024 // 16MB default
	cfg.LogOutput = io.Discard

	// Apply configurable window size
	if s.yamuxWindowSize > 0 {
		cfg.MaxStreamWindowSize = uint32(s.yamuxWindowSize)
	}

	session, err := yamux.Server(conn, cfg)
	if err != nil {
		log.Debugf("yamux server init: %v", err)
		conn.Close()
		return
	}
	defer session.Close()

	for {
		stream, err := session.Accept()
		if err != nil {
			log.Debugf("yamux accept stream: %v", err)
			return
		}
		go s.handleDataStream(stream)
	}
}

// handleDataStream handles a single yamux stream carrying proxy data.
// Reads the proxyID (length-prefixed) and delivers the connection to the pending proxy.
// The stream is NOT closed on success — ownership transfers to the RequestProxy caller.
// For forward proxy streams (SOCKS5), the proxyID starts with "FWD|" followed by
// the target address, and the server connects to the target directly.
func (s *Server) handleDataStream(conn net.Conn) {
	// Set a deadline for the initial handshake (DoS hardening)
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))

	// Read length-prefixed proxyID
	var idLen [2]byte
	if _, err := io.ReadFull(conn, idLen[:]); err != nil {
		log.Debugf("data stream read id length: %v", err)
		conn.Close()
		return
	}

	idSize := int(idLen[0])<<8 | int(idLen[1])
	if idSize < 1 || idSize > 512 {
		log.Debugf("data stream invalid id length: %d", idSize)
		conn.Close()
		return
	}

	idBuf := make([]byte, idSize)
	if _, err := io.ReadFull(conn, idBuf); err != nil {
		log.Debugf("data stream read id: %v", err)
		conn.Close()
		return
	}

	// Clear the deadline — let the proxied bytes flow without timeout
	_ = conn.SetReadDeadline(time.Time{})

	proxyID := string(idBuf)
	log.Debugf("data stream for proxyID=%s", proxyID)

	// Check for downstream relay registration
	if strings.HasPrefix(proxyID, "REG|") || strings.HasPrefix(proxyID, "DATA|") {
		// This stream is from a downstream relay (multi-hop)
		// "REG|tunnelID|type|localAddr" — register tunnel on upstream
		// "DATA|tunnelID|targetAddr" — proxy data through downstream
		HandleUpstreamRegistration(s, conn, proxyID)
		return
	}

	// Check for forward proxy (SOCKS5) streams
	if strings.HasPrefix(proxyID, "FWD|") {
		targetAddr := strings.TrimPrefix(proxyID, "FWD|")
		s.handleForwardStream(conn, targetAddr)
		return
	}

	// Check for exec streams
	if strings.HasPrefix(proxyID, "EXEC|") {
		s.handleExecStream(conn, proxyID)
		return
	}

	// Check for private tunnel access streams
	if strings.HasPrefix(proxyID, "ACCESS|") {
		s.handleAccessStream(conn, proxyID)
		return
	}

	// Reverse proxy: deliver to the waiting RequestProxy caller
	v, ok := s.pendingProxy.LoadAndDelete(proxyID)
	if !ok {
		log.Debugf("no pending proxy for id=%s", proxyID)
		conn.Close()
		return
	}
	ch := v.(chan net.Conn)

	// Don't close the connection — it's now owned by the RequestProxy handler
	ch <- conn
}

// handleForwardStream handles a forward proxy stream (SOCKS5).
// The server connects to the target address and pipes the stream to it.
func (s *Server) handleForwardStream(conn net.Conn, targetAddr string) {
	// SSRF protection: resolve once and block private/loopback addresses.
	// Dial the resolved IP directly to prevent DNS rebinding TOCTOU.
	resolvedAddr, blocked := resolveAndCheckTarget(targetAddr)
	if blocked {
		log.Debugf("forward proxy: blocked private address %s", targetAddr)
		conn.Close()
		return
	}

	log.Debugf("forward proxy: connecting to %s", resolvedAddr)

	targetConn, err := net.DialTimeout("tcp", resolvedAddr, 10*time.Second)
	if err != nil {
		log.Debugf("forward proxy dial %s: %v", targetAddr, err)
		conn.Close()
		return
	}

	log.Debugf("forward proxy: connected to %s", targetAddr)
	PipeConnZeroCopy(conn, targetConn)
}

// handleAccessStream handles a private tunnel access stream.
// The stream prefix format is: "ACCESS|<accessToken>|<targetAddr>"
// If targetAddr is empty, the tunnel's configured local address is used.
func (s *Server) handleAccessStream(conn net.Conn, header string) {
	parts := strings.SplitN(header[7:], "|", 2)
	if len(parts) < 1 {
		log.Debugf("access stream: missing token")
		conn.Close()
		return
	}

	accessToken := parts[0]
	targetAddr := ""
	if len(parts) > 1 {
		targetAddr = parts[1]
	}

	log.Debugf("access stream: token=%s target=%s", accessToken[:min(8, len(accessToken))], targetAddr)

	// Look up the tunnel by access token
	entry := s.registry.LookupByAccessToken(accessToken)
	if entry == nil {
		log.Warnf("access stream: invalid token")
		conn.Close()
		return
	}

	// Use the tunnel's configured local address if not specified
	if targetAddr == "" {
		targetAddr = entry.LocalAddr
	}

	// Request a proxy connection from the tunnel client
	proxyConn, err := s.RequestProxy(entry.ID, targetAddr)
	if err != nil {
		log.Debugf("access stream request proxy: %v", err)
		conn.Close()
		return
	}
	defer proxyConn.Close()

	log.Infof("private access: bridging %s → tunnel %s (%s)", targetAddr, entry.Subdomain, entry.ID[:8])

	// Pipe bidirectional with pooled buffers
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		defer proxyConn.Close()
		defer conn.Close()
		buf := getCopyBuf()
		io.CopyBuffer(proxyConn, conn, buf)
		putCopyBuf(buf)
	}()
	go func() {
		defer wg.Done()
		defer proxyConn.Close()
		defer conn.Close()
		buf := getCopyBuf()
		io.CopyBuffer(conn, proxyConn, buf)
		putCopyBuf(buf)
	}()
	wg.Wait()
}

// copyBufferPool is a shared pool of 32KB buffers for io.CopyBuffer.
// Reduces GC pressure on high-throughput tunnel connections by reusing
// buffers instead of allocating per-stream 32KB slices.
var copyBufferPool = sync.Pool{
	New: func() interface{} {
		b := make([]byte, 32*1024)
		return &b
	},
}

// getCopyBuf returns a 32KB buffer from the pool.
func getCopyBuf() []byte {
	return *copyBufferPool.Get().(*[]byte)
}

// putCopyBuf returns a buffer to the pool.
func putCopyBuf(buf []byte) {
	copyBufferPool.Put(&buf)
}

// handleExecStream handles a remote execution stream.
// The stream carries "EXEC|cmd" in the header.
// For client-side execution, the relay sends a control message and
// waits for the client to send the response through another yamux stream.
func (s *Server) handleExecStream(conn net.Conn, header string) {
	defer conn.Close()

	// RCE gate: remote command execution is disabled unless explicitly opted in.
	if !s.allowExec {
		conn.Write([]byte(`{"error":"exec disabled on this relay","exit_code":-1}`))
		return
	}

	cmdStr := strings.TrimPrefix(header, "EXEC|")

	// For now, exec runs on the relay directly (useful for jump box scenarios).
	// For client-side exec, we'd need to route through pendingExec mechanism.
	log.Debugf("exec on relay: %s", cmdStr)

	// Simple relay-side exec
	parts := strings.Fields(cmdStr)
	if len(parts) == 0 {
		conn.Write([]byte(`{"error":"empty command","exit_code":-1}`))
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, parts[0], parts[1:]...)
	output, err := cmd.CombinedOutput()
	exitCode := 0
	errMsg := ""
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			errMsg = err.Error()
			exitCode = -1
		}
	}

	resp := ExecResponse{
		Stdout:   string(output),
		ExitCode: exitCode,
		Error:    errMsg,
	}
	respBytes, _ := json.Marshal(resp)
	conn.Write(respBytes)
}

// applyProxyTCPOptions sets TCP_NODELAY and keepalive on a connection.
func applyProxyTCPOptions(conn net.Conn) {
	if tcp, ok := conn.(*net.TCPConn); ok {
		_ = tcp.SetNoDelay(true)
		_ = tcp.SetKeepAlive(true)
		_ = tcp.SetKeepAlivePeriod(30 * time.Second)
	}
}

// handleTunnelRegister handles a new tunnel control connection registration.
func (s *Server) handleTunnelRegister(c *comm.Comm, key []byte, payload []byte, rawConn net.Conn) {
	var reg TunnelRegistration
	if err := DecodePayload(payload, &reg); err != nil {
		log.Debugf("decode tunnel register failed: %v", err)
		return
	}

	if reg.Version > 0 && reg.Version != CurrentProtocolVersion {
		log.Debugf("client protocol version %d, server version %d", reg.Version, CurrentProtocolVersion)
	}

	if reg.Type != TunnelTypeHTTP && reg.Type != TunnelTypeTCP && reg.Type != TunnelTypeUDP && reg.Type != TunnelTypeSOCKS5 {
		SendTunnelMessage(c, key, message.TypeTunnelError, TunnelErrorMessage{
			Message: fmt.Sprintf("unsupported tunnel type: %s", reg.Type),
			Code:    400,
		})
		return
	}

	// Generate tunnel ID
	tunnelID := generateTunnelID()

	// Handle subdomain
	subdomain := strings.ToLower(reg.Subdomain)
	if subdomain == "" {
		subdomain = generateSubdomain()
	}

	token := strings.TrimSpace(reg.Token)

	// Generate access token for private tunnels
	var accessToken string
	if reg.Private {
		accessToken = generateAccessToken()
	}

	// Build the tunnel entry
	entry := &TunnelEntry{
		ID:          tunnelID,
		Subdomain:   subdomain,
		Type:        reg.Type,
		LocalAddr:   reg.LocalAddr,
		Password:    reg.Password,
		Token:       token,
		AccessToken: accessToken,
		Private:     reg.Private,
		ControlConn: c,
		ControlKey:  key,
		CreatedAt:   time.Now(),
		LastSeen:    time.Now(),
		MaxConns:    reg.MaxConns,
		ACLAllow:    reg.ACLAllow,
		ACLDeny:     reg.ACLDeny,
	}

	if reg.BandwidthLimit > 0 || reg.IdleTimeout > 0 {
		entry.BandwidthLimit = reg.BandwidthLimit
		entry.IdleTimeout = reg.IdleTimeout
	}
	switch reg.Type {
	case TunnelTypeHTTP:
		if reg.Private {
			entry.RemoteAddr = fmt.Sprintf("%s (private)", s.relayDomain)
		} else {
			publicURL := fmt.Sprintf("http://%s.%s", subdomain, s.relayDomain)
			if s.httpPort != 0 && s.httpPort != 80 {
				publicURL = fmt.Sprintf("http://%s.%s:%d", subdomain, s.relayDomain, s.httpPort)
			}
			entry.RemoteAddr = publicURL
		}

	case TunnelTypeTCP, TunnelTypeUDP:
		if reg.Private {
			entry.RemoteAddr = fmt.Sprintf("%s (private)", s.relayDomain)
		} else {
			publicPort := s.allocateTCPPort()
			entry.PublicPort = publicPort
			entry.RemoteAddr = fmt.Sprintf("%s:%d", s.relayDomain, publicPort)
		}

	case TunnelTypeSOCKS5:
		entry.RemoteAddr = fmt.Sprintf("%s (SOCKS5)", s.relayDomain)
	}

	// Register
	if err := s.registry.Register(entry); err != nil {
		SendTunnelMessage(c, key, message.TypeTunnelError, TunnelErrorMessage{
			Message: err.Error(),
			Code:    409,
		})
		return
	}

	if s.eventHandler != nil {
		s.eventHandler.OnTunnelRegister(entry)
	}
	s.metrics.RecordTunnelRegistered()

	if s.store != nil {
		pt := &PersistedTunnel{
			TunnelID:    tunnelID,
			Subdomain:   subdomain,
			Type:        reg.Type,
			LocalAddr:   reg.LocalAddr,
			Password:    reg.Password,
			Token:       token,
			AccessToken: accessToken,
			Private:     reg.Private,
			PublicPort:  entry.PublicPort,
			RemoteAddr:  entry.RemoteAddr,
			CreatedAt:   time.Now(),
		}
		if err := s.store.Save(pt); err != nil {
			log.Warnf("persist tunnel %s: %v", tunnelID, err)
		}
	}
	s.pushSync(tunnelID, "register")

	if s.relayHop != nil && entry.Type != TunnelTypeHTTP {
		if err := s.relayHop.RegisterTunnel(entry); err != nil {
			log.Warnf("upstream register tunnel %s: %v", entry.Subdomain, err)
		}
	}

	// Send success response
	info := TunnelInfo{
		TunnelID:    tunnelID,
		PublicURL:   entry.RemoteAddr,
		Subdomain:   subdomain,
		AssignedAt:  time.Now().Format(time.RFC3339),
		Token:       token,
		AccessToken: accessToken,
	}
	if reg.Type == TunnelTypeTCP || reg.Type == TunnelTypeUDP || reg.Type == TunnelTypeSOCKS5 {
		info.PublicPort = entry.PublicPort
		info.RemoteAddr = entry.RemoteAddr
	}

	if err := SendTunnelMessage(c, key, message.TypeTunnelRegistered, info); err != nil {
		log.Errorf("tunnel send registered failed: %v", err)
		s.registry.Unregister(tunnelID)
		return
	}

	if reg.Private {
		log.Infof("private tunnel %s registered (access token: %s...) [%s]", subdomain, accessToken[:8], tunnelID)
	} else {
		log.Infof("tunnel %s registered: %s → %s [%s]", subdomain, entry.RemoteAddr, entry.LocalAddr, tunnelID)
	}

	// Run the control connection event loop
	s.controlLoop(c, key, entry)
}

func (s *Server) handleTunnelResume(c *comm.Comm, key []byte, payload []byte) {
	var resume TunnelResumeMessage
	if err := DecodePayload(payload, &resume); err != nil {
		log.Debugf("decode tunnel resume failed: %v", err)
		return
	}
	if s.store == nil {
		SendTunnelMessage(c, key, message.TypeTunnelError, TunnelErrorMessage{
			Message: "session persistence not enabled on relay",
			Code:    501,
		})
		return
	}
	pt := s.store.Lookup(resume.TunnelID)
	if pt == nil {
		SendTunnelMessage(c, key, message.TypeTunnelError, TunnelErrorMessage{
			Message: "no such tunnel",
			Code:    404,
		})
		return
	}
	if pt.Token != "" && pt.Token != resume.Token {
		SendTunnelMessage(c, key, message.TypeTunnelError, TunnelErrorMessage{
			Message: "token mismatch",
			Code:    401,
		})
		return
	}
	entry := s.registry.LookupByID(resume.TunnelID)
	if entry != nil {
		if entry.ControlConn != nil {
			entry.ControlConn.Close()
		}
		s.registry.Unregister(resume.TunnelID)
	}
	entry = &TunnelEntry{
		ID:          pt.TunnelID,
		Subdomain:   pt.Subdomain,
		Type:        pt.Type,
		LocalAddr:   pt.LocalAddr,
		Password:    pt.Password,
		Token:       pt.Token,
		AccessToken: pt.AccessToken,
		Private:     pt.Private,
		PublicPort:  pt.PublicPort,
		RemoteAddr:  pt.RemoteAddr,
		ControlConn: c,
		ControlKey:  key,
		CreatedAt:   pt.CreatedAt,
		LastSeen:    time.Now(),
	}
	if err := s.registry.Register(entry); err != nil {
		SendTunnelMessage(c, key, message.TypeTunnelError, TunnelErrorMessage{
			Message: err.Error(),
			Code:    409,
		})
		return
	}
	if s.eventHandler != nil {
		s.eventHandler.OnTunnelRegister(entry)
	}
	s.metrics.RecordTunnelRegistered()
	info := TunnelInfo{
		TunnelID:    pt.TunnelID,
		PublicURL:   pt.RemoteAddr,
		Subdomain:   pt.Subdomain,
		AssignedAt:  time.Now().Format(time.RFC3339),
		Token:       pt.Token,
		AccessToken: pt.AccessToken,
	}
	if pt.Type == TunnelTypeTCP || pt.Type == TunnelTypeUDP || pt.Type == TunnelTypeSOCKS5 {
		info.PublicPort = pt.PublicPort
		info.RemoteAddr = pt.RemoteAddr
	}
	if err := SendTunnelMessage(c, key, message.TypeTunnelRegistered, info); err != nil {
		log.Errorf("tunnel send resume response failed: %v", err)
		s.registry.Unregister(pt.TunnelID)
		return
	}
	log.Infof("tunnel resumed: %s (%s) → %s [%s]", pt.Subdomain, pt.Type, pt.LocalAddr, pt.TunnelID)
	s.controlLoop(c, key, entry)
}

func (s *Server) controlLoop(c *comm.Comm, key []byte, entry *TunnelEntry) {
	hbCfg := DefaultHeartbeatConfig()
	ticker := time.NewTicker(hbCfg.NextInterval())
	defer ticker.Stop()

	heartbeatFailures := 0
	const maxHeartbeatFailures = 3

	// Channel to receive messages from the dedicated reader goroutine
	type msgResult struct {
		msgType message.Type
		payload []byte
		err     error
	}

	msgCh := make(chan msgResult, 1)
	doneCh := make(chan struct{})
	defer close(doneCh)

	// Start a dedicated reader goroutine that blocks on Receive
	go func() {
		for {
			msgType, payload, err := ReceiveTunnelMessage(c, key)
			select {
			case msgCh <- msgResult{msgType, payload, err}:
			case <-doneCh:
				return
			}
		}
	}()

	for {
		select {
		case <-s.quit:
			return

		case result := <-msgCh:
			if result.err != nil {
				log.Debugf("tunnel control connection lost: %v", result.err)
				s.registry.Unregister(entry.ID)
				return
			}

			switch result.msgType {
			case message.TypeHeartbeat:
				var hb HeartbeatMessage
				if err := DecodePayload(result.payload, &hb); err == nil {
					s.registry.Touch(entry.ID)
				}

			case message.TypeProxyConnected:
				// Client confirmed proxy data connection established.
				// The connection itself arrives via the data port handler,
				// so this is just a confirmation — no action needed.

			case message.TypeRTTProbe:
				var rpm RTTProbeMessage
				if err := DecodePayload(result.payload, &rpm); err == nil {
					SendTunnelMessage(c, key, message.TypeRTTProbe, rpm)
				}

			case message.TypeRekey:
				var rm RekeyMessage
				if err := DecodePayload(result.payload, &rm); err != nil {
					log.Debugf("decode rekey failed: %v", err)
					continue
				}
				newKey, serverPub, err := doRekeyServerSide(key, rm.PublicKey)
				if err != nil {
					log.Debugf("rekey failed: %v", err)
					continue
				}
				ack := RekeyMessage{PublicKey: serverPub}
				if err := SendTunnelMessage(c, key, message.TypeRekeyAck, ack); err != nil {
					log.Debugf("send rekey ack failed: %v", err)
					continue
				}
				key = newKey
				entry.ControlKey = newKey
				log.Debugf("tunnel rekeyed")

			case message.TypeTunnelClose:
				var tc TunnelCloseMessage
				if err := DecodePayload(result.payload, &tc); err == nil {
					log.Infof("tunnel %s closed by client: %s", entry.Subdomain, tc.Reason)
				}
				s.registry.Unregister(entry.ID)
				return

			default:
				log.Debugf("unexpected tunnel message type: %s", result.msgType)
			}

		case <-ticker.C:
			if err := SendTunnelMessage(c, key, message.TypeHeartbeat, HeartbeatMessage{
				Timestamp: time.Now().Unix(),
			}); err != nil {
				heartbeatFailures++
				log.Debugf("heartbeat send failed (%d/%d): %v", heartbeatFailures, maxHeartbeatFailures, err)
				if heartbeatFailures >= maxHeartbeatFailures {
					log.Infof("tunnel %s heartbeat failed, unregistering", entry.Subdomain)
					s.registry.Unregister(entry.ID)
					return
				}
			} else {
				heartbeatFailures = 0
				s.registry.Touch(entry.ID)
			}
		}
	}
}

// RequestProxy sends a ReqProxy to the tunnel client and waits for a proxy connection
// to arrive on the same listener. Returns the proxy connection that the HTTP handler can use.
// Enforces per-tunnel concurrency limit if MaxConns > 0.
func matchACL(addr string, allowList, denyList []string) bool {
	if len(allowList) == 0 && len(denyList) == 0 {
		return true
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	ip := net.ParseIP(host)

	// Check deny first
	for _, d := range denyList {
		if strings.Contains(d, "/") && ip != nil {
			_, cidr, _ := net.ParseCIDR(d)
			if cidr != nil && cidr.Contains(ip) {
				return false
			}
		} else if strings.Contains(d, "*.") && ip == nil {
			if strings.HasSuffix(host, d[1:]) {
				return false
			}
		} else if ip == nil && host == d {
			return false
		} else if ip != nil && ip.String() == d {
			return false
		}
	}

	if len(allowList) == 0 {
		return true
	}
	for _, a := range allowList {
		if strings.Contains(a, "/") && ip != nil {
			_, cidr, _ := net.ParseCIDR(a)
			if cidr != nil && cidr.Contains(ip) {
				return true
			}
		} else if strings.Contains(a, "*.") && ip == nil {
			if strings.HasSuffix(host, a[1:]) {
				return true
			}
		} else if ip == nil && host == a {
			return true
		} else if ip != nil && ip.String() == a {
			return true
		}
	}
	return false
}

func (s *Server) RequestProxy(tunnelID string, clientAddr string) (net.Conn, error) {
	entry := s.registry.LookupByID(tunnelID)
	if entry == nil {
		return nil, fmt.Errorf("tunnel %s not found", tunnelID)
	}

	if !matchACL(clientAddr, entry.ACLAllow, entry.ACLDeny) {
		return nil, fmt.Errorf("acl: %s denied", clientAddr)
	}

	if !entry.AcquireConn() {
		return nil, fmt.Errorf("tunnel %s at max concurrent connections (%d)", entry.Subdomain, entry.MaxConns)
	}
	defer entry.ReleaseConn()

	proxyID := generateProxyID()

	// Create a channel to receive the proxy connection
	proxyCh := make(chan net.Conn, 1)

	s.pendingProxy.Store(proxyID, proxyCh)

	defer func() {
		// Atomic delete if still present (race-safe cleanup on timeout)
		s.pendingProxy.Delete(proxyID)
	}()

	// Determine data address for the client to connect to
	dataAddr := fmt.Sprintf("%s:%d", s.host, s.dataPort)
	if s.host == "" || s.host == "0.0.0.0" {
		// Client needs to connect to the same host as the control connection
		// but with the data port. We include this in the message.
		dataAddr = fmt.Sprintf(":%d", s.dataPort)
	}

	// Send ReqProxy to client
	req := ReqProxyMessage{
		TunnelID:   tunnelID,
		ClientAddr: clientAddr,
		ProxyID:    proxyID,
		DataAddr:   dataAddr,
	}

	if err := SendTunnelMessage(entry.ControlConn, entry.ControlKey, message.TypeReqProxy, req); err != nil {
		return nil, fmt.Errorf("send req-proxy: %w", err)
	}

	// Wait for the proxy connection to arrive via the main accept loop.
	// Use context.WithTimeout to avoid leaking timers (time.After leaks until fire).
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	start := time.Now()
	s.metrics.RecordProxyStart()

	select {
	case conn := <-proxyCh:
		s.metrics.RecordProxyRequest(time.Since(start), false)
		return conn, nil
	case <-ctx.Done():
		s.metrics.RecordProxyRequest(time.Since(start), true)
		s.metrics.RecordProxyEnd()
		return nil, fmt.Errorf("proxy connection timeout after 10s")
	}
}

// RequestExec sends an exec request to a tunnel client and returns the response.
func (s *Server) RequestExec(tunnelID, command string) (*ExecResponse, error) {
	entry := s.registry.LookupByID(tunnelID)
	if entry == nil {
		return nil, fmt.Errorf("tunnel not found: %s", tunnelID)
	}

	execID := generateProxyID() // reuse proxy ID generator for uniqueness

	// Create a channel for the response
	respCh := make(chan *ExecResponse, 1)
	s.pendingExec.Store(execID, respCh)
	defer s.pendingExec.Delete(execID)

	// Send exec request to client
	if err := SendTunnelMessage(entry.ControlConn, entry.ControlKey, message.TypeExecRequest, ExecRequest{
		Command: command,
	}); err != nil {
		return nil, fmt.Errorf("send exec request: %w", err)
	}

	// Wait for response with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	select {
	case resp := <-respCh:
		return resp, nil
	case <-ctx.Done():
		return nil, fmt.Errorf("exec timeout after 60s")
	}
}

// SetYamuxWindowSize configures the yamux stream window size.
// Call before Start(). Default is 16MB.
func (s *Server) SetYamuxWindowSize(size int) {
	s.yamuxWindowSize = size
}

// SetAllowExec enables or disables remote command execution on the relay.
// Remote exec via EXEC| streams is disabled by default for safety.
func (s *Server) SetAllowExec(allow bool) {
	s.allowExec = allow
}

// pakeHandshake performs PAKE authentication for the tunnel control connection.
// Derives the PAKE weak key from the password (SHA-256) to prevent MITM session
// substitution that would be possible with a hardcoded weak key.
func (s *Server) pakeHandshake(c *comm.Comm) ([]byte, error) {
	weakKey := sha256.Sum256([]byte(s.password))

	B, err := pake.InitCurve(weakKey[:], 1, "siec")
	if err != nil {
		return nil, fmt.Errorf("pake init: %w", err)
	}

	Abytes, err := c.Receive()
	if err != nil {
		return nil, fmt.Errorf("receive pake A: %w", err)
	}

	if err := B.Update(Abytes); err != nil {
		return nil, fmt.Errorf("pake update: %w", err)
	}

	if err := c.Send(B.Bytes()); err != nil {
		return nil, fmt.Errorf("send pake B: %w", err)
	}

	strongKey, err := B.SessionKey()
	if err != nil {
		return nil, fmt.Errorf("pake session key: %w", err)
	}

	// Receive salt
	salt, err := c.Receive()
	if err != nil {
		return nil, fmt.Errorf("receive salt: %w", err)
	}

	encKey, _, err := crypt.New(strongKey, salt)
	if err != nil {
		return nil, fmt.Errorf("crypt new: %w", err)
	}

	// Receive password
	passwordEnc, err := c.Receive()
	if err != nil {
		return nil, fmt.Errorf("receive password: %w", err)
	}

	passwordBytes, err := crypt.Decrypt(passwordEnc, encKey)
	if err != nil {
		return nil, fmt.Errorf("decrypt password: %w", err)
	}

	if strings.TrimSpace(string(passwordBytes)) != strings.TrimSpace(s.password) {
		SendTunnelMessage(c, encKey, message.TypeTunnelError, TunnelErrorMessage{
			Message: "bad password",
			Code:    401,
		})
		return nil, fmt.Errorf("bad password")
	}

	// Send OK
	if err := c.Send(encKey); err != nil {
		return nil, fmt.Errorf("send ok: %w", err)
	}

	return encKey, nil
}

// allocateTCPPort assigns the next available TCP port for TCP tunnels.
func (s *Server) allocateTCPPort() int {
	s.tcpPortMu.Lock()
	defer s.tcpPortMu.Unlock()

	port := s.tcpPortNext
	s.tcpPortNext++
	return port
}

// resolveAndCheckTarget resolves the target address and checks if it's private/loopback.
// Returns the resolved address (IP:port) to dial directly, eliminating DNS rebinding TOCTOU.
// If blocked, returns ("", true). If unresolvable, returns the original address, false.
func resolveAndCheckTarget(addr string) (string, bool) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
		port = ""
	}
	// If it's already an IP, check directly
	if ip := net.ParseIP(host); ip != nil {
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() {
			return addr, true
		}
		return addr, false
	}
	// Resolve hostname to IP (single resolution — dial uses this IP)
	ips, err := net.LookupHost(host)
	if err != nil || len(ips) == 0 {
		return addr, false // can't resolve, allow (will fail at dial)
	}
	ip := net.ParseIP(ips[0])
	if ip == nil {
		return addr, false
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() {
		return addr, true
	}
	// Dial the resolved IP directly to prevent DNS rebinding
	if port != "" {
		return net.JoinHostPort(ip.String(), port), false
	}
	return ip.String(), false
}

func generateTunnelID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func generateAccessToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func generateSubdomain() string {
	b := make([]byte, 4)
	rand.Read(b)
	return "skink-" + hex.EncodeToString(b)
}

func generateProxyID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}

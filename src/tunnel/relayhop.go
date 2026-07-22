package tunnel

import (
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/yamux"
	"github.com/octagono/skink/src/comm"
	log "github.com/schollz/logger"
)

// RelayHop enables relay chaining. A downstream relay connects to an upstream
// relay via yamux, registers tunnels on the upstream, and pipes data through
// the nested yamux session.
//
// Architecture:
//   Target → Downstream Relay → (yamux) → Upstream Relay → Public
//
// The downstream connects to the upstream and registers each local tunnel
// as a "shadow tunnel" on the upstream. The upstream allocates public ports
// and handles incoming connections. Data flows through nested yamux streams:
//   Public → Upstream → (yamux stream) → Downstream → (yamux stream) → Client

type RelayHop struct {
	upstreamAddr string         // address of the upstream relay (host:port)
	session      *yamux.Session // persistent yamux session to upstream
	server       *Server        // local server reference
	quit         chan struct{}
	wg           sync.WaitGroup

	mu      sync.Mutex
	tunnels map[string]*hopTunnel // local tunnel ID → hop info
}

type hopTunnel struct {
	localID    string
	upstreamID string
	localAddr  string
	tunnelType TunnelType
	publicPort int
}

func NewRelayHop(server *Server, upstreamAddr string) *RelayHop {
	return &RelayHop{
		upstreamAddr: upstreamAddr,
		server:       server,
		quit:         make(chan struct{}),
		tunnels:      make(map[string]*hopTunnel),
	}
}

// Start connects to the upstream relay and starts handling upstream streams.
func (h *RelayHop) Start() error {
	conn, err := comm.Dial(h.upstreamAddr, 10*time.Second)
	if err != nil {
		return fmt.Errorf("connect upstream %s: %w", h.upstreamAddr, err)
	}

	cfg := yamux.DefaultConfig()
	cfg.LogOutput = io.Discard
	session, err := yamux.Client(conn, cfg)
	if err != nil {
		conn.Close()
		return fmt.Errorf("yamux client to upstream: %w", err)
	}

	h.session = session
	log.Infof("relay hop: connected to upstream %s", h.upstreamAddr)

	// Handle incoming streams from upstream (proxy data deliveries)
	h.wg.Add(1)
	go h.acceptLoop()

	return nil
}

func (h *RelayHop) Stop() {
	close(h.quit)
	if h.session != nil {
		h.session.Close()
	}
	h.wg.Wait()
}

// RegisterTunnel registers a local tunnel on the upstream relay.
// Called when a client registers a tunnel on the local relay.
func (h *RelayHop) RegisterTunnel(entry *TunnelEntry) error {
	if h.session == nil {
		return fmt.Errorf("upstream not connected")
	}

	// Types that don't need upstream forwarding
	if entry.Type != TunnelTypeTCP && entry.Type != TunnelTypeUDP {
		return nil
	}

	// Open a control stream to register on upstream
	stream, err := h.session.Open()
	if err != nil {
		return fmt.Errorf("open upstream stream: %w", err)
	}
	defer stream.Close()

	// Send registration: "REG|<type>|<localAddr>"
	regMsg := fmt.Sprintf("REG|%s|%s|%s", entry.ID, entry.Type, entry.LocalAddr)
	if _, err := io.WriteString(stream, regMsg); err != nil {
		return fmt.Errorf("send reg to upstream: %w", err)
	}

	// Read response: "OK|<port>" or "ERR|<msg>"
	resp := make([]byte, 256)
	n, err := stream.Read(resp)
	if err != nil {
		return fmt.Errorf("read upstream response: %w", err)
	}

	respStr := string(resp[:n])
	if len(respStr) < 3 || respStr[:3] != "OK|" {
		return fmt.Errorf("upstream rejected: %s", respStr)
	}

	portStr := respStr[3:]
	var port int
	fmt.Sscanf(portStr, "%d", &port)

	h.mu.Lock()
	h.tunnels[entry.ID] = &hopTunnel{
		localID:    entry.ID,
		localAddr:  entry.LocalAddr,
		tunnelType: entry.Type,
		publicPort: port,
	}
	h.mu.Unlock()

	log.Infof("relay hop: tunnel %s registered on upstream port %d", entry.Subdomain, port)
	return nil
}

func (h *RelayHop) UnregisterTunnel(entry *TunnelEntry) {
	h.mu.Lock()
	delete(h.tunnels, entry.ID)
	h.mu.Unlock()
}

// acceptLoop handles incoming streams from the upstream relay.
// Each stream carries proxy data for a tunnel registered on the upstream.
func (h *RelayHop) acceptLoop() {
	defer h.wg.Done()

	for {
		stream, err := h.session.AcceptStream()
		if err != nil {
			select {
			case <-h.quit:
				return
			default:
				log.Debugf("relay hop accept: %v", err)
				return
			}
		}

		go h.handleUpstreamStream(stream)
	}
}

// handleUpstreamStream handles a data delivery from the upstream.
// Read the target tunnel ID and pipe to the local client.
func (h *RelayHop) handleUpstreamStream(stream net.Conn) {
	defer stream.Close()

	// Read header: "DATA|<tunnelID>|<targetAddr>"
	header := make([]byte, 512)
	n, err := stream.Read(header)
	if err != nil {
		log.Debugf("relay hop read header: %v", err)
		return
	}

	headerStr := string(header[:n])
	if len(headerStr) < 5 || headerStr[:5] != "DATA|" {
		log.Debugf("relay hop bad header: %s", headerStr)
		return
	}

	parts := strings.SplitN(headerStr[5:], "|", 2)
	if len(parts) < 2 {
		return
	}
	tunnelID := parts[0]
	targetAddr := parts[1]

	log.Debugf("relay hop: data for tunnel %s, target %s", tunnelID, targetAddr)

	// Send a proxy request to the local client via the server
	proxyConn, err := h.server.RequestProxy(tunnelID, targetAddr)
	if err != nil {
		log.Debugf("relay hop request proxy: %v", err)
		return
	}
	defer proxyConn.Close()

	// Pipe upstream stream ↔ local proxy connection (pooled buffers)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		defer proxyConn.Close()
		defer stream.Close()
		buf := getCopyBuf()
		io.CopyBuffer(proxyConn, stream, buf)
		putCopyBuf(buf)
	}()
	go func() {
		defer wg.Done()
		defer proxyConn.Close()
		defer stream.Close()
		buf := getCopyBuf()
		io.CopyBuffer(stream, proxyConn, buf)
		putCopyBuf(buf)
	}()
	wg.Wait()
}

// HandleUpstreamRegistration handles an incoming tunnel registration from a downstream relay.
// Called on the UPSTREAM relay when it receives a registration stream.
// The registration header has already been read (starts with "REG|" or "DATA|").
func HandleUpstreamRegistration(s *Server, stream net.Conn, header string) {
	// Already have the header — parse it
	if strings.HasPrefix(header, "REG|") {
		handleUpstreamRegister(s, stream, header)
	} else if strings.HasPrefix(header, "DATA|") {
		handleUpstreamData(s, stream, header)
	} else {
		log.Debugf("upstream unknown header: %s", header)
	}
}

func handleUpstreamRegister(s *Server, stream net.Conn, header string) {
	parts := strings.SplitN(header[4:], "|", 3)
	if len(parts) < 3 {
		return
	}
	tunnelID := parts[0]
	tunnelType := TunnelType(parts[1])
	localAddr := parts[2]

	// Validate tunnel type
	if tunnelType != TunnelTypeTCP && tunnelType != TunnelTypeUDP {
		io.WriteString(stream, "ERR|unsupported type")
		return
	}

	publicPort := s.allocateTCPPort()

	// Create a "hop" tunnel entry (no direct client — data comes via yamux)
	entry := &TunnelEntry{
		ID:         tunnelID,
		Subdomain:  "hop-" + tunnelID[:8],
		Type:       tunnelType,
		LocalAddr:  localAddr,
		PublicPort: publicPort,
		RemoteAddr: fmt.Sprintf(":%d", publicPort),
		CreatedAt:  time.Now(),
		LastSeen:   time.Now(),
	}

	if err := s.registry.Register(entry); err != nil {
		io.WriteString(stream, fmt.Sprintf("ERR|%s", err.Error()))
		return
	}

	io.WriteString(stream, fmt.Sprintf("OK|%d", publicPort))

	log.Infof("upstream: registered hop tunnel %s on port %d (→ %s)", tunnelID, publicPort, localAddr)
}

func handleUpstreamData(s *Server, stream net.Conn, header string) {
	parts := strings.SplitN(header[5:], "|", 2)
	if len(parts) < 2 {
		return
	}
	tunnelID := parts[0]
	targetAddr := parts[1]

	log.Debugf("upstream data: tunnel %s, target %s", tunnelID, targetAddr)

	proxyConn, err := s.RequestProxy(tunnelID, targetAddr)
	if err != nil {
		log.Debugf("upstream request proxy: %v", err)
		return
	}
	defer proxyConn.Close()

	// Pipe upstream stream ↔ proxy connection (pooled buffers)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		defer proxyConn.Close()
		defer stream.Close()
		buf := getCopyBuf()
		io.CopyBuffer(proxyConn, stream, buf)
		putCopyBuf(buf)
	}()
	go func() {
		defer wg.Done()
		defer proxyConn.Close()
		defer stream.Close()
		buf := getCopyBuf()
		io.CopyBuffer(stream, proxyConn, buf)
		putCopyBuf(buf)
	}()
	wg.Wait()
}

package proxy

import (
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/octagono/skink/src/tunnel"
	log "github.com/schollz/logger"
)

const (
	udpReadTimeout     = 60 * time.Second // idle timeout before closing session
	udpMaxDatagram     = 65507            // max safe UDP datagram size
	udpCleanupInterval = 5 * time.Minute  // stale session cleanup
)

// udpSession tracks a UDP client session and its associated yamux stream.
type udpSession struct {
	clientAddr *net.UDPAddr
	stream     net.Conn
	lastSeen   time.Time
}

// UDPProxy listens on a UDP port and forwards datagrams through
// a tunnel client via framed yamux streams. Each unique source address
// gets its own yamux stream (opened via Server.RequestProxy).
type UDPProxy struct {
	server   *tunnel.Server
	port     int
	conn     *net.UDPConn
	sessions map[string]*udpSession
	mu       sync.Mutex
	quit     chan struct{}
	wg       sync.WaitGroup
}

func NewUDPProxy(server *tunnel.Server, port int) *UDPProxy {
	return &UDPProxy{
		server:   server,
		port:     port,
		sessions: make(map[string]*udpSession),
		quit:     make(chan struct{}),
	}
}

func (p *UDPProxy) Start() error {
	addr := fmt.Sprintf(":%d", p.port)
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return fmt.Errorf("resolve udp addr %s: %w", addr, err)
	}

	p.conn, err = net.ListenUDP("udp", udpAddr)
	if err != nil {
		return fmt.Errorf("udp listen on %s: %w", addr, err)
	}

	log.Infof("UDP proxy listening on %s", addr)

	p.wg.Add(1)
	go p.readLoop()

	p.wg.Add(1)
	go p.cleanupLoop()

	return nil
}

func (p *UDPProxy) Stop() {
	close(p.quit)
	if p.conn != nil {
		p.conn.Close()
	}
	p.wg.Wait()
}

// readLoop reads datagrams from the UDP socket and forwards them
// through the appropriate tunnel session.
func (p *UDPProxy) readLoop() {
	defer p.wg.Done()

	buf := make([]byte, udpMaxDatagram)
	for {
		select {
		case <-p.quit:
			return
		default:
		}

		n, clientAddr, err := p.conn.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-p.quit:
				return
			default:
				log.Debugf("udp proxy read: %v", err)
				continue
			}
		}

		data := make([]byte, n)
		copy(data, buf[:n])
		go p.handleDatagram(data, clientAddr)
	}
}

// handleDatagram routes a datagram to the correct tunnel session.
func (p *UDPProxy) handleDatagram(data []byte, clientAddr *net.UDPAddr) {
	key := clientAddr.String()

	p.mu.Lock()
	session, exists := p.sessions[key]
	if exists {
		session.lastSeen = time.Now()
		p.mu.Unlock()
		// Write framed datagram to existing stream
		p.writeFramedDatagram(session.stream, data)
		return
	}
	p.mu.Unlock()

	// New client — open a tunnel session
	stream, err := p.openTunnelSession(clientAddr)
	if err != nil {
		log.Debugf("udp open tunnel: %v", err)
		return
	}

	p.mu.Lock()
	p.sessions[key] = &udpSession{
		clientAddr: clientAddr,
		stream:     stream,
		lastSeen:   time.Now(),
	}
	p.mu.Unlock()

	p.writeFramedDatagram(stream, data)

	// Start reading responses back from the stream
	p.wg.Add(1)
	go p.responseReader(key, stream)
}

// responseReader reads framed datagrams from the yamux stream and
// writes them back to the UDP client.
func (p *UDPProxy) responseReader(key string, stream net.Conn) {
	defer p.wg.Done()

	for {
		select {
		case <-p.quit:
			return
		default:
		}

		// Read 4-byte length prefix
		var lenBuf [4]byte
		if _, err := io.ReadFull(stream, lenBuf[:]); err != nil {
			p.removeSession(key)
			return
		}
		dLen := int(lenBuf[0])<<24 | int(lenBuf[1])<<16 | int(lenBuf[2])<<8 | int(lenBuf[3])
		if dLen < 1 || dLen > udpMaxDatagram {
			p.removeSession(key)
			return
		}

		// Read datagram payload
		dBuf := make([]byte, dLen)
		if _, err := io.ReadFull(stream, dBuf); err != nil {
			p.removeSession(key)
			return
		}

		// Find session to get client address
		p.mu.Lock()
		session, exists := p.sessions[key]
		p.mu.Unlock()
		if !exists {
			return
		}

		// Write datagram back to UDP client
		if _, err := p.conn.WriteToUDP(dBuf, session.clientAddr); err != nil {
			log.Debugf("udp write to client: %v", err)
			p.removeSession(key)
			return
		}
	}
}

// writeFramedDatagram sends a length-prefixed datagram over a yamux stream.
func (p *UDPProxy) writeFramedDatagram(stream net.Conn, data []byte) {
	lenBuf := []byte{
		byte(len(data) >> 24),
		byte(len(data) >> 16),
		byte(len(data) >> 8),
		byte(len(data)),
	}
	if _, err := stream.Write(lenBuf); err != nil {
		log.Debugf("udp write frame header: %v", err)
		return
	}
	if _, err := stream.Write(data); err != nil {
		log.Debugf("udp write frame data: %v", err)
	}
}

// openTunnelSession opens a yamux stream through the tunnel for a new UDP client.
// Finds the tunnel entry by port and calls RequestProxy to establish the data channel.
func (p *UDPProxy) openTunnelSession(clientAddr *net.UDPAddr) (net.Conn, error) {
	// Find which tunnel owns this port
	var entry *tunnel.TunnelEntry
	for _, e := range p.server.Registry().List() {
		if e.Type == tunnel.TunnelTypeUDP && e.PublicPort == p.port {
			entry = e
			break
		}
	}
	if entry == nil {
		return nil, fmt.Errorf("no UDP tunnel for port %d", p.port)
	}

	// Use RequestProxy to establish a data channel
	proxyConn, err := p.server.RequestProxy(entry.ID, clientAddr.String())
	if err != nil {
		return nil, fmt.Errorf("request proxy: %w", err)
	}

	return proxyConn, nil
}

func (p *UDPProxy) removeSession(key string) {
	p.mu.Lock()
	session, exists := p.sessions[key]
	if exists {
		delete(p.sessions, key)
	}
	p.mu.Unlock()

	if exists && session.stream != nil {
		session.stream.Close()
	}
}

// cleanupLoop periodically removes stale sessions.
func (p *UDPProxy) cleanupLoop() {
	defer p.wg.Done()

	ticker := time.NewTicker(udpCleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			p.evictStale()
		case <-p.quit:
			return
		}
	}
}

// evictStale removes sessions that haven't sent a datagram within udpReadTimeout.
func (p *UDPProxy) evictStale() {
	p.mu.Lock()
	defer p.mu.Unlock()

	now := time.Now()
	for key, session := range p.sessions {
		if now.Sub(session.lastSeen) > udpReadTimeout {
			if session.stream != nil {
				session.stream.Close()
			}
			delete(p.sessions, key)
			log.Debugf("udp session evicted: %s", key)
		}
	}
}

// DynamicUDPProxy manages multiple UDP listeners, one per tunnel.
type DynamicUDPProxy struct {
	server  *tunnel.Server
	proxies map[int]*UDPProxy
}

func NewDynamicUDPProxy(server *tunnel.Server) *DynamicUDPProxy {
	return &DynamicUDPProxy{
		server:  server,
		proxies: make(map[int]*UDPProxy),
	}
}

func (d *DynamicUDPProxy) StartForTunnel(entry *tunnel.TunnelEntry) error {
	if entry.Type != tunnel.TunnelTypeUDP {
		return nil
	}

	if _, exists := d.proxies[entry.PublicPort]; exists {
		return nil // already listening
	}

	proxy := NewUDPProxy(d.server, entry.PublicPort)
	if err := proxy.Start(); err != nil {
		return fmt.Errorf("start udp proxy for port %d: %w", entry.PublicPort, err)
	}

	d.proxies[entry.PublicPort] = proxy
	log.Infof("UDP proxy started for %s on port %d", entry.Subdomain, entry.PublicPort)
	return nil
}

func (d *DynamicUDPProxy) StopForTunnel(entry *tunnel.TunnelEntry) {
	if entry.Type != tunnel.TunnelTypeUDP {
		return
	}

	proxy, exists := d.proxies[entry.PublicPort]
	if !exists {
		return
	}

	proxy.Stop()
	delete(d.proxies, entry.PublicPort)
	log.Infof("UDP proxy stopped for %s on port %d", entry.Subdomain, entry.PublicPort)
}

func (d *DynamicUDPProxy) StopAll() {
	for port, proxy := range d.proxies {
		proxy.Stop()
		log.Infof("UDP proxy stopped on port %d", port)
	}
}

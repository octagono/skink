package proxy

import (
	"fmt"
	"net"

	"github.com/octagono/skink/src/tunnel"
	log "github.com/schollz/logger"
)

// TCPProxy handles incoming raw TCP connections from the public internet
// and forwards them through the appropriate tunnel.
type TCPProxy struct {
	server   *tunnel.Server
	listener net.Listener
	port     int
	quit     chan struct{}
}

func NewTCPProxy(server *tunnel.Server, port int) *TCPProxy {
	return &TCPProxy{
		server: server,
		port:   port,
		quit:   make(chan struct{}),
	}
}

func (p *TCPProxy) Start() error {
	addr := fmt.Sprintf(":%d", p.port)
	var err error
	p.listener, err = net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("tcp proxy listen on %s: %w", addr, err)
	}

	log.Infof("TCP proxy listening on %s", addr)

	go func() {
		for {
			conn, err := p.listener.Accept()
			if err != nil {
				select {
				case <-p.quit:
					return
				default:
					log.Debugf("tcp proxy accept: %v", err)
					continue
				}
			}

			go p.handleConnection(conn)
		}
	}()

	return nil
}

func (p *TCPProxy) Stop() {
	close(p.quit)
	if p.listener != nil {
		p.listener.Close()
	}
}

// handleConnection handles an incoming TCP connection.
// Since TCP tunnels don't have subdomain-based routing, we need to know which tunnel
// this connection belongs to. We determine this by looking up which tunnel owns this port.
func (p *TCPProxy) handleConnection(conn net.Conn) {
	defer conn.Close()

	// Find all TCP tunnels and see which one owns our port
	var entry *tunnel.TunnelEntry
	for _, e := range p.server.Registry().List() {
		if e.Type == tunnel.TunnelTypeTCP && e.PublicPort == p.port {
			entry = e
			break
		}
	}

	if entry == nil {
		log.Debugf("no TCP tunnel for port %d", p.port)
		return
	}

	log.Debugf("proxy routing TCP connection to tunnel %s", entry.Subdomain)

	// If the entry has a custom DataHandler (e.g. SSH gateway), use it
	if entry.DataHandler != nil {
		if err := entry.DataHandler(conn); err != nil {
			log.Errorf("data handler for tunnel %s: %v", entry.Subdomain, err)
		}
		return
	}

	// Request proxy connection from tunnel client
	proxyConn, err := p.server.RequestProxy(entry.ID, conn.RemoteAddr().String())
	if err != nil {
		log.Errorf("request proxy for tunnel %s: %v", entry.Subdomain, err)
		return
	}
	defer proxyConn.Close()

	// Pipe the connections
	PipeConnections(conn, proxyConn)
}

// DynamicTCPProxy manages multiple TCP listeners, one per tunnel.
type DynamicTCPProxy struct {
	server  *tunnel.Server
	proxies map[int]*TCPProxy
}

func NewDynamicTCPProxy(server *tunnel.Server) *DynamicTCPProxy {
	return &DynamicTCPProxy{
		server:  server,
		proxies: make(map[int]*TCPProxy),
	}
}

func (d *DynamicTCPProxy) StartForTunnel(entry *tunnel.TunnelEntry) error {
	if entry.Type != tunnel.TunnelTypeTCP {
		return nil
	}

	if _, exists := d.proxies[entry.PublicPort]; exists {
		return nil // already listening
	}

	proxy := NewTCPProxy(d.server, entry.PublicPort)
	if err := proxy.Start(); err != nil {
		return fmt.Errorf("start proxy for port %d: %w", entry.PublicPort, err)
	}

	d.proxies[entry.PublicPort] = proxy
	log.Infof("TCP proxy started for %s on port %d", entry.Subdomain, entry.PublicPort)
	return nil
}

func (d *DynamicTCPProxy) StopForTunnel(entry *tunnel.TunnelEntry) {
	if entry.Type != tunnel.TunnelTypeTCP {
		return
	}

	proxy, exists := d.proxies[entry.PublicPort]
	if !exists {
		return
	}

	proxy.Stop()
	delete(d.proxies, entry.PublicPort)
	log.Infof("proxy stopped for %s on port %d", entry.Subdomain, entry.PublicPort)
}

func (d *DynamicTCPProxy) StopAll() {
	for port, proxy := range d.proxies {
		proxy.Stop()
		log.Infof("TCP proxy stopped on port %d", port)
	}
}

package proxy

import (
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// bufferSize is the optimal buffer size for io.Copy in proxy pipes.
// Matches Go stdlib's net/http internal buffer and traefik's choice.
const bufferSize = 32 * 1024

// bufPool is a shared sync.Pool of 32KB buffers for io.CopyBuffer.
// Pooling *[]byte (pointer) avoids slice-header escape per Go vet guidance.
var bufPool = sync.Pool{
	New: func() interface{} {
		buf := make([]byte, bufferSize)
		return &buf
	},
}

func getBuffer() []byte {
	return *bufPool.Get().(*[]byte)
}

// putBuffer returns a buffer to the pool. Buffers of the wrong size are discarded.
func putBuffer(buf []byte) {
	if cap(buf) != bufferSize {
		return // discard mismatched-capacity buffers (size drift protection)
	}
	b := buf[:bufferSize]
	bufPool.Put(&b)
}

// PipeConnections copies data bidirectionally between two connections
// using pooled 32KB buffers. Returns total bytes transferred in each direction.
// Ownership of both connections is transferred — both are closed when piping completes.
func PipeConnections(conn1, conn2 net.Conn) (int64, int64, error) {
	// Apply TCP optimizations (P2 perf)
	applyTCPOptions(conn1)
	applyTCPOptions(conn2)

	var wg sync.WaitGroup
	var bytes1, bytes2 int64
	var errOnce sync.Once
	var pipeErr error

	wg.Add(2)

	go func() {
		defer wg.Done()
		buf := getBuffer()
		defer putBuffer(buf)
		n, err := io.CopyBuffer(conn1, conn2, buf)
		bytes1 = n
		if err != nil {
			errOnce.Do(func() { pipeErr = fmt.Errorf("pipe conn1→conn2: %w", err) })
		}
		// Half-close to propagate EOF cleanly (tun2socks pattern)
		if cw, ok := conn1.(interface{ CloseWrite() error }); ok {
			cw.CloseWrite()
		}
		conn1.Close()
		conn2.Close()
	}()

	go func() {
		defer wg.Done()
		buf := getBuffer()
		defer putBuffer(buf)
		n, err := io.CopyBuffer(conn2, conn1, buf)
		bytes2 = n
		if err != nil {
			errOnce.Do(func() { pipeErr = fmt.Errorf("pipe conn2→conn1: %w", err) })
		}
		if cw, ok := conn2.(interface{ CloseWrite() error }); ok {
			cw.CloseWrite()
		}
		conn1.Close()
		conn2.Close()
	}()

	wg.Wait()

	return bytes1, bytes2, pipeErr
}

// applyTCPOptions sets TCP_NODELAY and keepalive on a connection if it's a *net.TCPConn.
// This eliminates Nagle's 40ms coalescing delay and detects dead peers.
func applyTCPOptions(conn net.Conn) {
	if tcp, ok := conn.(*net.TCPConn); ok {
		_ = tcp.SetNoDelay(true)   // disable Nagle for low-latency tunnels
		_ = tcp.SetKeepAlive(true) // detect dead peers
		_ = tcp.SetKeepAlivePeriod(30 * time.Second)
	}
}

// SetSocketBufferers tunes the kernel socket buffers for high-throughput proxying.
func SetSocketBufferers(conn net.Conn, read, write int) error {
	if tcp, ok := conn.(*net.TCPConn); ok {
		if read > 0 {
			if err := tcp.SetReadBuffer(read); err != nil {
				return err
			}
		}
		if write > 0 {
			if err := tcp.SetWriteBuffer(write); err != nil {
				return err
			}
		}
	}
	return nil
}

// ProxyConn wraps a net.Conn with metadata about the proxy session.
type ProxyConn struct {
	net.Conn
	ID        string
	TunnelID  string
	CreatedAt time.Time
}

func NewProxyConn(conn net.Conn, id, tunnelID string) *ProxyConn {
	return &ProxyConn{
		Conn:      conn,
		ID:        id,
		TunnelID:  tunnelID,
		CreatedAt: time.Now(),
	}
}

// ConnPool maintains a pool of reusable proxy connections.
type ConnPool struct {
	mu      sync.Mutex
	pool    []*ProxyConn
	maxSize int
}

func NewConnPool(maxSize int) *ConnPool {
	return &ConnPool{
		pool:    make([]*ProxyConn, 0, maxSize),
		maxSize: maxSize,
	}
}

// Put adds a connection back to the pool.
func (p *ConnPool) Put(conn *ProxyConn) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if len(p.pool) < p.maxSize {
		p.pool = append(p.pool, conn)
	} else {
		conn.Close()
	}
}

// Get retrieves a connection from the pool, or nil if empty.
func (p *ConnPool) Get() *ProxyConn {
	p.mu.Lock()
	defer p.mu.Unlock()

	if len(p.pool) == 0 {
		return nil
	}

	conn := p.pool[len(p.pool)-1]
	p.pool = p.pool[:len(p.pool)-1]
	return conn
}

func (p *ConnPool) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()

	for _, conn := range p.pool {
		conn.Close()
	}
	p.pool = p.pool[:0]
}

func (p *ConnPool) Size() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.pool)
}

// AuthHandler handles tunnel-level authentication.
type AuthHandler struct {
	password string
}

func NewAuthHandler(password string) *AuthHandler {
	return &AuthHandler{password: password}
}

// Authenticate checks if the given password matches.
func (a *AuthHandler) Authenticate(password string) bool {
	if a.password == "" {
		return true
	}
	return a.password == password
}

// RateLimiter is a per-IP token bucket rate limiter using golang.org/x/time/rate.
// Entries are evicted after not being seen for TTL duration to prevent unbounded
// memory growth from spoofed source IPs.
type RateLimiter struct {
	mu       sync.Mutex
	limiters map[string]*rateEntry
	r        rate.Limit
	burst    int
	ttl      time.Duration
	stopCh   chan struct{}
}

type rateEntry struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

// NewRateLimiter creates a new per-IP rate limiter.
// r is requests/sec; burst is the max burst size.
// The TTL controls how long an idle IP's limiter is retained.
func NewRateLimiter(r rate.Limit, burst int, ttl time.Duration) *RateLimiter {
	rl := &RateLimiter{
		limiters: make(map[string]*rateEntry),
		r:        r,
		burst:    burst,
		ttl:      ttl,
		stopCh:   make(chan struct{}),
	}
	// Background cleanup goroutine to evict stale entries
	go rl.cleanupLoop()
	return rl
}

// NewSimpleRateLimiter creates a rate limiter with sensible defaults.
// 100 req/sec, burst 200, 10 minute idle TTL.
func NewSimpleRateLimiter() *RateLimiter {
	return NewRateLimiter(rate.Limit(100), 200, 10*time.Minute)
}

// Allow checks if a request from the given IP is allowed.
func (r *RateLimiter) Allow(ip string) bool {
	r.mu.Lock()
	e, exists := r.limiters[ip]
	if !exists {
		e = &rateEntry{
			limiter:  rate.NewLimiter(r.r, r.burst),
			lastSeen: time.Now(),
		}
		r.limiters[ip] = e
	}
	e.lastSeen = time.Now()
	r.mu.Unlock()

	return e.limiter.Allow()
}

// Wait blocks until a request from the given IP is allowed or ctx is canceled.
func (r *RateLimiter) Wait(ctx context.Context, ip string) error {
	r.mu.Lock()
	e, exists := r.limiters[ip]
	if !exists {
		e = &rateEntry{
			limiter:  rate.NewLimiter(r.r, r.burst),
			lastSeen: time.Now(),
		}
		r.limiters[ip] = e
	}
	e.lastSeen = time.Now()
	r.mu.Unlock()

	return e.limiter.Wait(ctx)
}

// cleanupLoop periodically evicts stale rate limiter entries.
func (r *RateLimiter) cleanupLoop() {
	ticker := time.NewTicker(r.ttl / 2)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			r.evictStale()
		case <-r.stopCh:
			return
		}
	}
}

// evictStale removes entries not seen within the TTL window.
func (r *RateLimiter) evictStale() {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	for ip, entry := range r.limiters {
		if now.Sub(entry.lastSeen) > r.ttl {
			delete(r.limiters, ip)
		}
	}
}

// Stop halts the cleanup goroutine.
func (r *RateLimiter) Stop() {
	close(r.stopCh)
}

// IPAllowlist is a CIDR-based IP allowlist/denylist using net.IPNet.Contains.
type IPAllowlist struct {
	nets []*net.IPNet
	ips  map[string]struct{} // single-IP fast path
}

// NewIPAllowlist parses a list of CIDR strings (or bare IPs which become /32 or /128).
// Returns an allowlist that matches any of the entries.
func NewIPAllowlist(specs []string) (*IPAllowlist, error) {
	a := &IPAllowlist{ips: make(map[string]struct{})}
	for _, s := range specs {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		// Bare IP → convert to CIDR
		if !strings.Contains(s, "/") {
			if ip := net.ParseIP(s); ip != nil {
				if ip.To4() != nil {
					s += "/32"
				} else {
					s += "/128"
				}
				a.ips[ip.String()] = struct{}{}
			}
		}
		_, n, err := net.ParseCIDR(s)
		if err != nil {
			return nil, fmt.Errorf("parse %q: %w", s, err)
		}
		a.nets = append(a.nets, n)
	}
	return a, nil
}

// Allow returns true if the IP is allowed (matches the allowlist).
// An empty allowlist allows everything.
func (a *IPAllowlist) Allow(ip net.IP) bool {
	if a == nil || (len(a.ips) == 0 && len(a.nets) == 0) {
		return true
	}
	if ip == nil {
		return false
	}
	// Fast path for single IPs
	if _, ok := a.ips[ip.String()]; ok {
		return true
	}
	// CIDR match
	for _, n := range a.nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func (a *IPAllowlist) Count() int {
	return len(a.ips) + len(a.nets)
}

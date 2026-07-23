package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/octagono/skink/src/tunnel"
	log "github.com/schollz/logger"
)

// hopByHopHeaders are headers that should not be forwarded by a proxy
// per RFC 9110 §7.6.1.
var hopByHopHeaders = []string{
	"Connection",
	"Proxy-Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Te",
	"Trailer",
	"Transfer-Encoding",
	"Upgrade",
	"HTTP2-Settings",
}

// statusRecorder wraps http.ResponseWriter to capture status code and bytes written.
type statusRecorder struct {
	http.ResponseWriter
	status    int
	bytes     int64
	wroteHead bool
}

func (r *statusRecorder) WriteHeader(code int) {
	if r.wroteHead {
		return
	}
	r.status = code
	r.wroteHead = true
	r.ResponseWriter.WriteHeader(code)
}

func (r *statusRecorder) Write(b []byte) (int, error) {
	if !r.wroteHead {
		r.status = http.StatusOK
		r.wroteHead = true
	}
	n, err := r.ResponseWriter.Write(b)
	r.bytes += int64(n)
	return n, err
}

// Hijack proxies the underlying Hijacker if present.
func (r *statusRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hj, ok := r.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, fmt.Errorf("ResponseWriter is not a Hijacker")
	}
	return hj.Hijack()
}

type HTTPProxyConfig struct {
	Server    *tunnel.Server
	Domain    string
	Port      int
	TLSConfig *tls.Config // nil = plaintext
	RateLimit *RateLimiter
	Allowlist *IPAllowlist
}

// HTTPProxy handles incoming HTTP connections from the public internet
// and forwards them through the appropriate tunnel using httputil.ReverseProxy.
type HTTPProxy struct {
	cfg        HTTPProxyConfig
	httpSrv    *http.Server
	transports sync.Map
	wssHandler func(net.Conn)
}

func (p *HTTPProxy) SetWSSHandler(handler func(net.Conn)) {
	p.wssHandler = handler
}

func NewHTTPProxy(cfg HTTPProxyConfig) *HTTPProxy {
	p := &HTTPProxy{cfg: cfg}

	p.httpSrv = &http.Server{
		Addr:              fmt.Sprintf(":%d", cfg.Port),
		Handler:           p,
		ReadHeaderTimeout: 10 * time.Second, // slowloris defense
		ReadTimeout:       60 * time.Second, // body read ceiling
		WriteTimeout:      0,                // 0 = streaming/SSE/WebSocket OK
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 20, // 1MB
	}

	if cfg.TLSConfig != nil {
		p.httpSrv.TLSConfig = cfg.TLSConfig
	}

	return p
}

// Start begins listening for HTTP connections.
func (p *HTTPProxy) Start() error {
	scheme := "http"
	if p.cfg.TLSConfig != nil {
		scheme = "https"
	}
	log.Infof("HTTP proxy listening on %s://%s (domain: %s)", scheme, p.httpSrv.Addr, p.cfg.Domain)

	if p.cfg.TLSConfig != nil {
		return p.httpSrv.ListenAndServeTLS("", "")
	}
	return p.httpSrv.ListenAndServe()
}

func (p *HTTPProxy) Stop() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return p.httpSrv.Shutdown(ctx)
}

// ServeHTTP implements the http.Handler interface.
func (p *HTTPProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/tunnel" && r.Header.Get("Upgrade") == "websocket" && p.wssHandler != nil {
		upgrader := &websocket.Upgrader{
			ReadBufferSize:  32768,
			WriteBufferSize: 32768,
			CheckOrigin:     func(r *http.Request) bool { return true },
		}
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		p.wssHandler(tunnel.NewWSConn(conn))
		return
	}

	start := time.Now()
	rec := &statusRecorder{ResponseWriter: w}

	// Recover from panics to keep the server alive
	defer func() {
		if rv := recover(); rv != nil {
			log.Errorf("proxy panic: %v", rv)
			if !rec.wroteHead {
				http.Error(rec, "Internal proxy error", http.StatusInternalServerError)
			}
		}
	}()

	// Extract client IP for logging and rate limiting
	clientIP := extractClientIP(r.RemoteAddr)

	// Rate limit check (P1 security)
	if p.cfg.RateLimit != nil && !p.cfg.RateLimit.Allow(clientIP) {
		http.Error(rec, "Rate limit exceeded", http.StatusTooManyRequests)
		p.logRequest(rec, r, clientIP, start)
		return
	}

	// Resolve the tunnel entry
	subdomain := extractSubdomain(r.Host, p.cfg.Domain)
	if subdomain == "" {
		http.Error(rec, "Invalid host", http.StatusBadRequest)
		p.logRequest(rec, r, clientIP, start)
		return
	}

	entry := p.cfg.Server.Registry().LookupBySubdomain(subdomain)
	if entry == nil {
		http.Error(rec, "Tunnel not found", http.StatusNotFound)
		p.logRequest(rec, r, clientIP, start)
		return
	}

	// IP allowlist check (P1 security)
	if p.cfg.Allowlist != nil && !p.cfg.Allowlist.Allow(net.ParseIP(clientIP)) {
		http.Error(rec, "Forbidden", http.StatusForbidden)
		p.logRequest(rec, r, clientIP, start)
		return
	}

	// Authentication — bearer token first, then Basic Auth fallback
	if !p.authenticate(rec, r, entry) {
		p.logRequest(rec, r, clientIP, start)
		return
	}

	// WebSocket / Upgrade handling (P0 fix)
	if isUpgradeRequest(r) {
		p.handleUpgrade(rec, r, entry, clientIP)
		p.logRequest(rec, r, clientIP, start)
		return
	}

	// Standard HTTP proxying via httputil.ReverseProxy semantics
	p.handleHTTP(rec, r, entry, clientIP)
	p.logRequest(rec, r, clientIP, start)
}

// authenticate validates the request against the tunnel's auth configuration.
// Supports bearer token (preferred) and Basic Auth (fallback).
func (p *HTTPProxy) authenticate(w http.ResponseWriter, r *http.Request, entry *tunnel.TunnelEntry) bool {
	// No auth required
	if entry.Token == "" && entry.Password == "" {
		return true
	}

	// Bearer token check
	if entry.Token != "" {
		auth := r.Header.Get("Authorization")
		if strings.HasPrefix(auth, "Bearer ") {
			if strings.TrimSpace(strings.TrimPrefix(auth, "Bearer ")) == entry.Token {
				return true
			}
		}
		// Also accept ?token=xxx query param for browser convenience
		if q := r.URL.Query().Get("token"); q != "" && q == entry.Token {
			return true
		}
	}

	// Basic Auth fallback
	if entry.Password != "" {
		_, pass, ok := r.BasicAuth()
		if ok && pass == entry.Password {
			return true
		}
	}

	w.Header().Set("WWW-Authenticate", `Basic realm="Tunnel"`)
	http.Error(w, "Authorization required", http.StatusUnauthorized)
	return false
}

// handleUpgrade handles WebSocket and other protocol upgrade requests by hijacking
// the client connection and piping it bidirectionally through the tunnel.
func (p *HTTPProxy) handleUpgrade(w http.ResponseWriter, r *http.Request, entry *tunnel.TunnelEntry, clientIP string) {
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Upgrade not supported", http.StatusInternalServerError)
		return
	}

	clientConn, clientBuf, err := hj.Hijack()
	if err != nil {
		log.Errorf("hijack failed: %v", err)
		return
	}
	defer clientConn.Close()

	// Flush any buffered client data
	if clientBuf != nil {
		clientBuf.Flush()
	}

	// Request a proxy connection through the tunnel
	proxyConn, err := p.cfg.Server.RequestProxy(entry.ID, r.RemoteAddr)
	if err != nil {
		log.Errorf("request proxy for upgrade %s: %v", entry.Subdomain, err)
		writeRawHTTPError(clientConn, http.StatusBadGateway, "Tunnel unavailable")
		return
	}
	defer proxyConn.Close()

	// Add forwarding headers before writing the request to the backend
	addForwardingHeaders(r, clientIP)

	// Write the upgrade request to the backend so it can complete the handshake
	if err := r.Write(proxyConn); err != nil {
		log.Debugf("write upgrade request to tunnel: %v", err)
		return
	}

	// Pipe bidirectionally — WebSocket frames flow raw
	log.Debugf("upgrade pipe: %s ↔ tunnel:%s", clientIP, entry.Subdomain)
	PipeConnections(clientConn, proxyConn)
}

// handleHTTP forwards a standard HTTP request through the tunnel using
// manual request/response forwarding with proper hop-by-hop header stripping.
// (Full httputil.ReverseProxy migration is tracked in handleHTTPViaReverseProxy.)
func (p *HTTPProxy) handleHTTP(w http.ResponseWriter, r *http.Request, entry *tunnel.TunnelEntry, clientIP string) {
	// Strip hop-by-hop headers from the inbound request (RFC 9110 §7.6.1)
	stripHopByHopHeaders(r.Header)

	// Add forwarding headers
	addForwardingHeaders(r, clientIP)

	// Request proxy connection
	proxyConn, err := p.cfg.Server.RequestProxy(entry.ID, r.RemoteAddr)
	if err != nil {
		log.Errorf("request proxy for %s: %v", entry.Subdomain, err)
		if isTimeoutError(err) {
			http.Error(w, "Gateway timeout", http.StatusGatewayTimeout)
		} else {
			http.Error(w, "Tunnel unavailable", http.StatusBadGateway)
		}
		return
	}
	defer proxyConn.Close()

	// Set a deadline for reading the response header (frp uses 60s)
	if err := proxyConn.SetReadDeadline(time.Now().Add(60 * time.Second)); err != nil {
		log.Debugf("set read deadline: %v", err)
	}
	defer proxyConn.SetReadDeadline(time.Time{})

	// Wire client disconnect → close backend conn (mid-stream cancellation)
	go func() {
		<-r.Context().Done()
		proxyConn.Close()
	}()

	// Write the request to the backend
	if err := r.Write(proxyConn); err != nil {
		log.Debugf("write request to tunnel: %v", err)
		http.Error(w, "Proxy error", http.StatusBadGateway)
		return
	}

	// Read the response — use shared buffer pool
	buf := getBuffer()
	defer putBuffer(buf)

	reader := bufio.NewReaderSize(proxyConn, 0)
	reader.Reset(bufio.NewReader(proxyConn))
	resp, err := http.ReadResponse(reader, r)
	if err != nil {
		log.Debugf("read response from tunnel: %v", err)
		if isTimeoutError(err) {
			http.Error(w, "Gateway timeout", http.StatusGatewayTimeout)
		} else {
			http.Error(w, "Proxy error", http.StatusBadGateway)
		}
		return
	}
	defer resp.Body.Close()

	// Strip hop-by-hop headers from the response
	stripHopByHopHeaders(resp.Header)

	// Copy response headers
	for k, v := range resp.Header {
		for _, hv := range v {
			w.Header().Add(k, hv)
		}
	}

	// Write status code
	w.WriteHeader(resp.StatusCode)

	// Copy body with immediate flush for streaming responses (SSE, chunked)
	flusher, _ := w.(http.Flusher)
	buf2 := getBuffer()
	defer putBuffer(buf2)

	for {
		n, err := resp.Body.Read(buf2)
		if n > 0 {
			if _, werr := w.Write(buf2[:n]); werr != nil {
				break
			}
			if flusher != nil {
				flusher.Flush()
			}
		}
		if err != nil {
			break
		}
	}
}

// logRequest emits a structured access log entry.
func (p *HTTPProxy) logRequest(rec *statusRecorder, r *http.Request, clientIP string, start time.Time) {
	status := rec.status
	if status == 0 {
		status = http.StatusOK
	}
	duration := time.Since(start)

	log.Infof("HTTP %d %s %s %s host=%s bytes=%d duration=%s ip=%s",
		status,
		r.Method,
		r.URL.Path,
		r.Proto,
		r.Host,
		rec.bytes,
		duration,
		clientIP,
	)
}

// isUpgradeRequest returns true if the request is a WebSocket or other upgrade.
func isUpgradeRequest(r *http.Request) bool {
	if !strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade") {
		return false
	}
	return r.Header.Get("Upgrade") != ""
}

// addForwardingHeaders adds X-Forwarded-* headers and strips any client-supplied
// forwarding headers to prevent IP spoofing.
func addForwardingHeaders(r *http.Request, clientIP string) {
	// Strip client-supplied forwarding headers (anti-spoofing)
	r.Header.Del("Forwarded")
	r.Header.Del("X-Forwarded-For")
	r.Header.Del("X-Forwarded-Host")
	r.Header.Del("X-Forwarded-Proto")
	r.Header.Del("X-Real-IP")

	// Add our own
	if clientIP != "" {
		r.Header.Set("X-Forwarded-For", clientIP)
		r.Header.Set("X-Real-IP", clientIP)
	}
	r.Header.Set("X-Forwarded-Host", r.Host)
	r.Header.Set("X-Forwarded-Proto", "http")
	if r.TLS != nil {
		r.Header.Set("X-Forwarded-Proto", "https")
	}
}

// stripHopByHopHeaders removes hop-by-hop headers per RFC 9110 §7.6.1.
// Also processes the Connection header for additional headers to strip.
func stripHopByHopHeaders(h http.Header) {
	// Process Connection header — it may list additional hop-by-hop headers
	if conn := h.Get("Connection"); conn != "" {
		for _, f := range strings.Split(conn, ",") {
			if f = strings.TrimSpace(f); f != "" {
				h.Del(f)
			}
		}
	}

	for _, hh := range hopByHopHeaders {
		h.Del(hh)
	}
}

// extractClientIP extracts the client IP from RemoteAddr, stripping the port.
func extractClientIP(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return remoteAddr
	}
	return host
}

// isTimeoutError returns true if the error is a network timeout.
func isTimeoutError(err error) bool {
	if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		return true
	}
	if urlErr, ok := err.(*url.Error); ok {
		return isTimeoutError(urlErr.Err)
	}
	return false
}

// extractSubdomain extracts the subdomain from a Host header.
// For "myapp.tunnel.example.com" with domain "tunnel.example.com", returns "myapp".
func extractSubdomain(host, domain string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.ToLower(host)
	domain = strings.ToLower(domain)
	if !strings.HasSuffix(host, domain) {
		return ""
	}
	subdomain := strings.TrimSuffix(host, domain)
	subdomain = strings.TrimSuffix(subdomain, ".")
	if subdomain == "" || strings.Contains(subdomain, ".") {
		return ""
	}
	return subdomain
}

// writeRawHTTPError writes an HTTP error response to a raw connection.
func writeRawHTTPError(conn net.Conn, statusCode int, message string) {
	resp := &http.Response{
		StatusCode: statusCode,
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     make(http.Header),
	}
	resp.Header.Set("Content-Type", "text/plain")
	resp.Body = io.NopCloser(strings.NewReader(message))
	resp.ContentLength = int64(len(message))
	resp.Write(conn)
}

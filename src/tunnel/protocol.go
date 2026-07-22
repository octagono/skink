package tunnel

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/octagono/skink/src/comm"
	"github.com/octagono/skink/src/compress"
	"github.com/octagono/skink/src/crypt"
	"github.com/octagono/skink/src/message"
	log "github.com/schollz/logger"
)

// TunnelType represents the protocol being tunneled.
type TunnelType string

const (
	TunnelTypeHTTP   TunnelType = "http"
	TunnelTypeTCP    TunnelType = "tcp"
	TunnelTypeUDP    TunnelType = "udp"
	TunnelTypeSOCKS5 TunnelType = "socks5" // SOCKS5 proxy (forward proxy through relay)
)

// TunnelRegistration is sent by the client to register a new tunnel.
type TunnelRegistration struct {
	Subdomain string     `json:"subdomain"`
	LocalAddr string     `json:"local_addr"`
	Type      TunnelType `json:"type"`
	Password  string     `json:"password,omitempty"`
	Token     string     `json:"token,omitempty"`   // bearer token for auth (alternative to password)
	Private   bool       `json:"private,omitempty"` // private mode: no public port, access by token only
}

// TunnelInfo is returned by the server on successful registration.
type TunnelInfo struct {
	TunnelID   string `json:"tunnel_id"`
	PublicURL  string `json:"public_url"`
	Subdomain  string `json:"subdomain"`
	AssignedAt string `json:"assigned_at"`
	Token      string `json:"token,omitempty"` // server-assigned token if client didn't provide one
	// For TCP tunnels, the remote address to connect to
	RemoteAddr string `json:"remote_addr,omitempty"`
	// Assigned public port for TCP tunnels
	PublicPort int `json:"public_port,omitempty"`
	// AccessToken for private tunnels (no public port — access by token only)
	AccessToken string `json:"access_token,omitempty"`
}

// ReqProxyMessage is sent by the server to request a new proxy connection.
type ReqProxyMessage struct {
	TunnelID   string `json:"tunnel_id"`
	ClientAddr string `json:"client_addr"`
	ProxyID    string `json:"proxy_id"`
	DataAddr   string `json:"data_addr,omitempty"` // data port address for proxy connection
}

// ProxyConnectedMessage is sent by the client after establishing a proxy connection.
type ProxyConnectedMessage struct {
	TunnelID string `json:"tunnel_id"`
	ProxyID  string `json:"proxy_id"`
}

// HeartbeatMessage is sent periodically to keep the tunnel alive.
type HeartbeatMessage struct {
	Timestamp int64 `json:"ts"`
}

// TunnelCloseMessage signals tunnel teardown.
type TunnelCloseMessage struct {
	TunnelID string `json:"tunnel_id"`
	Reason   string `json:"reason"`
}

// TunnelErrorMessage carries error information.
type TunnelErrorMessage struct {
	Message string `json:"message"`
	Code    int    `json:"code"`
}

// AccessRequest is sent by an access client to request a private tunnel connection.
type AccessRequest struct {
	Token      string `json:"token"`
	TargetAddr string `json:"target_addr,omitempty"` // optional specific target
	TunnelID   string `json:"tunnel_id,omitempty"`   // optional tunnel ID
}

// AccessGranted is returned when a private tunnel access request succeeds.
type AccessGranted struct {
	TunnelID string `json:"tunnel_id"`
	AgentID  string `json:"agent_id,omitempty"`
}

// ExecRequest is sent by the client to execute a command on the target.
// Sent over a forward yamux stream with the "EXEC|" prefix.
type ExecRequest struct {
	Command string   `json:"command"`
	Args    []string `json:"args,omitempty"`
	Stdin   string   `json:"stdin,omitempty"`   // for push operations
	Timeout int      `json:"timeout,omitempty"` // seconds
}

// ExecResponse is returned by the server after executing a command.
type ExecResponse struct {
	Stdout   string `json:"stdout"`
	Stderr   string `json:"stderr"`
	ExitCode int    `json:"exit_code"`
	Error    string `json:"error,omitempty"`
}

// RouteRule checks if a destination address matches a set of CIDR routes.
type RouteRule struct {
	routes    []*net.IPNet
	bypass    []*net.IPNet
	hasRoutes bool
}

// NewRouteRule creates a RouteRule from CIDR strings.
// routeCIDRs: traffic to these goes through tunnel
// bypassCIDRs: traffic to these goes directly (never tunnel)
func NewRouteRule(routeCIDRs, bypassCIDRs []string) (*RouteRule, error) {
	r := &RouteRule{}

	for _, cidr := range routeCIDRs {
		cidr = strings.TrimSpace(cidr)
		if cidr == "" {
			continue
		}
		if !strings.Contains(cidr, "/") {
			cidr += "/32"
		}
		_, net, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, fmt.Errorf("parse route %q: %w", cidr, err)
		}
		r.routes = append(r.routes, net)
	}

	for _, cidr := range bypassCIDRs {
		cidr = strings.TrimSpace(cidr)
		if cidr == "" {
			continue
		}
		if !strings.Contains(cidr, "/") {
			cidr += "/32"
		}
		_, net, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, fmt.Errorf("parse bypass %q: %w", cidr, err)
		}
		r.bypass = append(r.bypass, net)
	}

	r.hasRoutes = len(r.routes) > 0
	return r, nil
}

// Route returns true if the given host:port should go through the tunnel.
// If no routes are configured, everything routes through the tunnel (default).
func (r *RouteRule) Route(hostPort string) bool {
	if !r.hasRoutes {
		return true // no routes = route everything
	}

	host, _, err := net.SplitHostPort(hostPort)
	if err != nil {
		host = hostPort
	}

	ip := net.ParseIP(host)
	if ip == nil {
		// Try DNS resolution for domain names
		return r.hasRoutes // route domain names if routes are configured
	}

	// Check bypass first
	for _, b := range r.bypass {
		if b.Contains(ip) {
			return false
		}
	}

	// Check routes
	for _, route := range r.routes {
		if route.Contains(ip) {
			return true
		}
	}

	return false
}

// HeartbeatConfig controls heartbeat timing and jitter for stealth.
type HeartbeatConfig struct {
	// Interval between heartbeats (default: 30s)
	Interval time.Duration
	// Jitter is the percentage of random jitter applied to the interval (0.0 - 1.0)
	// e.g., 0.4 means ±40% random jitter. Disables beaconing detection.
	Jitter float64
}

// DefaultHeartbeatConfig returns a default heartbeat config.
func DefaultHeartbeatConfig() HeartbeatConfig {
	return HeartbeatConfig{
		Interval: DefaultHeartbeatInterval,
		Jitter:   0.2, // ±20%
	}
}

// NextInterval returns the next heartbeat interval with jitter applied.
func (h HeartbeatConfig) NextInterval() time.Duration {
	if h.Jitter <= 0 {
		return h.Interval
	}
	// Apply random jitter: interval ± interval*jitter
	jitter := time.Duration(float64(h.Interval) * h.Jitter)
	// Use a simple pseudo-random offset
	offset := time.Duration(0)
	if h.Jitter > 0 {
		n := time.Now().UnixNano()
		offset = time.Duration(int64(jitter) * (2*int64(n%1000) - 1000) / 1000)
		if offset < 0 {
			offset = -offset
		}
		if n%2 == 0 {
			offset = -offset
		}
	}
	next := h.Interval + offset
	if next < time.Second {
		next = time.Second
	}
	return next
}

// TLSConfig holds TLS wrapping configuration for the control channel.
type TLSConfig struct {
	// Enable wraps the control connection in TLS.
	Enable bool
	// InsecureSkipVerify skips server certificate verification (for self-signed certs).
	InsecureSkipVerify bool
	// CertFile and KeyFile for client-side TLS (mutual TLS).
	CertFile string
	KeyFile  string
	// CAFile for custom CA certificates.
	CAFile string
}

// Config holds tunnel client configuration.
type Config struct {
	ServerAddr  string
	ServerPass  string
	Subdomain   string
	LocalAddr   string
	TunnelType  TunnelType
	Password    string
	Token       string // bearer token for HTTP auth (alternative to password)
	RelayDomain string // public domain of the relay (for constructing URLs)
	HTTPPort    int    // public HTTP port on the relay

	// Heartbeat config for stealth (beacon jitter)
	Heartbeat HeartbeatConfig

	// TLS wrapping for control channel
	TLS TLSConfig

	// SOCKS5Proxy config for SOCKS5 tunnel mode
	SOCKS5Port int // local port for SOCKS5 listener (default: 1080)

	// Transport protocol: "tcp" (default), "wss" (WebSocket), "pipe" (named pipe)
	Transport string

	// PipeName for named pipe transport (Windows SMB lateral movement)
	PipeName string

	// Routes for split tunneling: CIDR ranges to route through the tunnel.
	// Traffic to destinations matching these routes goes through the tunnel;
	// everything else connects directly (for SOCKS5 mode).
	Routes []string

	// BypassRoutes are CIDRs that should NEVER go through the tunnel (forced direct).
	BypassRoutes []string

	// YamuxWindowSize sets the yamux stream window size in bytes.
	// Default: 16MB. Reduce to 1MB for low-memory targets.
	// Increase to 64MB for high-throughput tunnels.
	YamuxWindowSize int

	// Private tunnel access mode (no public port — access by token)
	Private     bool
	AccessToken string

	// ConfigFile path (loaded externally)
	ConfigFile string
}

// ConfigFile is a YAML-serializable configuration for the tunnel client.
type ConfigFile struct {
	Server          string   `yaml:"server"`
	Local           string   `yaml:"local"`
	Type            string   `yaml:"type"`
	Password        string   `yaml:"password,omitempty"`
	Token           string   `yaml:"token,omitempty"`
	Subdomain       string   `yaml:"subdomain,omitempty"`
	TLS             bool     `yaml:"tls,omitempty"`
	TLSSkipVerify   bool     `yaml:"tls_skip_verify,omitempty"`
	SOCKS5Port      int      `yaml:"socks5_port,omitempty"`
	Heartbeat       int      `yaml:"heartbeat_interval,omitempty"` // seconds
	HeartbeatJitter float64  `yaml:"heartbeat_jitter,omitempty"`
	Private         bool     `yaml:"private,omitempty"`
	AccessToken     string   `yaml:"access_token,omitempty"`
	Routes          []string `yaml:"routes,omitempty"`
	BypassRoutes    []string `yaml:"bypass_routes,omitempty"`
}

// TunnelState tracks the lifecycle state of a tunnel.
type TunnelState int

const (
	TunnelStateDisconnected TunnelState = iota
	TunnelStateConnecting
	TunnelStateConnected
	TunnelStateError
)

// SendTunnelMessage sends a typed tunnel message over a comm connection with optional encryption.
func SendTunnelMessage(c *comm.Comm, key []byte, msgType message.Type, payload interface{}) error {
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal tunnel message: %w", err)
	}

	msg := message.Message{
		Type:  msgType,
		Bytes: payloadBytes,
	}

	encoded, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("marshal message wrapper: %w", err)
	}

	encoded = compress.Compress(encoded)
	if key != nil {
		encoded, err = crypt.Encrypt(encoded, key)
		if err != nil {
			return fmt.Errorf("encrypt tunnel message: %w", err)
		}
	}

	log.Debugf("sending tunnel message type=%s len=%d", msgType, len(encoded))
	return c.Send(encoded)
}

// ReceiveTunnelMessage receives a tunnel message, optionally decrypting it.
// Returns the message type and raw payload bytes.
func ReceiveTunnelMessage(c *comm.Comm, key []byte) (message.Type, []byte, error) {
	data, err := c.Receive()
	if err != nil {
		return "", nil, fmt.Errorf("receive: %w", err)
	}

	if key != nil {
		data, err = crypt.Decrypt(data, key)
		if err != nil {
			return "", nil, fmt.Errorf("decrypt: %w", err)
		}
	}

	data = compress.Decompress(data)

	var msg message.Message
	if err := json.Unmarshal(data, &msg); err != nil {
		return "", nil, fmt.Errorf("unmarshal: %w", err)
	}

	return msg.Type, msg.Bytes, nil
}

// DecodePayload decodes a JSON payload into the given struct.
func DecodePayload(data []byte, v interface{}) error {
	if err := json.Unmarshal(data, v); err != nil {
		return fmt.Errorf("decode payload: %w", err)
	}
	return nil
}

// Defaults
const (
	DefaultTunnelPort        = 9090
	DefaultHTTPPort          = 8080
	DefaultHeartbeatInterval = 30 * time.Second
	DefaultHeartbeatTimeout  = 10 * time.Second
	DefaultReconnectBase     = 1 * time.Second
	DefaultReconnectMax      = 60 * time.Second
)

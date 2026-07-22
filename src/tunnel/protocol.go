package tunnel

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net"
	"regexp"
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

type TunnelRegistration struct {
	Version        int        `json:"version,omitempty"`
	Subdomain      string     `json:"subdomain"`
	LocalAddr      string     `json:"local_addr"`
	Type           TunnelType `json:"type"`
	Password       string     `json:"password,omitempty"`
	Token          string     `json:"token,omitempty"`
	Private        bool       `json:"private,omitempty"`
	MaxConns       int        `json:"max_conns,omitempty"`
	BandwidthLimit int64      `json:"bandwidth_limit,omitempty"`
	IdleTimeout    int        `json:"idle_timeout,omitempty"`
	ACLAllow       []string   `json:"acl_allow,omitempty"`
	ACLDeny        []string   `json:"acl_deny,omitempty"`
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

type TunnelResumeMessage struct {
	TunnelID string `json:"tunnel_id"`
	Token    string `json:"token"`
}

type RTTProbeMessage struct {
	SentAt int64 `json:"t"` // UnixNano when sent
}

type RekeyMessage struct {
	PublicKey []byte `json:"pk"`
}

type TunnelSyncMessage struct {
	Action    string           `json:"action"` // "register" or "unregister"
	Tunnel    *PersistedTunnel `json:"tunnel,omitempty"`
	TunnelID  string           `json:"tunnel_id,omitempty"`
	RelayAddr string           `json:"relay_addr,omitempty"`
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

type domainPattern struct {
	pattern  string
	wildcard bool
	regex    bool
	re       *regexp.Regexp
}

type RouteRule struct {
	routes        []*net.IPNet
	bypass        []*net.IPNet
	domains       []domainPattern
	bypassDomains []domainPattern
	hasRoutes     bool
}

func newDomainPattern(s string) domainPattern {
	if strings.HasPrefix(s, "re:") {
		re, err := regexp.Compile(s[3:])
		if err == nil {
			return domainPattern{pattern: s[3:], regex: true, re: re}
		}
	}
	if strings.HasPrefix(s, "*.") {
		return domainPattern{pattern: s[1:], wildcard: true}
	}
	return domainPattern{pattern: s, wildcard: false}
}

func matchDomain(host string, dp domainPattern) bool {
	if dp.regex {
		return dp.re.MatchString(host)
	}
	if dp.wildcard {
		return strings.HasSuffix(host, dp.pattern)
	}
	return host == dp.pattern
}

func NewRouteRule(routeCandidates, bypassCandidates []string) (*RouteRule, error) {
	r := &RouteRule{}

	for _, s := range routeCandidates {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if strings.HasPrefix(s, "*.") || (strings.Contains(s, ".") && !strings.Contains(s, "/")) {
			r.domains = append(r.domains, newDomainPattern(s))
			r.hasRoutes = true
			continue
		}
		if !strings.Contains(s, "/") {
			s += "/32"
		}
		_, parsed, err := net.ParseCIDR(s)
		if err != nil {
			return nil, fmt.Errorf("parse route %q: %w", s, err)
		}
		r.routes = append(r.routes, parsed)
		r.hasRoutes = true
	}

	for _, s := range bypassCandidates {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if strings.HasPrefix(s, "*.") || (strings.Contains(s, ".") && !strings.Contains(s, "/")) {
			r.bypassDomains = append(r.bypassDomains, newDomainPattern(s))
			continue
		}
		if !strings.Contains(s, "/") {
			s += "/32"
		}
		_, parsed, err := net.ParseCIDR(s)
		if err != nil {
			return nil, fmt.Errorf("parse bypass %q: %w", s, err)
		}
		r.bypass = append(r.bypass, parsed)
	}

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
		for _, bd := range r.bypassDomains {
			if matchDomain(host, bd) {
				return false
			}
		}
		for _, d := range r.domains {
			if matchDomain(host, d) {
				return true
			}
		}
		return r.hasRoutes
	}

	for _, b := range r.bypass {
		if b.Contains(ip) {
			return false
		}
	}

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

	Private     bool
	AccessToken string
	ConfigFile  string
	ResumeFile  string

	MaxConns       int
	BandwidthLimit int64
	IdleTimeout    int
	RekeyInterval  int
	AdaptiveWindow bool
	ACLAllow       []string
	ACLDeny        []string
	DNSMode        string // "remote" (default), "local", "both"
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

var (
	paddingMin int = 0
	paddingMax int = 0
)

func SetPadding(min, max int) {
	paddingMin = min
	paddingMax = max
}

func randomPadding() []byte {
	if paddingMax <= 0 || paddingMax < paddingMin {
		return nil
	}
	size := paddingMin
	if paddingMax > paddingMin {
		size += int(time.Now().UnixNano() % int64(paddingMax-paddingMin+1))
	}
	if size <= 0 {
		return nil
	}
	b := make([]byte, size)
	rand.Read(b)
	return b
}

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

	pad := randomPadding()
	if pad != nil {
		encoded = append(encoded, pad...)
	}

	if key != nil {
		encoded, err = crypt.Encrypt(encoded, key)
		if err != nil {
			return fmt.Errorf("encrypt tunnel message: %w", err)
		}
	}

	if key == nil && pad != nil {
		padLen := []byte{byte(len(pad))}
		encoded = append(padLen, encoded...)
	}

	log.Debugf("sending tunnel message type=%s len=%d pad=%d", msgType, len(encoded), len(pad))
	return c.Send(encoded)
}

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

	if key == nil && len(data) > 0 {
		padLen := int(data[0])
		if padLen > 0 && padLen < len(data) {
			data = data[1 : len(data)-padLen]
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
	CurrentProtocolVersion   = 1
	DefaultHeartbeatInterval = 30 * time.Second
	DefaultHeartbeatTimeout  = 10 * time.Second
	DefaultReconnectBase     = 1 * time.Second
	DefaultReconnectMax      = 60 * time.Second
)

package tunnel

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/octagono/skink/src/comm"
	log "github.com/schollz/logger"
)

// TunnelEntry holds all state for an active tunnel.
type TunnelEntry struct {
	ID             string
	Subdomain      string
	Type           TunnelType
	LocalAddr      string
	Password       string
	Token          string // bearer token for HTTP auth (alternative to Password)
	AccessToken    string // access token for private tunnel sharing (no public port)
	Private        bool   // private mode: no public port, access by token only
	ControlConn    *comm.Comm
	ControlKey     []byte
	CreatedAt      time.Time
	LastSeen       time.Time
	PublicPort     int
	RemoteAddr     string // assigned public TCP address for TCP tunnels
	MaxConns       int
	BandwidthLimit int64
	IdleTimeout    int
	HealthURL      string
	ACLAllow       []string
	ACLDeny        []string

	// Concurrency semaphore (initialized lazily when MaxConns > 0)
	connSem chan struct{}

	// DataHandler is an optional handler for incoming data connections.
	// If set, it is called instead of the default RequestProxy flow.
	// Used by SSH gateway to route data through SSH channels.
	DataHandler func(publicConn net.Conn) error

	// Stats (atomic updates via connStatMu)
	connStatMu    sync.Mutex
	activeConns   int64
	totalConns    int64
	totalBytesIn  int64
	totalBytesOut int64
}

// Registry manages active tunnels on the server side.
type Registry struct {
	mu        sync.RWMutex
	tunnels   map[string]*TunnelEntry // tunnelID → entry
	subdomain map[string]string       // subdomain → tunnelID

	// Access token index for private tunnels
	accessTokens map[string]string // accessToken → tunnelID

	// TTL for stale tunnels
	ttl time.Duration

	// HeartbeatStale is the duration after which a tunnel with no heartbeat
	// is considered stale and removed by CleanupHeartbeats.
	HeartbeatStale time.Duration

	// Event handler for tunnel lifecycle
	eventHandler TunnelEventHandler
}

// SetEventHandler sets a handler for tunnel lifecycle events.
func (r *Registry) SetEventHandler(h TunnelEventHandler) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.eventHandler = h
}

// NewRegistry creates a new tunnel registry.
func NewRegistry() *Registry {
	return &Registry{
		tunnels:        make(map[string]*TunnelEntry),
		subdomain:      make(map[string]string),
		accessTokens:   make(map[string]string),
		ttl:            3 * time.Hour,               // match Skink's default room TTL
		HeartbeatStale: DefaultHeartbeatTimeout * 8, // 80s for the 10s heartbeat timeout
	}
}

// Register adds a new tunnel to the registry.
// Returns an error if the subdomain is already taken.
func (r *Registry) Register(entry *TunnelEntry) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Check subdomain uniqueness
	if _, exists := r.subdomain[entry.Subdomain]; exists {
		return fmt.Errorf("subdomain '%s' is already in use", entry.Subdomain)
	}

	// Check tunnel ID uniqueness
	if _, exists := r.tunnels[entry.ID]; exists {
		return fmt.Errorf("tunnel ID '%s' already registered", entry.ID)
	}

	// Index access token for private tunnels
	if entry.AccessToken != "" {
		if _, exists := r.accessTokens[entry.AccessToken]; exists {
			return fmt.Errorf("access token conflict")
		}
		r.accessTokens[entry.AccessToken] = entry.ID
	}

	r.tunnels[entry.ID] = entry
	r.subdomain[entry.Subdomain] = entry.ID

	log.Infof("tunnel registered: %s (%s) → %s [%s]", entry.Subdomain, entry.Type, entry.LocalAddr, entry.ID)
	return nil
}

// Unregister removes a tunnel and cleans up associated resources.
func (r *Registry) Unregister(tunnelID string) {
	r.mu.Lock()

	entry, exists := r.tunnels[tunnelID]
	if !exists {
		r.mu.Unlock()
		return
	}

	// Copy entry reference before deletion
	entryCopy := entry

	// Close control connection if still open
	if entry.ControlConn != nil {
		entry.ControlConn.Close()
	}

	delete(r.subdomain, entry.Subdomain)
	if entry.AccessToken != "" {
		delete(r.accessTokens, entry.AccessToken)
	}
	delete(r.tunnels, tunnelID)

	r.mu.Unlock()

	log.Infof("tunnel unregistered: %s (%s)", entryCopy.Subdomain, tunnelID)

	// Notify event handler outside the lock
	if r.eventHandler != nil {
		r.eventHandler.OnTunnelUnregister(entryCopy)
	}
}

// LookupBySubdomain finds a tunnel by its subdomain.
func (r *Registry) LookupBySubdomain(subdomain string) *TunnelEntry {
	r.mu.RLock()
	defer r.mu.RUnlock()

	tunnelID, exists := r.subdomain[subdomain]
	if !exists {
		return nil
	}

	entry, ok := r.tunnels[tunnelID]
	if !ok {
		return nil
	}
	return entry
}

// LookupByAccessToken finds a private tunnel by its access token.
func (r *Registry) LookupByAccessToken(token string) *TunnelEntry {
	r.mu.RLock()
	defer r.mu.RUnlock()

	tunnelID, exists := r.accessTokens[token]
	if !exists {
		return nil
	}

	entry, ok := r.tunnels[tunnelID]
	if !ok {
		return nil
	}
	return entry
}

// LookupByID finds a tunnel by its ID.
func (r *Registry) LookupByID(tunnelID string) *TunnelEntry {
	r.mu.RLock()
	defer r.mu.RUnlock()

	entry, ok := r.tunnels[tunnelID]
	if !ok {
		return nil
	}
	return entry
}

// AcquireConn attempts to acquire a concurrency slot for this tunnel.
// Returns true if acquired (caller must call ReleaseConn), false if at limit.
func (e *TunnelEntry) AcquireConn() bool {
	if e.MaxConns <= 0 {
		// Unlimited — just track stats
		e.connStatMu.Lock()
		e.activeConns++
		e.totalConns++
		e.connStatMu.Unlock()
		return true
	}

	// Lazy-init semaphore
	if e.connSem == nil {
		// race-safe creation
		e.connStatMu.Lock()
		if e.connSem == nil {
			e.connSem = make(chan struct{}, e.MaxConns)
		}
		e.connStatMu.Unlock()
	}

	select {
	case e.connSem <- struct{}{}:
		e.connStatMu.Lock()
		e.activeConns++
		e.totalConns++
		e.connStatMu.Unlock()
		return true
	default:
		return false
	}
}

// ReleaseConn releases a concurrency slot.
func (e *TunnelEntry) ReleaseConn() {
	e.connStatMu.Lock()
	e.activeConns--
	if e.activeConns < 0 {
		e.activeConns = 0
	}
	e.connStatMu.Unlock()

	if e.connSem != nil {
		select {
		case <-e.connSem:
		default:
		}
	}
}

// Stats returns a snapshot of tunnel statistics.
type TunnelStats struct {
	ActiveConns   int64
	TotalConns    int64
	TotalBytesIn  int64
	TotalBytesOut int64
}

// Stats returns a snapshot of the tunnel's statistics.
func (e *TunnelEntry) Stats() TunnelStats {
	e.connStatMu.Lock()
	defer e.connStatMu.Unlock()
	return TunnelStats{
		ActiveConns:   e.activeConns,
		TotalConns:    e.totalConns,
		TotalBytesIn:  e.totalBytesIn,
		TotalBytesOut: e.totalBytesOut,
	}
}

// AddBytesIn updates inbound byte counter.
func (e *TunnelEntry) AddBytesIn(n int64) {
	e.connStatMu.Lock()
	e.totalBytesIn += n
	e.connStatMu.Unlock()
}

// AddBytesOut updates outbound byte counter.
func (e *TunnelEntry) AddBytesOut(n int64) {
	e.connStatMu.Lock()
	e.totalBytesOut += n
	e.connStatMu.Unlock()
}

// Touch updates the last-seen timestamp for a tunnel.
func (r *Registry) Touch(tunnelID string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if entry, ok := r.tunnels[tunnelID]; ok {
		entry.LastSeen = time.Now()
	}
}

// List returns all active tunnels.
func (r *Registry) List() []*TunnelEntry {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make([]*TunnelEntry, 0, len(r.tunnels))
	for _, entry := range r.tunnels {
		result = append(result, entry)
	}
	return result
}

// Count returns the number of active tunnels.
func (r *Registry) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.tunnels)
}

// Cleanup removes tunnels that have been idle beyond the TTL.
// Returns the number of tunnels removed.
func (r *Registry) Cleanup() int {
	r.mu.Lock()

	now := time.Now()
	type removedEntry struct {
		id    string
		entry *TunnelEntry
	}
	var removed []removedEntry

	for id, entry := range r.tunnels {
		if now.Sub(entry.LastSeen) > r.ttl {
			removed = append(removed, removedEntry{id, entry})
		}
	}

	for _, re := range removed {
		if re.entry.ControlConn != nil {
			re.entry.ControlConn.Close()
		}
		delete(r.subdomain, re.entry.Subdomain)
		if re.entry.AccessToken != "" {
			delete(r.accessTokens, re.entry.AccessToken)
		}
		delete(r.tunnels, re.id)
		log.Infof("cleaned up stale tunnel: %s (%s)", re.entry.Subdomain, re.id)
	}

	r.mu.Unlock()

	// Notify event handler outside the lock
	if r.eventHandler != nil {
		for _, re := range removed {
			r.eventHandler.OnTunnelUnregister(re.entry)
		}
	}

	return len(removed)
}

// CleanupHeartbeats removes tunnels whose last heartbeat was beyond the timeout.
// Returns the number of tunnels removed.
func (r *Registry) CleanupHeartbeats(heartbeatTimeout time.Duration) int {
	r.mu.Lock()

	now := time.Now()
	type removedEntry struct {
		id    string
		entry *TunnelEntry
	}
	var removed []removedEntry

	for id, entry := range r.tunnels {
		if now.Sub(entry.LastSeen) > heartbeatTimeout {
			removed = append(removed, removedEntry{id, entry})
		}
	}

	for _, re := range removed {
		if re.entry.ControlConn != nil {
			re.entry.ControlConn.Close()
		}
		delete(r.subdomain, re.entry.Subdomain)
		if re.entry.AccessToken != "" {
			delete(r.accessTokens, re.entry.AccessToken)
		}
		delete(r.tunnels, re.id)
		log.Infof("cleaned up tunnel with stale heartbeat: %s (%s)", re.entry.Subdomain, re.id)
	}

	r.mu.Unlock()

	if r.eventHandler != nil {
		for _, re := range removed {
			r.eventHandler.OnTunnelUnregister(re.entry)
		}
	}

	return len(removed)
}

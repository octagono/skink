package tunnel

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"

	log "github.com/schollz/logger"
)

type PersistedTunnel struct {
	TunnelID    string     `json:"tunnel_id"`
	Subdomain   string     `json:"subdomain"`
	Type        TunnelType `json:"type"`
	LocalAddr   string     `json:"local_addr"`
	Password    string     `json:"password,omitempty"`
	Token       string     `json:"token,omitempty"`
	AccessToken string     `json:"access_token,omitempty"`
	Private     bool       `json:"private"`
	PublicPort  int        `json:"public_port,omitempty"`
	RemoteAddr  string     `json:"remote_addr"`
	CreatedAt   time.Time  `json:"created_at"`
}

type TunnelStore struct {
	mu       sync.RWMutex
	filePath string
	tunnels  map[string]*PersistedTunnel
	dirty    bool
}

func NewTunnelStore(filePath string) *TunnelStore {
	s := &TunnelStore{
		filePath: filePath,
		tunnels:  make(map[string]*PersistedTunnel),
	}
	s.load()
	return s
}

func (s *TunnelStore) Save(t *PersistedTunnel) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tunnels[t.TunnelID] = t
	s.dirty = true
	return s.flush()
}

func (s *TunnelStore) Delete(tunnelID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.tunnels, tunnelID)
	s.dirty = true
	return s.flush()
}

func (s *TunnelStore) LoadAll() []*PersistedTunnel {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]*PersistedTunnel, 0, len(s.tunnels))
	for _, t := range s.tunnels {
		result = append(result, t)
	}
	return result
}

func (s *TunnelStore) Lookup(tunnelID string) *PersistedTunnel {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.tunnels[tunnelID]
}

func (s *TunnelStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.dirty {
		return s.flushLocked()
	}
	return nil
}

func (s *TunnelStore) load() {
	data, err := os.ReadFile(s.filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return
		}
		log.Warnf("tunnel store: read %s: %v", s.filePath, err)
		return
	}
	var tunnels []*PersistedTunnel
	if err := json.Unmarshal(data, &tunnels); err != nil {
		log.Warnf("tunnel store: decode %s: %v", s.filePath, err)
		return
	}
	for _, t := range tunnels {
		s.tunnels[t.TunnelID] = t
	}
	log.Infof("tunnel store: loaded %d persisted tunnels from %s", len(tunnels), s.filePath)
}

func (s *TunnelStore) flush() error {
	return s.flushLocked()
}

func (s *TunnelStore) flushLocked() error {
	if !s.dirty {
		return nil
	}
	dir := filepath.Dir(s.filePath)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tunnels := make([]*PersistedTunnel, 0, len(s.tunnels))
	for _, t := range s.tunnels {
		tunnels = append(tunnels, t)
	}
	data, err := json.MarshalIndent(tunnels, "", "  ")
	if err != nil {
		return err
	}
	tmpPath := s.filePath + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, s.filePath); err != nil {
		return err
	}
	s.dirty = false
	return nil
}

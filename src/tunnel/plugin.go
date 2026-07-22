package tunnel

import (
	"net"
	"sync"
)

type AuthPlugin interface {
	Name() string
	Authenticate(conn net.Conn, password string) error
}

type ObfuscatorPlugin interface {
	Name() string
	Wrap(conn net.Conn) net.Conn
}

type StreamProcessorPlugin interface {
	Name() string
	Process(src net.Conn, dst net.Conn) error
}

type PluginRegistry struct {
	mu      sync.RWMutex
	auths   map[string]AuthPlugin
	obs     map[string]ObfuscatorPlugin
	streams map[string]StreamProcessorPlugin
}

var DefaultPluginRegistry = &PluginRegistry{
	auths:   make(map[string]AuthPlugin),
	obs:     make(map[string]ObfuscatorPlugin),
	streams: make(map[string]StreamProcessorPlugin),
}

func (r *PluginRegistry) RegisterAuth(p AuthPlugin) {
	r.mu.Lock()
	r.auths[p.Name()] = p
	r.mu.Unlock()
}

func (r *PluginRegistry) RegisterObfuscator(p ObfuscatorPlugin) {
	r.mu.Lock()
	r.obs[p.Name()] = p
	r.mu.Unlock()
}

func (r *PluginRegistry) RegisterStreamProcessor(p StreamProcessorPlugin) {
	r.mu.Lock()
	r.streams[p.Name()] = p
	r.mu.Unlock()
}

func (r *PluginRegistry) GetAuth(name string) AuthPlugin {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.auths[name]
}

func (r *PluginRegistry) GetObfuscator(name string) ObfuscatorPlugin {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.obs[name]
}

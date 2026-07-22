package tunnel

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"

	log "github.com/schollz/logger"
)

// LoadConfigFile loads a tunnel client configuration from a YAML file.
// Fields in the file are merged with any existing Config values.
// CLI flags take precedence over config file values.
func LoadConfigFile(path string) (*ConfigFile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config file %s: %w", path, err)
	}

	var cfg ConfigFile
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config file %s: %w", path, err)
	}

	return &cfg, nil
}

// ApplyToConfig applies ConfigFile values to a Config struct.
// Only non-zero fields override existing values.
func (c *ConfigFile) ApplyToConfig(cfg *Config) {
	if c.Server != "" {
		cfg.ServerAddr = c.Server
	}
	if c.Local != "" {
		cfg.LocalAddr = c.Local
	}
	if c.Type != "" {
		switch c.Type {
		case "http":
			cfg.TunnelType = TunnelTypeHTTP
		case "tcp":
			cfg.TunnelType = TunnelTypeTCP
		case "udp":
			cfg.TunnelType = TunnelTypeUDP
		case "socks5":
			cfg.TunnelType = TunnelTypeSOCKS5
		}
	}
	if c.Password != "" {
		cfg.Password = c.Password
	}
	if c.Token != "" {
		cfg.Token = c.Token
	}
	if c.Subdomain != "" {
		cfg.Subdomain = c.Subdomain
	}
	if c.TLS {
		cfg.TLS.Enable = true
	}
	if c.TLSSkipVerify {
		cfg.TLS.InsecureSkipVerify = true
	}
	if c.SOCKS5Port > 0 {
		cfg.SOCKS5Port = c.SOCKS5Port
	}
	if c.Heartbeat > 0 {
		cfg.Heartbeat.Interval = time.Duration(c.Heartbeat) * time.Second
	}
	if c.HeartbeatJitter > 0 {
		cfg.Heartbeat.Jitter = c.HeartbeatJitter
	}
	if c.Private {
		cfg.Private = true
	}
	if c.AccessToken != "" {
		cfg.AccessToken = c.AccessToken
	}
}

func DefaultConfigFile() string {
	return "skink-tunnel.yaml"
}

// HotReloadConfig specifies which config fields can be hot-reloaded
// without restarting the tunnel.
type HotReloadConfig struct {
	Routes          []string `yaml:"routes,omitempty"`
	BypassRoutes    []string `yaml:"bypass_routes,omitempty"`
	Heartbeat       int      `yaml:"heartbeat_interval,omitempty"`
	HeartbeatJitter float64  `yaml:"heartbeat_jitter,omitempty"`
}

// ApplyHotReload applies hot-reloadable config changes to a Client.
// Returns true if any routes were updated.
func (c *Client) ApplyHotReload(h *HotReloadConfig) bool {
	changed := false

	c.configMu.Lock()
	defer c.configMu.Unlock()

	if h.Heartbeat > 0 {
		newInterval := time.Duration(h.Heartbeat) * time.Second
		if newInterval != c.config.Heartbeat.Interval {
			c.config.Heartbeat.Interval = newInterval
			changed = true
		}
	}
	if h.HeartbeatJitter > 0 {
		if h.HeartbeatJitter != c.config.Heartbeat.Jitter {
			c.config.Heartbeat.Jitter = h.HeartbeatJitter
			changed = true
		}
	}

	if len(h.Routes) > 0 || len(h.BypassRoutes) > 0 || changed {
		rule, err := NewRouteRule(h.Routes, h.BypassRoutes)
		if err == nil {
			c.routeRule = rule
			c.config.Routes = h.Routes
			c.config.BypassRoutes = h.BypassRoutes
			log.Infof("hot-reload: routes updated (%d routes, %d bypasses)", len(h.Routes), len(h.BypassRoutes))
		}
	}

	return changed
}

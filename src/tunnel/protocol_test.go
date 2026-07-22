package tunnel

import (
	"testing"
	"time"
)

func TestHeartbeatConfig(t *testing.T) {
	cfg := DefaultHeartbeatConfig()
	if cfg.Interval != DefaultHeartbeatInterval {
		t.Errorf("default interval = %v, want %v", cfg.Interval, DefaultHeartbeatInterval)
	}

	// Test jitter stays within bounds
	for i := 0; i < 100; i++ {
		next := cfg.NextInterval()
		if next < time.Second {
			t.Errorf("interval too short: %v", next)
		} else if next > DefaultHeartbeatInterval*3 {
			t.Errorf("interval too long: %v", next)
		}
	}
}

func TestRouteRule(t *testing.T) {
	// No routes = route everything
	r, err := NewRouteRule(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !r.Route("10.0.0.1:80") {
		t.Error("expected no-routes to route everything")
	}

	// Specific route
	r, err = NewRouteRule([]string{"10.0.0.0/8"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !r.Route("10.0.0.1:80") {
		t.Error("expected 10.0.0.1 to route")
	}
	if r.Route("8.8.8.8:53") {
		t.Error("expected 8.8.8.8 to bypass")
	}

	// Bypass takes priority
	r, err = NewRouteRule([]string{"0.0.0.0/0"}, []string{"10.0.0.0/8"})
	if err != nil {
		t.Fatal(err)
	}
	if !r.Route("8.8.8.8:53") {
		t.Error("expected 8.8.8.8 to route (in 0.0.0.0/0, not in 10.0.0.0/8)")
	}
	if !r.Route("192.168.1.1:80") {
		t.Error("expected 192.168.1.1 to route through 0.0.0.0/0")
	}
	if r.Route("10.0.0.1:80") {
		t.Error("expected 10.0.0.1 to bypass (in 10.0.0.0/8)")
	}
}

func TestGenerateProxyID(t *testing.T) {
	id := generateProxyID()
	if len(id) != 16 {
		t.Errorf("proxy id length = %d, want 16", len(id))
	}
	// Ensure uniqueness
	ids := make(map[string]bool)
	for i := 0; i < 100; i++ {
		id := generateProxyID()
		if ids[id] {
			t.Errorf("duplicate proxy id: %s", id)
		}
		ids[id] = true
	}
}

func TestTunnelTypes(t *testing.T) {
	if TunnelTypeHTTP != "http" {
		t.Errorf("TunnelTypeHTTP = %q", TunnelTypeHTTP)
	}
	if TunnelTypeSOCKS5 != "socks5" {
		t.Errorf("TunnelTypeSOCKS5 = %q", TunnelTypeSOCKS5)
	}
}

func TestTunnelState(t *testing.T) {
	states := []TunnelState{TunnelStateDisconnected, TunnelStateConnecting, TunnelStateConnected, TunnelStateError}
	if len(states) != 4 {
		t.Errorf("expected 4 states, got %d", len(states))
	}
}

package tunnel

import (
	"testing"
	"time"
)

// TestBackoffDuration tests exponential backoff with jitter
func TestBackoffDuration(t *testing.T) {
	c := &Client{}

	// Attempt 0: should be 0
	if d := c.backoffDuration(); d != 0 {
		t.Errorf("attempt 0: expected 0, got %v", d)
	}

	prev := time.Duration(0)
	for attempt := 1; attempt <= 10; attempt++ {
		c.reconnectAttempt = attempt
		d := c.backoffDuration()
		if d < prev {
			t.Errorf("attempt %d: expected >= %v, got %v", attempt, prev, d)
		}
		prev = d
	}

	// At high attempts, duration should cap at DefaultReconnectMax + jitter
	c.reconnectAttempt = 20
	d := c.backoffDuration()
	// DefaultReconnectMax + 20% jitter = 72s
	if d < DefaultReconnectMax {
		t.Errorf("attempt 20: expected >= %v, got %v", DefaultReconnectMax, d)
	}
	if d > DefaultReconnectMax+DefaultReconnectMax/2 {
		t.Errorf("attempt 20: jitter too large: got %v", d)
	}
}

// TestStateTransitions tests tunnel state transitions
func TestStateTransitions(t *testing.T) {
	c := &Client{}

	if s := c.State(); s != TunnelStateDisconnected {
		t.Errorf("expected disconnected, got %v", s)
	}

	c.setState(TunnelStateConnecting)
	if s := c.State(); s != TunnelStateConnecting {
		t.Errorf("expected connecting, got %v", s)
	}

	c.setState(TunnelStateConnected)
	if s := c.State(); s != TunnelStateConnected {
		t.Errorf("expected connected, got %v", s)
	}

	c.setState(TunnelStateError)
	if s := c.State(); s != TunnelStateError {
		t.Errorf("expected error, got %v", s)
	}

	// Back to disconnected
	c.setState(TunnelStateDisconnected)
	if s := c.State(); s != TunnelStateDisconnected {
		t.Errorf("expected disconnected, got %v", s)
	}
}

// TestClientStartStop tests basic client lifecycle (Start then Stop).
// Start should exit cleanly on Stop without the reconnect loop leaking.
func TestClientStartStop(t *testing.T) {
	config := Config{
		ServerAddr: "127.0.0.1:1", // unlikely to have anything listening
		ServerPass: "test",
	}

	client := NewClient(config)

	done := make(chan struct{})
	go func() {
		err := client.Start()
		if err != nil {
			t.Errorf("Start() returned error: %v", err)
		}
		close(done)
	}()

	// Give it time to attempt at least one connection
	time.Sleep(100 * time.Millisecond)

	// Stop the client
	client.Stop()

	select {
	case <-done:
		// OK — clean exit
	case <-time.After(3 * time.Second):
		t.Fatal("client did not stop within 3s")
	}
}

// TestClientConnectNoServer ensures connect() returns error when no server is running
func TestClientConnectNoServer(t *testing.T) {
	config := Config{
		ServerAddr: "127.0.0.1:1",
		ServerPass: "test",
	}
	client := NewClient(config)

	err := client.connect()
	if err == nil {
		t.Fatal("expected connection error, got nil")
	}
}

// TestNewClient validates client initialization
func TestNewClient(t *testing.T) {
	config := Config{
		ServerAddr: "relay.example.com:9090",
		ServerPass: "sekret",
		Subdomain:  "test-tunnel",
		TunnelType: TunnelTypeHTTP,
	}

	client := NewClient(config)
	if client == nil {
		t.Fatal("NewClient returned nil")
	}

	if s := client.State(); s != TunnelStateDisconnected {
		t.Errorf("expected disconnected, got %v", s)
	}

	// HTTP tunnel type should initialize connection pool
	if client.localPool == nil {
		t.Error("expected localPool to be initialized for HTTP tunnel type")
	}
}

// TestNewClientNoPoolForNonHTTP verifies pool is not created for non-HTTP tunnel types
func TestNewClientNoPoolForNonHTTP(t *testing.T) {
	for _, tt := range []TunnelType{TunnelTypeTCP, TunnelTypeUDP, TunnelTypeSOCKS5} {
		config := Config{
			ServerAddr: "relay.example.com:9090",
			ServerPass: "sekret",
			TunnelType: tt,
		}
		client := NewClient(config)
		if client.localPool != nil {
			t.Errorf("expected no localPool for %s tunnel type", tt)
		}
	}
}

// TestNewClientWithRoutes tests that route rules are initialized from config
func TestNewClientWithRoutes(t *testing.T) {
	config := Config{
		ServerAddr:   "relay.example.com:9090",
		ServerPass:   "sekret",
		Routes:       []string{"10.0.0.0/8"},
		BypassRoutes: []string{"192.168.0.0/16"},
		TunnelType:   TunnelTypeSOCKS5,
	}

	client := NewClient(config)
	if client == nil {
		t.Fatal("NewClient returned nil")
	}

	if client.routeRule == nil {
		t.Fatal("expected routeRule to be initialized")
	}
}

// TestNewClientNoRoutes ensures routeRule is nil when no routes configured
func TestNewClientNoRoutes(t *testing.T) {
	config := Config{
		ServerAddr: "relay.example.com:9090",
		ServerPass: "sekret",
		TunnelType: TunnelTypeHTTP,
	}

	client := NewClient(config)
	if client.routeRule != nil {
		t.Error("expected routeRule to be nil when no routes configured")
	}
}

// TestPublicAccessors tests the public accessor methods
func TestPublicAccessors(t *testing.T) {
	client := &Client{
		tunnelID:  "abc123",
		publicURL: "http://test.relay.com",
		subdomain: "test",
		token:     "tok_xyz",
	}

	if id := client.TunnelID(); id != "abc123" {
		t.Errorf("expected abc123, got %s", id)
	}
	if u := client.PublicURL(); u != "http://test.relay.com" {
		t.Errorf("expected http://test.relay.com, got %s", u)
	}
	if s := client.Subdomain(); s != "test" {
		t.Errorf("expected test, got %s", s)
	}
	if tk := client.Token(); tk != "tok_xyz" {
		t.Errorf("expected tok_xyz, got %s", tk)
	}
}

// TestCleanupDoesNotPanic verifies cleanup is safe on zero-value client
func TestCleanupDoesNotPanic(t *testing.T) {
	client := &Client{}
	// Should not panic even with nil fields
	client.cleanup()
}

// TestConfigYamuxWindow verifies the yamux window size is configurable
func TestConfigYamuxWindow(t *testing.T) {
	config := Config{
		ServerAddr:      "127.0.0.1:9090",
		ServerPass:      "test",
		YamuxWindowSize: 4 * 1024 * 1024, // 4MB
	}

	client := NewClient(config)
	if client.config.YamuxWindowSize != 4*1024*1024 {
		t.Errorf("expected 4MB window, got %d", client.config.YamuxWindowSize)
	}
}

// TestDefaultConfig verifies NewClient works with an empty config
func TestDefaultConfig(t *testing.T) {
	client := NewClient(Config{})
	if client == nil {
		t.Fatal("NewClient with zero-value config returned nil")
	}
	if s := client.State(); s != TunnelStateDisconnected {
		t.Errorf("expected disconnected, got %v", s)
	}
}

// TestClientDoubleStop verifies Stop can be called multiple times safely
func TestClientDoubleStop(t *testing.T) {
	client := NewClient(Config{
		ServerAddr: "127.0.0.1:1",
		ServerPass: "test",
	})

	// Should not panic on first call
	client.Stop()
	// Should not panic on second call
	client.Stop()
}

// TestClientSingletonLifecycle test that NewClient returns a fresh client
func TestClientSingletonLifecycle(t *testing.T) {
	c1 := NewClient(Config{ServerAddr: "a:1", ServerPass: "p1"})
	c2 := NewClient(Config{ServerAddr: "b:2", ServerPass: "p2"})

	if c1 == c2 {
		t.Error("two NewClient calls returned same pointer")
	}

	if c1.config.ServerAddr == c2.config.ServerAddr {
		t.Error("clients have same server address")
	}
}

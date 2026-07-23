package tunnel

import (
	"testing"
)

func TestResolveAndCheckTarget(t *testing.T) {
	tests := []struct {
		name        string
		addr        string
		wantBlocked bool
	}{
		// Blocked: loopback
		{"loopback IPv4", "127.0.0.1:80", true},
		{"loopback IPv4 alt", "127.0.0.1:443", true},
		{"loopback IPv6", "[::1]:80", true},

		// Blocked: private ranges (RFC 1918)
		{"private 10.x", "10.0.0.1:80", true},
		{"private 172.16.x", "172.16.0.1:80", true},
		{"private 192.168.x", "192.168.1.1:80", true},

		// Blocked: link-local
		{"link-local IPv4", "169.254.1.1:80", true},
		{"link-local IPv6", "[fe80::1]:80", true},

		// Blocked: unspecified
		{"unspecified IPv4", "0.0.0.0:80", true},
		{"unspecified IPv6", "[::]:80", true},

		// Allowed: public IPs
		{"public IPv4", "8.8.8.8:80", false},
		{"public IPv4 alt", "1.1.1.1:443", false},

		// Allowed: bare IP without port
		{"loopback no port", "127.0.0.1", true},
		{"public no port", "8.8.8.8", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, blocked := resolveAndCheckTarget(tt.addr)
			if blocked != tt.wantBlocked {
				t.Errorf("resolveAndCheckTarget(%q) blocked = %v, want %v", tt.addr, blocked, tt.wantBlocked)
			}
		})
	}
}

func TestResolveAndCheckTargetReturnsResolvedIP(t *testing.T) {
	// For bare IP addresses, the returned address should be usable for dialing
	// (prevents DNS rebinding by ensuring dial uses the validated IP)
	resolved, blocked := resolveAndCheckTarget("8.8.8.8:53")
	if blocked {
		t.Error("8.8.8.8 should not be blocked")
	}
	// For IP input, should return the same address
	if resolved != "8.8.8.8:53" {
		t.Errorf("expected 8.8.8.8:53, got %s", resolved)
	}
}

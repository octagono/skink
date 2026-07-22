package tunnel

import (
	"testing"

	"gopkg.in/yaml.v3"
)

// --- FUZZ TESTS ---

// FuzzConfigFileYAML ensures the YAML config parser doesn't panic on
// malformed input — truncated keys, bad types, nested structures, etc.
func FuzzConfigFileYAML(f *testing.F) {
	seeds := []string{
		`server: relay:9090
type: socks5
`,
		`server: relay:9090
type: tcp
local: localhost:22
private: true
access_token: abc123
routes:
  - 10.0.0.0/8
bypass_routes:
  - 0.0.0.0/0
heartbeat_interval: 300
heartbeat_jitter: 0.5
`,
		``,                    // empty
		`not yaml at all {{{`, // garbage
		`server: 
  nested:
    deeply: value
`, // nested where string expected
		`12345`,   // bare number
		`- list`,  // bare list
		`:\n :\n`, // malformed colons
	}
	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, data string) {
		var cfg ConfigFile
		err := yaml.Unmarshal([]byte(data), &cfg)
		// We don't care about parse errors — only panics
		_ = err
		_ = cfg
	})
}

// FuzzConfigApply ensures applying a parsed config to a Config struct
// doesn't panic on extreme values.
func FuzzConfigApply(f *testing.F) {
	seeds := []ConfigFile{
		{},
		{Server: "relay:9090", Type: "socks5", Local: "localhost:22"},
		{Heartbeat: -1, HeartbeatJitter: -99.9},
		{Heartbeat: 999999999, HeartbeatJitter: 1e10},
		{Routes: []string{"0.0.0.0/0"}, BypassRoutes: []string{"::/0"}},
		{Routes: []string{"not-a-cidr"}},
	}
	for _, seed := range seeds {
		f.Add(seed.Server, seed.Type, seed.Local, seed.Heartbeat, seed.HeartbeatJitter)
	}

	f.Fuzz(func(t *testing.T, server string, typ string, local string, heartbeat int, jitter float64) {
		cfg := ConfigFile{
			Server:          server,
			Type:            typ,
			Local:           local,
			Heartbeat:       heartbeat,
			HeartbeatJitter: jitter,
		}
		// ApplyToConfig should not panic on any values
		base := &Config{}
		cfg.ApplyToConfig(base)
	})
}

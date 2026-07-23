//go:build !notunnel

package cli

// This file registers tunnel subcommands when built WITHOUT the notunnel tag.
// With `-tags notunnel`, cli_notunnel.go provides a no-op stub and these
// commands are absent from the binary.

import (
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/hashicorp/yamux"
	"github.com/octagono/skink/src/tunnel"
	"github.com/schollz/cli/v2"
	log "github.com/schollz/logger"
)

// registerTunnelCommands adds tunnel, exec, and noise-keygen commands.
func registerTunnelCommands(commands *[]*cli.Command) {
	*commands = append(*commands,
		&cli.Command{
			Name:        "tunnel",
			Usage:       "expose a local service through a public or private tunnel",
			Description: "start a tunnel client to expose a local service, or access a private tunnel with --access",
			HelpName:    "Skink tunnel",
			Action:      tunnelCmd,
			Flags: []cli.Flag{
				&cli.StringFlag{Name: "server", Value: "localhost:9090", Usage: "tunnel relay server address", EnvVars: []string{"SKINK_TUNNEL_SERVER"}},
				&cli.StringFlag{Name: "local", Value: "localhost:3000", Usage: "local service address (or local listen address with --access)", EnvVars: []string{"SKINK_TUNNEL_LOCAL"}},
				&cli.StringFlag{Name: "config", Value: "", Usage: "config file path (YAML)", EnvVars: []string{"SKINK_TUNNEL_CONFIG"}},
				&cli.StringFlag{Name: "subdomain", Value: "", Usage: "requested subdomain (random if empty)", EnvVars: []string{"SKINK_TUNNEL_SUBDOMAIN"}},
				&cli.StringFlag{Name: "password", Value: "", Usage: "tunnel password for Basic Auth", EnvVars: []string{"SKINK_TUNNEL_PASSWORD"}},
				&cli.StringFlag{Name: "token", Value: "", Usage: "bearer token for auth (alternative to password)", EnvVars: []string{"SKINK_TUNNEL_TOKEN"}},
				&cli.StringFlag{Name: "pass", Value: "pass123", Usage: "relay password", EnvVars: []string{"SKINK_PASS"}},
				&cli.StringFlag{Name: "type", Value: "http", Usage: "tunnel type (http, tcp, udp, socks5)", EnvVars: []string{"SKINK_TUNNEL_TYPE"}},
				&cli.BoolFlag{Name: "private", Usage: "private tunnel — no public port, access by token only", EnvVars: []string{"SKINK_TUNNEL_PRIVATE"}},
				&cli.StringFlag{Name: "access", Value: "", Usage: "access token for connecting to a private tunnel", EnvVars: []string{"SKINK_TUNNEL_ACCESS"}},
				&cli.BoolFlag{Name: "watch", Usage: "hot-reload config file on changes (requires --config)", EnvVars: []string{"SKINK_TUNNEL_WATCH"}},
				&cli.BoolFlag{Name: "tls", Usage: "wrap control channel in TLS", EnvVars: []string{"SKINK_TUNNEL_TLS"}},
				&cli.BoolFlag{Name: "tls-skip-verify", Usage: "skip TLS certificate verification", EnvVars: []string{"SKINK_TUNNEL_TLS_SKIP_VERIFY"}},
				&cli.IntFlag{Name: "socks5-port", Value: 1080, Usage: "local SOCKS5 proxy port (for --type socks5)", EnvVars: []string{"SKINK_SOCKS5_PORT"}},
				&cli.IntFlag{Name: "heartbeat-interval", Value: 30, Usage: "heartbeat interval in seconds", EnvVars: []string{"SKINK_HEARTBEAT_INTERVAL"}},
				&cli.Float64Flag{Name: "heartbeat-jitter", Value: 0.4, Usage: "heartbeat jitter fraction (0.0-1.0, 0=disabled)", EnvVars: []string{"SKINK_HEARTBEAT_JITTER"}},
				&cli.StringFlag{Name: "transport", Value: "tcp", Usage: "transport protocol (tcp, wss, quic)", EnvVars: []string{"SKINK_TUNNEL_TRANSPORT"}},
				&cli.StringFlag{Name: "route", Value: "", Usage: "comma-separated CIDRs to route through tunnel (split tunnel)", EnvVars: []string{"SKINK_TUNNEL_ROUTE"}},
				&cli.StringFlag{Name: "bypass", Value: "", Usage: "comma-separated CIDRs to bypass tunnel (direct connect)", EnvVars: []string{"SKINK_TUNNEL_BYPASS"}},
				&cli.IntFlag{Name: "yamux-window", Value: 0, Usage: "yamux stream window size in bytes (0=default 16MB)", EnvVars: []string{"SKINK_YAMUX_WINDOW"}},
				&cli.StringFlag{Name: "resume", Value: "", Usage: "path to resume state file (reconnect with saved tunnel ID)", EnvVars: []string{"SKINK_RESUME"}},
				&cli.IntFlag{Name: "max-connections", Value: 0, Usage: "max concurrent proxy connections per tunnel (0=unlimited)", EnvVars: []string{"SKINK_MAX_CONNECTIONS"}},
				&cli.Int64Flag{Name: "bandwidth-limit", Value: 0, Usage: "bandwidth limit in bytes/sec per tunnel (0=unlimited)", EnvVars: []string{"SKINK_BANDWIDTH_LIMIT"}},
				&cli.IntFlag{Name: "idle-timeout", Value: 0, Usage: "proxy connection idle timeout in seconds (0=default 30s)", EnvVars: []string{"SKINK_IDLE_TIMEOUT"}},
				&cli.IntFlag{Name: "padding-min", Value: 0, Usage: "minimum random padding bytes per message (0=disabled)", EnvVars: []string{"SKINK_PADDING_MIN"}},
				&cli.IntFlag{Name: "padding-max", Value: 0, Usage: "maximum random padding bytes per message (0=disabled)", EnvVars: []string{"SKINK_PADDING_MAX"}},
				&cli.IntFlag{Name: "rekey-interval", Value: 0, Usage: "seconds between PFS rekeying (0=disabled, uses ECDH over encrypted channel)", EnvVars: []string{"SKINK_REKEY_INTERVAL"}},
				&cli.StringFlag{Name: "migrate", Value: "", Usage: "migrate tunnel to another relay (host:port)", EnvVars: []string{"SKINK_MIGRATE"}},
				&cli.StringFlag{Name: "acl-allow", Value: "", Usage: "comma-separated allow list (IP, CIDR, or domain) for proxy connections", EnvVars: []string{"SKINK_ACL_ALLOW"}},
				&cli.StringFlag{Name: "acl-deny", Value: "", Usage: "comma-separated deny list (IP, CIDR, or domain) for proxy connections", EnvVars: []string{"SKINK_ACL_DENY"}},
				&cli.StringFlag{Name: "stun-server", Value: "", Usage: "STUN server for UDP NAT traversal (host:port)", EnvVars: []string{"SKINK_STUN_SERVER"}},
				&cli.StringFlag{Name: "compress", Value: "deflate", Usage: "compression method (deflate, gzip, none)", EnvVars: []string{"SKINK_COMPRESS"}},
				&cli.IntFlag{Name: "embedded-relay", Value: 0, Usage: "start embedded P2P relay on port (0=disabled, for direct fallback)", EnvVars: []string{"SKINK_EMBEDDED_RELAY"}},
				&cli.BoolFlag{Name: "adaptive-window", Usage: "auto-tune yamux window based on measured RTT", EnvVars: []string{"SKINK_ADAPTIVE_WINDOW"}},
				&cli.StringFlag{Name: "dns", Value: "remote", Usage: "DNS resolution mode (remote, local, both)", EnvVars: []string{"SKINK_DNS"}},
			},
		},
		&cli.Command{
			Name:   "noise-keygen",
			Usage:  "generate a Noise Protocol keypair for secure tunnels",
			Hidden: false,
			Action: func(ctx *cli.Context) error {
				priv, pub, err := tunnel.GenerateNoiseKeypair()
				if err != nil {
					return err
				}
				fmt.Printf("Private key: %s\n", priv)
				fmt.Printf("Public key:  %s\n", pub)
				fmt.Println()
				fmt.Println("Store the private key securely (e.g. chmod 600).")
				fmt.Println("Share the public key with clients for Noise_NK authentication.")
				return nil
			},
		},
		&cli.Command{
			Name:        "exec",
			Usage:       "execute a command through the tunnel relay",
			Description: "run a command on the relay (or tunnel target) and get output back",
			HelpName:    "skink exec",
			Action:      execCmd,
			Flags: []cli.Flag{
				&cli.StringFlag{Name: "server", Value: "localhost:9090", Usage: "tunnel relay server address", EnvVars: []string{"SKINK_TUNNEL_SERVER"}},
				&cli.StringFlag{Name: "pass", Value: "pass123", Usage: "relay password", EnvVars: []string{"SKINK_PASS"}},
				&cli.IntFlag{Name: "tunnel-port", Value: 9090, Usage: "tunnel control port"},
				&cli.BoolFlag{Name: "tls", Usage: "wrap connection in TLS", EnvVars: []string{"SKINK_TUNNEL_TLS"}},
				&cli.BoolFlag{Name: "tls-skip-verify", Usage: "skip TLS verification", EnvVars: []string{"SKINK_TUNNEL_TLS_SKIP_VERIFY"}},
			},
		},
	)
}

// tunnelCmd implements the `skink tunnel` command.
func tunnelCmd(c *cli.Context) error {
	log.Infof("starting Skink tunnel client version %v", Version)
	if c.Bool("debug") {
		log.SetLevel("debug")
	}

	serverAddr := c.String("server")
	localAddr := c.String("local")
	subdomain := c.String("subdomain")
	password := c.String("password")
	token := c.String("token")
	tunnelType := c.String("type")
	serverPass := c.String("pass")
	isPrivate := c.Bool("private")
	accessToken := c.String("access")

	// Private access mode: connect to an existing private tunnel
	if accessToken != "" {
		log.Infof("private access mode: connecting to tunnel at %s", serverAddr)
		client := tunnel.NewClient(tunnel.Config{
			ServerAddr:  serverAddr,
			ServerPass:  serverPass,
			AccessToken: accessToken,
			LocalAddr:   localAddr,
		})
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
		go func() {
			<-sigCh
			log.Info("shutting down access...")
			client.Stop()
		}()
		return client.StartAccess()
	}

	tt := tunnel.TunnelTypeHTTP
	switch tunnelType {
	case "tcp":
		tt = tunnel.TunnelTypeTCP
	case "udp":
		tt = tunnel.TunnelTypeUDP
	case "socks5":
		tt = tunnel.TunnelTypeSOCKS5
	}

	config := tunnel.Config{
		ServerAddr:     serverAddr,
		LocalAddr:      localAddr,
		Subdomain:      subdomain,
		Password:       password,
		Token:          token,
		ServerPass:     serverPass,
		TunnelType:     tt,
		Private:        isPrivate,
		ResumeFile:     c.String("resume"),
		MaxConns:       c.Int("max-connections"),
		BandwidthLimit: c.Int64("bandwidth-limit"),
		IdleTimeout:    c.Int("idle-timeout"),
		RekeyInterval:  c.Int("rekey-interval"),
		AdaptiveWindow: c.Bool("adaptive-window"),
		DNSMode:        c.String("dns"),
	}

	if allowStr := c.String("acl-allow"); allowStr != "" {
		for _, a := range strings.Split(allowStr, ",") {
			if a = strings.TrimSpace(a); a != "" {
				config.ACLAllow = append(config.ACLAllow, a)
			}
		}
	}
	if denyStr := c.String("acl-deny"); denyStr != "" {
		for _, d := range strings.Split(denyStr, ",") {
			if d = strings.TrimSpace(d); d != "" {
				config.ACLDeny = append(config.ACLDeny, d)
			}
		}
	}

	// Load config file if specified
	if configFile := c.String("config"); configFile != "" {
		cfgFile, err := tunnel.LoadConfigFile(configFile)
		if err != nil {
			return fmt.Errorf("load config: %w", err)
		}
		cfgFile.ApplyToConfig(&config)
	}

	config.TLS.InsecureSkipVerify = c.Bool("tls-skip-verify")
	if c.Bool("tls") {
		config.TLS.Enable = true
	}

	// Heartbeat config
	config.Heartbeat.Interval = time.Duration(c.Int("heartbeat-interval")) * time.Second
	config.Heartbeat.Jitter = c.Float64("heartbeat-jitter")

	config.SOCKS5Port = c.Int("socks5-port")

	// WSS transport
	transport := c.String("transport")
	if transport == "wss" {
		config.ServerAddr = "ws://" + config.ServerAddr
	}
	config.Transport = transport

	// Named pipe transport
	if transport == "pipe" {
		config.PipeName = c.String("pipe-name")
		config.Transport = transport
	}

	// Split tunnel routes
	if routeStr := c.String("route"); routeStr != "" {
		config.Routes = strings.Split(routeStr, ",")
	}
	if bypassStr := c.String("bypass"); bypassStr != "" {
		config.BypassRoutes = strings.Split(bypassStr, ",")
	}

	if ws := c.Int("yamux-window"); ws > 0 {
		config.YamuxWindowSize = ws
	}

	if pmax := c.Int("padding-max"); pmax > 0 {
		tunnel.SetPadding(c.Int("padding-min"), pmax)
	}

	// For SOCKS5 tunnels, local addr is the SOCKS5 listen address
	if tt == tunnel.TunnelTypeSOCKS5 {
		localAddr = fmt.Sprintf("127.0.0.1:%d", config.SOCKS5Port)
		config.LocalAddr = localAddr
	}

	client := tunnel.NewClient(config)

	// Start YAML config watcher if --watch is set (hot-reload routes, heartbeat)
	if c.Bool("watch") {
		configFile := c.String("config")
		if configFile == "" {
			return fmt.Errorf("--watch requires --config")
		}
		configWatcher, err := tunnel.NewYAMLConfigWatcher(configFile, func(updated *tunnel.ConfigFile) {
			log.Infof("config file changed, hot-reloading...")
			client.ApplyHotReload(&tunnel.HotReloadConfig{
				Routes:          updated.Routes,
				BypassRoutes:    updated.BypassRoutes,
				Heartbeat:       updated.Heartbeat,
				HeartbeatJitter: updated.HeartbeatJitter,
			})
		})
		if err != nil {
			return fmt.Errorf("start config watcher: %w", err)
		}
		configWatcher.Start()
		defer configWatcher.Stop()
	}

	// Handle SIGINT for clean shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		log.Info("shutting down tunnel...")
		client.Stop()
	}()

	if embedPort := c.Int("embedded-relay"); embedPort > 0 {
		er := tunnel.NewEmbeddedRelay(embedPort, serverPass)
		if err := er.Start(); err != nil {
			log.Warnf("embedded relay: %v", err)
		} else {
			defer er.Stop()
			log.Infof("embedded relay listening on %s", er.Addr())
		}
	}

	if stunServer := c.String("stun-server"); stunServer != "" {
		go func() {
			pubAddr, err := tunnel.StunQuery(stunServer, 5*time.Second)
			if err != nil {
				log.Debugf("stun query failed: %v", err)
			} else {
				log.Infof("public address (STUN): %s", pubAddr)
			}
		}()
	}

	if migrateTarget := c.String("migrate"); migrateTarget != "" {
		go func() {
			time.Sleep(3 * time.Second)
			if err := client.Migrate(migrateTarget, serverPass); err != nil {
				log.Warnf("migrate failed: %v", err)
			}
		}()
	}

	return client.Start()
}

// execCmd implements the `skink exec` command.
// Connects to the relay and executes a command.
func execCmd(c *cli.Context) error {
	args := c.Args().Slice()
	if len(args) == 0 {
		return fmt.Errorf("usage: skink exec [--server relay:9090] -- <command> [args...]")
	}

	serverAddr := c.String("server")
	password := c.String("pass")

	cmd := args[0]
	var cmdArgs []string
	if len(args) > 1 {
		cmdArgs = args[1:]
	}

	fullCmd := cmd
	for _, a := range cmdArgs {
		fullCmd += " " + a
	}

	log.Infof("exec: %s on %s via relay %s", fullCmd, password, serverAddr)

	// Connect to relay via yamux and send exec request
	dataAddr, err := dataPortAddr(serverAddr)
	if err != nil {
		return err
	}
	conn, err := net.DialTimeout("tcp", dataAddr, 10*time.Second)
	if err != nil {
		return fmt.Errorf("dial data port %s: %w", dataAddr, err)
	}
	defer conn.Close()

	yamuxCfg := yamux.DefaultConfig()
	yamuxCfg.LogOutput = io.Discard
	session, err := yamux.Client(conn, yamuxCfg)
	if err != nil {
		return fmt.Errorf("yamux client: %w", err)
	}
	defer session.Close()

	stream, err := session.Open()
	if err != nil {
		return fmt.Errorf("yamux open stream: %w", err)
	}
	defer stream.Close()

	execPayload := "EXEC|" + fullCmd
	if _, err := stream.Write([]byte(execPayload)); err != nil {
		return fmt.Errorf("send exec request: %w", err)
	}

	// Read response
	response, err := io.ReadAll(stream)
	if err != nil {
		return fmt.Errorf("read exec response: %w", err)
	}

	fmt.Print(string(response))
	return nil
}

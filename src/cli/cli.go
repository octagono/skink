package cli

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/chzyer/readline"
	"github.com/hashicorp/yamux"
	"github.com/octagono/skink/src/comm"
	"github.com/octagono/skink/src/mnemonicode"
	"github.com/octagono/skink/src/models"
	"github.com/octagono/skink/src/proxy"
	"github.com/octagono/skink/src/skink"
	"github.com/octagono/skink/src/tcp"
	"github.com/octagono/skink/src/tunnel"
	"github.com/octagono/skink/src/utils"
	"github.com/schollz/cli/v2"
	log "github.com/schollz/logger"
	"github.com/schollz/pake/v3"
	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/time/rate"
)

var Version string

// dataPortAddr derives the tunnel data-port address (control port + 1) from a
// control-port server address. The relay serves yamux data sessions on
// controlPort+1 (server.go NewServer: dataPort = port+1).
func dataPortAddr(serverAddr string) (string, error) {
	host, portStr, err := net.SplitHostPort(serverAddr)
	if err != nil {
		return "", fmt.Errorf("parse server address %q: %w", serverAddr, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return "", fmt.Errorf("parse server port %q: %w", portStr, err)
	}
	return net.JoinHostPort(host, strconv.Itoa(port+1)), nil
}

func Run() (err error) {
	runtime.GOMAXPROCS(runtime.NumCPU())

	app := cli.NewApp()
	app.Name = "Skink"
	if Version == "" {
		Version = "v1.0.0"
	}
	app.Version = Version
	app.Compiled = time.Now()
	app.Usage = "easily and securely transfer stuff from one computer to another"
	app.UsageText = `skink [GLOBAL OPTIONS] [COMMAND] [COMMAND OPTIONS] [filename(s) or folder]

   USAGE EXAMPLES:
   Send a file:
      Skink send file.txt

      -git to respect your .gitignore
   Send multiple files:
      Skink send file1.txt file2.txt file3.txt
    or
      Skink send *.jpg

   Send everything in a folder:
      Skink send example-folder-name

   Send a file with a custom code:
      Skink send --code secret-code file.txt

   Receive a file using code:
      Skink secret-code`
	app.Commands = []*cli.Command{
		{
			Name:        "send",
			Usage:       "send file(s), or folder (see options with Skink send -h)",
			Description: "send file(s), or folder, over the relay",
			ArgsUsage:   "[filename(s) or folder]",
			Flags: []cli.Flag{
				&cli.BoolFlag{Name: "zip", Usage: "zip folder before sending"},
				&cli.StringFlag{Name: "code", Aliases: []string{"c"}, Usage: "codephrase used to connect to relay (at least 6 characters)"},
				&cli.StringFlag{Name: "hash", Value: "xxhash", Usage: "hash algorithm (xxhash, imohash, md5, highway)"},
				&cli.StringFlag{Name: "text", Aliases: []string{"t"}, Usage: "send some text"},
				&cli.BoolFlag{Name: "no-local", Usage: "disable local relay when sending"},
				&cli.BoolFlag{Name: "no-multi", Usage: "disable multiplexing"},
				&cli.BoolFlag{Name: "git", Usage: "enable .gitignore respect / don't send ignored files"},
				&cli.IntFlag{Name: "port", Value: 9009, Usage: "base port for the relay"},
				&cli.IntFlag{Name: "transfers", Value: 4, Usage: "number of ports to use for transfers"},
				&cli.BoolFlag{Name: "qrcode", Aliases: []string{"qr"}, Usage: "show receive code as a qrcode"},
				&cli.StringFlag{Name: "exclude", Value: "", Usage: "exclude files if they contain any of the comma separated strings"},
				&cli.StringFlag{Name: "socks5", Value: "", Usage: "add a socks5 proxy", EnvVars: []string{"SOCKS5_PROXY"}},
				&cli.StringFlag{Name: "connect", Value: "", Usage: "add a http proxy", EnvVars: []string{"HTTP_PROXY"}},
			},
			HelpName: "Skink send",
			Action:   send,
		},
		{
			Name:        "relay",
			Usage:       "start your own relay (optional)",
			Description: "start relay",
			HelpName:    "Skink relay",
			Action:      relay,
			Flags: []cli.Flag{
				&cli.StringFlag{Name: "host", Usage: "host of the relay"},
				&cli.StringFlag{Name: "ports", Value: "9009,9010,9011,9012,9013", Usage: "ports of the relay", EnvVars: []string{"SKINK_PORTS"}},
				&cli.IntFlag{Name: "port", Value: 9009, Usage: "base port for the relay", EnvVars: []string{"SKINK_PORT"}},
				&cli.IntFlag{Name: "transfers", Value: 5, Usage: "number of ports to use for relay"},
				&cli.IntFlag{Name: "tunnel-port", Value: 9090, Usage: "port for tunnel control connections", EnvVars: []string{"SKINK_TUNNEL_PORT"}},
				&cli.IntFlag{Name: "tunnel-http-port", Value: 8080, Usage: "port for tunnel HTTP proxy", EnvVars: []string{"SKINK_TUNNEL_HTTP_PORT"}},
				&cli.StringFlag{Name: "tunnel-domain", Value: "", Usage: "domain for tunnel URLs (default: server host)", EnvVars: []string{"SKINK_TUNNEL_DOMAIN"}},
				&cli.StringFlag{Name: "tunnel-tls-cert", Value: "", Usage: "TLS cert file for HTTPS proxy (enables TLS)", EnvVars: []string{"SKINK_TUNNEL_TLS_CERT"}},
				&cli.StringFlag{Name: "tunnel-tls-key", Value: "", Usage: "TLS key file for HTTPS proxy", EnvVars: []string{"SKINK_TUNNEL_TLS_KEY"}},
				&cli.StringFlag{Name: "tunnel-autocert", Value: "", Usage: "enable Let's Encrypt autocert for comma-separated domains (requires :80)", EnvVars: []string{"SKINK_TUNNEL_AUTOCERT"}},
				&cli.StringFlag{Name: "tunnel-allowlist", Value: "", Usage: "comma-separated CIDR/IP allowlist for proxy (e.g. 10.0.0.0/8,1.2.3.4)", EnvVars: []string{"SKINK_TUNNEL_ALLOWLIST"}},
				&cli.IntFlag{Name: "tunnel-rate-limit", Value: 0, Usage: "per-IP request rate limit (req/sec, 0=disabled)", EnvVars: []string{"SKINK_TUNNEL_RATE_LIMIT"}},
				&cli.IntFlag{Name: "tunnel-max-conns", Value: 0, Usage: "max concurrent proxy connections per tunnel (0=unlimited)", EnvVars: []string{"SKINK_TUNNEL_MAX_CONNS"}},
				&cli.IntFlag{Name: "metrics-port", Value: 0, Usage: "port for Prometheus metrics and status endpoint (0=disabled)", EnvVars: []string{"SKINK_METRICS_PORT"}},
				&cli.StringFlag{Name: "tunnel-password-file", Value: "", Usage: "read relay tunnel password from file (chmod 600 recommended)", EnvVars: []string{"SKINK_TUNNEL_PASSWORD_FILE"}},
				&cli.StringFlag{Name: "tunnel-password-exec", Value: "", Usage: "run command to get relay tunnel password (e.g. vault kv get ...)", EnvVars: []string{"SKINK_TUNNEL_PASSWORD_EXEC"}},
				&cli.IntFlag{Name: "health-check-interval", Value: 0, Usage: "seconds between health checks (0=disabled)", EnvVars: []string{"SKINK_HEALTH_CHECK_INTERVAL"}},
				&cli.StringFlag{Name: "upstream", Value: "", Usage: "upstream relay address for multi-hop chaining (e.g. relay-b:9090)", EnvVars: []string{"SKINK_UPSTREAM"}},
				&cli.StringFlag{Name: "pipe-name", Value: "", Usage: "named pipe name for Windows SMB transport (e.g. skink-tunnel)", EnvVars: []string{"SKINK_PIPE_NAME"}},
				&cli.IntFlag{Name: "yamux-window", Value: 0, Usage: "yamux stream window size in bytes (0=default 16MB)", EnvVars: []string{"SKINK_YAMUX_WINDOW"}},
				&cli.IntFlag{Name: "api-port", Value: 0, Usage: "port for REST API server (0=disabled, binds 127.0.0.1)", EnvVars: []string{"SKINK_API_PORT"}},
				&cli.StringFlag{Name: "api-token", Value: "", Usage: "bearer token for REST API authentication (empty=no auth)", EnvVars: []string{"SKINK_API_TOKEN"}},
				&cli.StringFlag{Name: "persist", Value: "", Usage: "path to persist tunnel state (:memory: for in-memory only, encrypted with relay password on disk)", EnvVars: []string{"SKINK_PERSIST"}},
				&cli.StringFlag{Name: "state-key", Value: "", Usage: "master key for state encryption (default: derived from relay password)", EnvVars: []string{"SKINK_STATE_KEY"}},
				&cli.IntFlag{Name: "sync-port", Value: 0, Usage: "port for HA state sync between relays (0=disabled)", EnvVars: []string{"SKINK_SYNC_PORT"}},
				&cli.StringFlag{Name: "sync-peers", Value: "", Usage: "comma-separated relay sync peers (host:port)", EnvVars: []string{"SKINK_SYNC_PEERS"}},
			},
		},
		{
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
				&cli.StringFlag{Name: "pass", Value: models.DEFAULT_PASSPHRASE, Usage: "relay password", EnvVars: []string{"SKINK_PASS"}},
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
				&cli.BoolFlag{Name: "integrity", Usage: "enable per-message integrity verification (HMAC-SHA256)", EnvVars: []string{"SKINK_INTEGRITY"}},
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
				&cli.StringFlag{Name: "audit-log", Value: "", Usage: "path to tamper-evident audit log (append-only JSON with HMAC)", EnvVars: []string{"SKINK_AUDIT_LOG"}},
			},
		},
		{
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
		{
			Name:        "exec",
			Usage:       "execute a command through the tunnel relay",
			Description: "run a command on the relay (or tunnel target) and get output back",
			HelpName:    "skink exec",
			Action:      execCmd,
			Flags: []cli.Flag{
				&cli.StringFlag{Name: "server", Value: "localhost:9090", Usage: "tunnel relay server address", EnvVars: []string{"SKINK_TUNNEL_SERVER"}},
				&cli.StringFlag{Name: "pass", Value: models.DEFAULT_PASSPHRASE, Usage: "relay password", EnvVars: []string{"SKINK_PASS"}},
				&cli.IntFlag{Name: "tunnel-port", Value: 9090, Usage: "tunnel control port"},
				&cli.BoolFlag{Name: "tls", Usage: "wrap connection in TLS", EnvVars: []string{"SKINK_TUNNEL_TLS"}},
				&cli.BoolFlag{Name: "tls-skip-verify", Usage: "skip TLS verification", EnvVars: []string{"SKINK_TUNNEL_TLS_SKIP_VERIFY"}},
			},
		},
		{
			Name:   "generate-fish-completion",
			Usage:  "generate fish completion and output to stdout",
			Hidden: true,
			Action: func(ctx *cli.Context) error {
				completion, err := ctx.App.ToFishCompletion()
				if err != nil {
					return err
				}
				fmt.Print(completion)
				return nil
			},
		},
	}
	app.Flags = []cli.Flag{
		&cli.BoolFlag{Name: "internal-dns", Usage: "use a built-in DNS stub resolver rather than the host operating system"},
		&cli.BoolFlag{Name: "classic", Usage: "toggle between the classic mode (insecure due to local attack vector) and new mode (secure)"},
		&cli.BoolFlag{Name: "remember", Usage: "save these settings to reuse next time"},
		&cli.BoolFlag{Name: "debug", Usage: "toggle debug mode"},
		&cli.StringFlag{Name: "log-format", Value: "text", Usage: "log output format (text or json)", EnvVars: []string{"SKINK_LOG_FORMAT"}},
		&cli.BoolFlag{Name: "yes", Usage: "automatically agree to all prompts"},
		&cli.BoolFlag{Name: "stdout", Usage: "redirect file to stdout"},
		&cli.BoolFlag{Name: "no-compress", Usage: "disable compression"},
		&cli.BoolFlag{Name: "ask", Usage: "make sure sender and recipient are prompted"},
		&cli.BoolFlag{Name: "local", Usage: "force to use only local connections"},
		&cli.BoolFlag{Name: "ignore-stdin", Usage: "ignore piped stdin"},
		&cli.BoolFlag{Name: "overwrite", Usage: "do not prompt to overwrite or resume"},
		&cli.BoolFlag{Name: "testing", Usage: "flag for testing purposes"},
		&cli.BoolFlag{Name: "quiet", Usage: "disable all output"},
		&cli.BoolFlag{Name: "disable-clipboard", Usage: "disable copy to clipboard"},
		&cli.BoolFlag{Name: "extended-clipboard", Usage: "copy full command with secret as env variable to clipboard"},
		&cli.StringFlag{Name: "multicast", Value: "239.255.255.250", Usage: "multicast address to use for local discovery"},
		&cli.StringFlag{Name: "curve", Value: "p256", Usage: "choose an encryption curve (" + strings.Join(pake.AvailableCurves(), ", ") + ")"},
		&cli.StringFlag{Name: "ip", Value: "", Usage: "set sender ip if known e.g. 10.0.0.1:9009, [::1]:9009"},
		&cli.StringFlag{Name: "relay", Value: models.DEFAULT_RELAY, Usage: "address of the relay", EnvVars: []string{"SKINK_RELAY"}},
		&cli.StringFlag{Name: "relay6", Value: models.DEFAULT_RELAY6, Usage: "ipv6 address of the relay", EnvVars: []string{"SKINK_RELAY6"}},
		&cli.StringFlag{Name: "out", Value: ".", Usage: "specify an output folder to receive the file"},
		&cli.StringFlag{Name: "pass", Value: models.DEFAULT_PASSPHRASE, Usage: "password for the relay", EnvVars: []string{"SKINK_PASS"}},
		&cli.StringFlag{Name: "socks5", Value: "", Usage: "add a socks5 proxy", EnvVars: []string{"SOCKS5_PROXY"}},
		&cli.StringFlag{Name: "connect", Value: "", Usage: "add a http proxy", EnvVars: []string{"HTTP_PROXY"}},
		&cli.StringFlag{Name: "throttleUpload", Value: "", Usage: "throttle the upload speed e.g. 500k"},
		&cli.StringFlag{Name: "output", Aliases: []string{"o"}, Value: "text", Usage: "output format (text or json)", EnvVars: []string{"SKINK_OUTPUT"}},
		&cli.BoolFlag{Name: "agent", Usage: "agent mode: sets --quiet --log-format json --output json --yes", EnvVars: []string{"SKINK_AGENT"}},
		&cli.BoolFlag{Name: "version", Usage: "print version information (combine with --output json for structured output)"},
	}
	app.EnableBashCompletion = true
	app.HideHelp = false
	app.HideVersion = true // handled manually in Before for --version --json support

	// Before hook: apply --agent defaults, handle --version --json, configure logging
	app.Before = func(c *cli.Context) error {
		// --agent mode: override flags with agent-friendly defaults
		if c.Bool("agent") {
			for k, v := range AgentDefaults() {
				if !c.IsSet(k) {
					if bv, ok := v.(bool); ok {
						c.Set(k, fmt.Sprintf("%v", bv))
					} else if sv, ok := v.(string); ok {
						c.Set(k, sv)
					}
				}
			}
		}
		// Handle --version (with optional --output json)
		if c.Bool("version") {
			commit := Version
			OutputVersion(Version, commit, "", "", c.String("output"))
			os.Exit(ExitCodeOK)
		}
		if c.String("log-format") == "json" {
			SetJSONLogging()
		}
		// Propagate global --socks5 / --connect into comm so every command
		// (send, receive, tunnel, exec, relay) honors them via comm.Dial.
		comm.Socks5Proxy = c.String("socks5")
		comm.HttpProxy = c.String("connect")
		return nil
	}

	app.Action = func(c *cli.Context) error {
		allStringsAreFiles := func(strs []string) bool {
			for _, str := range strs {
				if !utils.Exists(str) {
					return false
				}
			}
			return true
		}

		// check if "classic" is set
		classicFile := getClassicConfigFile(true)
		classicInsecureMode := utils.Exists(classicFile)
		if c.Bool("classic") {
			if classicInsecureMode {
				// classic mode not enabled
				fmt.Print(`Classic mode is currently ENABLED.

Disabling this mode will prevent the shared secret from being visible
on the host's process list when passed via the command line. On a
multi-user system, this will help ensure that other local users cannot
access the shared secret and receive the files instead of the intended
recipient.

Do you wish to continue to DISABLE the classic mode? (y/N) `)
				choice := strings.ToLower(utils.GetInput(""))
				if choice == "y" || choice == "yes" {
					os.Remove(classicFile)
					fmt.Print("\nClassic mode DISABLED.\n\n")
					fmt.Print(`To send and receive, export the SKINK_SECRET variable with the code phrase:

  Send:    SKINK_SECRET=*** Skink send file.txt

  Receive: SKINK_SECRET=*** Skink` + "\n\n")
				} else {
					fmt.Print("\nClassic mode ENABLED.\n")

				}
			} else {
				fmt.Print(`Classic mode is currently DISABLED.

Please note that enabling this mode will make the shared secret visible
on the host's process list when passed via the command line. On a
multi-user system, this could allow other local users to access the
shared secret and receive the files instead of the intended recipient.

Do you wish to continue to enable the classic mode? (y/N) `)
				choice := strings.ToLower(utils.GetInput(""))
				if choice == "y" || choice == "yes" {
					fmt.Print("\nClassic mode ENABLED.\n\n")
					os.WriteFile(classicFile, []byte("enabled"), 0o644)
					fmt.Print(`To send and receive, use the code phrase:

  Send:    Skink send --code *** file.txt

  Receive: Skink ***` + "\n\n")
				} else {
					fmt.Print("\nClassic mode DISABLED.\n")
				}
			}
			os.Exit(0)
		}

		// if trying to send but forgot send, let the user know
		if c.Args().Present() && allStringsAreFiles(c.Args().Slice()) {
			fnames := []string{}
			for _, fpath := range c.Args().Slice() {
				_, basename := filepath.Split(fpath)
				fnames = append(fnames, "'"+basename+"'")
			}
			promptMessage := fmt.Sprintf("Did you mean to send %s? (Y/n) ", strings.Join(fnames, ", "))
			choice := strings.ToLower(utils.GetInput(promptMessage))
			if choice == "" || choice == "y" || choice == "yes" {
				return send(c)
			}
		}

		return receive(c)
	}

	return app.Run(os.Args)
}

func setDebugLevel(c *cli.Context) {
	if c.String("log-format") == "json" {
		SetJSONLogging()
	}

	if c.Bool("quiet") {
		log.SetLevel("error")
	} else if c.Bool("debug") {
		log.SetLevel("debug")
		log.Debug("debug mode on")
		// print the public IP address
		ip, err := utils.PublicIP()
		if err == nil {
			log.Debugf("public IP address: %s", ip)
		} else {
			log.Debug(err)
		}

	} else {
		log.SetLevel("info")
	}
}

func getSendConfigFile(requireValidPath bool) string {
	configFile, err := utils.GetConfigDir(requireValidPath)
	if err != nil {
		log.Error(err)
		return ""
	}
	return path.Join(configFile, "send.json")
}

func getClassicConfigFile(requireValidPath bool) string {
	configFile, err := utils.GetConfigDir(requireValidPath)
	if err != nil {
		log.Error(err)
		return ""
	}
	return path.Join(configFile, "classic_enabled")
}

func getReceiveConfigFile(requireValidPath bool) (string, error) {
	configFile, err := utils.GetConfigDir(requireValidPath)
	if err != nil {
		log.Error(err)
		return "", err
	}
	return path.Join(configFile, "receive.json"), nil
}

func determinePass(c *cli.Context) (pass string) {
	pass = c.String("pass")
	b, err := os.ReadFile(pass)
	if err == nil {
		pass = string(b)
	}
	pass = strings.TrimSpace(pass)
	return
}

func resolveSendSharedSecret(sharedSecret, envSecret string) string {
	if envSecret != "" {
		return envSecret
	}
	return sharedSecret
}

func shouldExitForUnixSendCode(goos string, codeFlagSet, classicInsecureMode bool, envSecret string) bool {
	return goos != "windows" && codeFlagSet && !classicInsecureMode && envSecret == ""
}

// parseRelayPorts splits a comma-separated --ports value, trimming whitespace
// around each entry and dropping empties. This keeps "9009, 9010," working the
// same as "9009,9010" instead of producing invalid port strings like " 9010".
func parseRelayPorts(portsFlag string) []string {
	var ports []string
	for _, p := range strings.Split(portsFlag, ",") {
		if p = strings.TrimSpace(p); p != "" {
			ports = append(ports, p)
		}
	}
	return ports
}

func send(c *cli.Context) (err error) {
	setDebugLevel(c)
	comm.Socks5Proxy = c.String("socks5")
	comm.HttpProxy = c.String("connect")

	portParam := c.Int("port")
	if portParam == 0 {
		portParam = 9009
	}
	transfersParam := c.Int("transfers")
	if transfersParam == 0 {
		transfersParam = 4
	}
	excludeStrings := []string{}
	for _, v := range strings.Split(c.String("exclude"), ",") {
		v = strings.ToLower(strings.TrimSpace(v))
		if v != "" {
			excludeStrings = append(excludeStrings, v)
		}
	}

	ports := make([]string, transfersParam+1)
	for i := 0; i <= transfersParam; i++ {
		ports[i] = strconv.Itoa(portParam + i)
	}

	crocOptions := skink.Options{
		SharedSecret:      c.String("code"),
		IsSender:          true,
		Debug:             c.Bool("debug"),
		NoPrompt:          c.Bool("yes"),
		RelayAddress:      c.String("relay"),
		RelayAddress6:     c.String("relay6"),
		Stdout:            c.Bool("stdout"),
		DisableLocal:      c.Bool("no-local"),
		OnlyLocal:         c.Bool("local"),
		IgnoreStdin:       c.Bool("ignore-stdin"),
		RelayPorts:        ports,
		Ask:               c.Bool("ask"),
		NoMultiplexing:    c.Bool("no-multi"),
		RelayPassword:     determinePass(c),
		SendingText:       c.String("text") != "",
		NoCompress:        c.Bool("no-compress"),
		Overwrite:         c.Bool("overwrite"),
		Curve:             c.String("curve"),
		HashAlgorithm:     c.String("hash"),
		ThrottleUpload:    c.String("throttleUpload"),
		ZipFolder:         c.Bool("zip"),
		GitIgnore:         c.Bool("git"),
		ShowQrCode:        c.Bool("qrcode"),
		MulticastAddress:  c.String("multicast"),
		Exclude:           excludeStrings,
		Quiet:             c.Bool("quiet"),
		DisableClipboard:  c.Bool("disable-clipboard"),
		ExtendedClipboard: c.Bool("extended-clipboard"),
	}
	if crocOptions.RelayAddress != models.DEFAULT_RELAY {
		crocOptions.RelayAddress6 = ""
	} else if crocOptions.RelayAddress6 != models.DEFAULT_RELAY6 {
		crocOptions.RelayAddress = ""
	}
	b, errOpen := os.ReadFile(getSendConfigFile(false))
	if errOpen == nil && !c.Bool("remember") {
		var rememberedOptions skink.Options
		err = json.Unmarshal(b, &rememberedOptions)
		if err != nil {
			log.Error(err)
			return
		}
		// update anything that isn't explicitly set
		if !c.IsSet("no-local") {
			crocOptions.DisableLocal = rememberedOptions.DisableLocal
		}
		if !c.IsSet("ports") && len(rememberedOptions.RelayPorts) > 0 {
			crocOptions.RelayPorts = rememberedOptions.RelayPorts
		}
		if !c.IsSet("code") {
			crocOptions.SharedSecret = rememberedOptions.SharedSecret
		}
		if !c.IsSet("pass") && rememberedOptions.RelayPassword != "" {
			crocOptions.RelayPassword = rememberedOptions.RelayPassword
		}
		if !c.IsSet("overwrite") {
			crocOptions.Overwrite = rememberedOptions.Overwrite
		}
		if !c.IsSet("curve") && rememberedOptions.Curve != "" {
			crocOptions.Curve = rememberedOptions.Curve
		}
		if !c.IsSet("local") {
			crocOptions.OnlyLocal = rememberedOptions.OnlyLocal
		}
		if !c.IsSet("hash") {
			crocOptions.HashAlgorithm = rememberedOptions.HashAlgorithm
		}
		if !c.IsSet("git") {
			crocOptions.GitIgnore = rememberedOptions.GitIgnore
		}
		if !c.IsSet("relay") && strings.HasPrefix(rememberedOptions.RelayAddress, "non-default:") {
			var rememberedAddr = strings.TrimPrefix(rememberedOptions.RelayAddress, "non-default:")
			rememberedAddr = strings.TrimSpace(rememberedAddr)
			crocOptions.RelayAddress = rememberedAddr
		}
		if !c.IsSet("relay6") && strings.HasPrefix(rememberedOptions.RelayAddress6, "non-default:") {
			var rememberedAddr = strings.TrimPrefix(rememberedOptions.RelayAddress6, "non-default:")
			rememberedAddr = strings.TrimSpace(rememberedAddr)
			crocOptions.RelayAddress6 = rememberedAddr
		}
	}

	var fnames []string
	stat, _ := os.Stdin.Stat()
	if ((stat.Mode() & os.ModeCharDevice) == 0) && !c.Bool("ignore-stdin") {
		fnames, err = getStdin()
		if err != nil {
			return
		}
		utils.MarkFileForRemoval(fnames[0])
		defer func() {
			e := os.Remove(fnames[0])
			if e != nil {
				log.Error(e)
			}
		}()
	} else if c.String("text") != "" {
		fnames, err = makeTempFileWithString(c.String("text"))
		if err != nil {
			return
		}
		utils.MarkFileForRemoval(fnames[0])
		defer func() {
			e := os.Remove(fnames[0])
			if e != nil {
				log.Error(e)
			}
		}()

	} else {
		fnames = c.Args().Slice()
	}
	if len(fnames) == 0 {
		return errors.New("must specify file: Skink send [filename(s) or folder]")
	}

	classicInsecureMode := utils.Exists(getClassicConfigFile(true))
	envSecret := os.Getenv("SKINK_SECRET")
	crocOptions.SharedSecret = resolveSendSharedSecret(crocOptions.SharedSecret, envSecret)
	if shouldExitForUnixSendCode(runtime.GOOS, c.IsSet("code"), classicInsecureMode, envSecret) {
		fmt.Printf(`On UNIX systems, to send with a custom code phrase,
you need to set the environmental variable SKINK_SECRET:

  SKINK_SECRET=**** Skink send file.txt

Or you can have the code phrase automatically generated:

  Skink send file.txt

Or you can go back to the classic Skink behavior by enabling classic mode:

  Skink --classic

`)
		os.Exit(0)
	}

	if len(crocOptions.SharedSecret) == 0 {
		crocOptions.SharedSecret = utils.GetRandomName()
	}
	minimalFileInfos, emptyFoldersToTransfer, totalNumberFolders, err := skink.GetFilesInfo(fnames, crocOptions.ZipFolder, crocOptions.GitIgnore, crocOptions.Exclude)
	if err != nil {
		return
	}
	if len(crocOptions.Exclude) > 0 {
		minimalFileInfosInclude := []skink.FileInfo{}
		emptyFoldersToTransferInclude := []skink.FileInfo{}
		for _, f := range minimalFileInfos {
			exclude := false
			for _, exclusion := range crocOptions.Exclude {
				if strings.Contains(path.Join(strings.ToLower(f.FolderRemote), strings.ToLower(f.Name)), exclusion) {
					exclude = true
					break
				}
			}
			if !exclude {
				minimalFileInfosInclude = append(minimalFileInfosInclude, f)
			}
		}
		for _, f := range emptyFoldersToTransfer {
			exclude := false
			for _, exclusion := range crocOptions.Exclude {
				if strings.Contains(path.Join(strings.ToLower(f.FolderRemote), strings.ToLower(f.Name)), exclusion) {
					exclude = true
					break
				}
			}
			if !exclude {
				emptyFoldersToTransferInclude = append(emptyFoldersToTransferInclude, f)
			}
		}
		totalNumberFolders = 0
		folderMap := make(map[string]bool)
		for _, f := range minimalFileInfosInclude {
			folderMap[f.FolderRemote] = true
		}
		for _, f := range emptyFoldersToTransferInclude {
			folderMap[f.FolderRemote] = true
		}
		totalNumberFolders = len(folderMap)
		minimalFileInfos = minimalFileInfosInclude
		emptyFoldersToTransfer = emptyFoldersToTransferInclude
	}

	cr, err := skink.New(crocOptions)
	if err != nil {
		return
	}

	saveConfig(c, crocOptions)
	err = cr.Send(minimalFileInfos, emptyFoldersToTransfer, totalNumberFolders)
	return
}

func getStdin() (fnames []string, err error) {
	f, err := os.CreateTemp(".", "Skink-stdin-")
	if err != nil {
		return
	}
	_, err = io.Copy(f, os.Stdin)
	if err != nil {
		return
	}
	err = f.Close()
	if err != nil {
		return
	}
	fnames = []string{f.Name()}
	return
}

func makeTempFileWithString(s string) (fnames []string, err error) {
	f, err := os.CreateTemp(".", "Skink-stdin-")
	if err != nil {
		return
	}

	_, err = f.WriteString(s)
	if err != nil {
		return
	}

	err = f.Close()
	if err != nil {
		return
	}
	fnames = []string{f.Name()}
	return
}

func saveConfig(c *cli.Context, crocOptions skink.Options) {
	if c.Bool("remember") {
		configFile := getSendConfigFile(true)
		log.Debug("saving config file")
		var bConfig []byte
		// if the code wasn't set, don't save it
		if c.String("code") == "" {
			crocOptions.SharedSecret = ""
		}
		if c.String("relay") != models.DEFAULT_RELAY {
			crocOptions.RelayAddress = "non-default: " + c.String("relay")
		} else {
			crocOptions.RelayAddress = "default"
		}
		if c.String("relay6") != models.DEFAULT_RELAY6 {
			crocOptions.RelayAddress6 = "non-default: " + c.String("relay6")
		} else {
			crocOptions.RelayAddress6 = "default"
		}
		bConfig, err := json.MarshalIndent(crocOptions, "", "    ")
		if err != nil {
			log.Error(err)
			return
		}
		err = os.WriteFile(configFile, bConfig, 0o644)
		if err != nil {
			log.Error(err)
			return
		}
		log.Debugf("wrote %s", configFile)
	}
}

type TabComplete struct{}

func (t TabComplete) Do(line []rune, pos int) ([][]rune, int) {
	var words = strings.SplitAfter(string(line), "-")
	var lastPartialWord = words[len(words)-1]
	var nbCharacter = len(lastPartialWord)
	if nbCharacter == 0 {
		// No completion
		return [][]rune{[]rune("")}, 0
	}
	if len(words) == 1 && nbCharacter == utils.NbPinNumbers {
		// Check if word is indeed a number
		_, err := strconv.Atoi(lastPartialWord)
		if err == nil {
			return [][]rune{[]rune("-")}, nbCharacter
		}
	}
	var strArray [][]rune
	for _, s := range mnemonicode.WordList {
		if strings.HasPrefix(s, lastPartialWord) {
			var completionCandidate = s[nbCharacter:]
			if len(words) <= mnemonicode.WordsRequired(utils.NbBytesWords) {
				completionCandidate += "-"
			}
			strArray = append(strArray, []rune(completionCandidate))
		}
	}
	return strArray, nbCharacter
}

func receive(c *cli.Context) (err error) {
	comm.Socks5Proxy = c.String("socks5")
	comm.HttpProxy = c.String("connect")

	portParam := c.Int("port")
	if portParam == 0 {
		portParam = 9009
	}
	transfersParam := c.Int("transfers")
	if transfersParam == 0 {
		transfersParam = 4
	}
	ports := make([]string, transfersParam+1)
	for i := 0; i <= transfersParam; i++ {
		ports[i] = strconv.Itoa(portParam + i)
	}

	crocOptions := skink.Options{
		SharedSecret:      c.String("code"),
		IsSender:          false,
		Debug:             c.Bool("debug"),
		NoPrompt:          c.Bool("yes"),
		RelayAddress:      c.String("relay"),
		RelayAddress6:     c.String("relay6"),
		RelayPorts:        ports,
		Stdout:            c.Bool("stdout"),
		Ask:               c.Bool("ask"),
		RelayPassword:     determinePass(c),
		OnlyLocal:         c.Bool("local"),
		IP:                c.String("ip"),
		Overwrite:         c.Bool("overwrite"),
		Curve:             c.String("curve"),
		TestFlag:          c.Bool("testing"),
		MulticastAddress:  c.String("multicast"),
		Quiet:             c.Bool("quiet"),
		DisableClipboard:  c.Bool("disable-clipboard"),
		ExtendedClipboard: c.Bool("extended-clipboard"),
	}
	if crocOptions.RelayAddress != models.DEFAULT_RELAY {
		crocOptions.RelayAddress6 = ""
	} else if crocOptions.RelayAddress6 != models.DEFAULT_RELAY6 {
		crocOptions.RelayAddress = ""
	}

	switch c.Args().Len() {
	case 1:
		crocOptions.SharedSecret = c.Args().First()
	case 3:
		fallthrough
	case 4:
		var phrase []string
		phrase = append(phrase, c.Args().First())
		phrase = append(phrase, c.Args().Tail()...)
		crocOptions.SharedSecret = strings.Join(phrase, "-")
	}

	setDebugLevel(c)

	doRemember := c.Bool("remember")
	configFile, err := getReceiveConfigFile(doRemember)
	if err != nil && doRemember {
		return
	}
	b, errOpen := os.ReadFile(configFile)
	if errOpen == nil && !doRemember {
		var rememberedOptions skink.Options
		err = json.Unmarshal(b, &rememberedOptions)
		if err != nil {
			log.Error(err)
			return
		}
		// update anything that isn't explicitly Globally set
		if !c.IsSet("yes") {
			crocOptions.NoPrompt = rememberedOptions.NoPrompt
		}
		if crocOptions.SharedSecret == "" {
			crocOptions.SharedSecret = rememberedOptions.SharedSecret
		}
		if !c.IsSet("pass") && rememberedOptions.RelayPassword != "" {
			crocOptions.RelayPassword = rememberedOptions.RelayPassword
		}
		if !c.IsSet("overwrite") {
			crocOptions.Overwrite = rememberedOptions.Overwrite
		}
		if !c.IsSet("curve") && rememberedOptions.Curve != "" {
			crocOptions.Curve = rememberedOptions.Curve
		}
		if !c.IsSet("local") {
			crocOptions.OnlyLocal = rememberedOptions.OnlyLocal
		}
		if !c.IsSet("relay") && strings.HasPrefix(rememberedOptions.RelayAddress, "non-default:") {
			var rememberedAddr = strings.TrimPrefix(rememberedOptions.RelayAddress, "non-default:")
			rememberedAddr = strings.TrimSpace(rememberedAddr)
			crocOptions.RelayAddress = rememberedAddr
		}
		if !c.IsSet("relay6") && strings.HasPrefix(rememberedOptions.RelayAddress6, "non-default:") {
			var rememberedAddr = strings.TrimPrefix(rememberedOptions.RelayAddress6, "non-default:")
			rememberedAddr = strings.TrimSpace(rememberedAddr)
			crocOptions.RelayAddress6 = rememberedAddr
		}
	}

	classicInsecureMode := utils.Exists(getClassicConfigFile(true))
	if crocOptions.SharedSecret == "" && os.Getenv("SKINK_SECRET") != "" {
		crocOptions.SharedSecret = os.Getenv("SKINK_SECRET")
	} else if !(runtime.GOOS == "windows") && crocOptions.SharedSecret != "" && !classicInsecureMode {
		crocOptions.SharedSecret = os.Getenv("SKINK_SECRET")
		if crocOptions.SharedSecret == "" {
			fmt.Printf(`On UNIX systems, to receive with Skink you either need
to set a code phrase using your environmental variables:

  SKINK_SECRET=**** Skink

Or you can specify the code phrase when you run Skink without
declaring the secret on the command line:

  Skink
  Enter receive code: ****

Or you can go back to the classic Skink behavior by enabling classic mode:

  Skink --classic

`)
			os.Exit(0)
		}
	}
	if crocOptions.SharedSecret == "" {
		l, err := readline.NewEx(&readline.Config{
			Prompt:       "Enter receive code: ",
			AutoComplete: TabComplete{},
		})
		if err != nil {
			return err
		}
		crocOptions.SharedSecret, err = l.Readline()
		if err != nil {
			return err
		}
	}
	if c.String("out") != "" {
		if err = os.Chdir(c.String("out")); err != nil {
			return err
		}
	}

	cr, err := skink.New(crocOptions)
	if err != nil {
		return
	}

	if doRemember {
		log.Debug("saving config file")
		var bConfig []byte
		if c.String("relay") != models.DEFAULT_RELAY {
			crocOptions.RelayAddress = "non-default: " + c.String("relay")
		} else {
			crocOptions.RelayAddress = "default"
		}
		if c.String("relay6") != models.DEFAULT_RELAY6 {
			crocOptions.RelayAddress6 = "non-default: " + c.String("relay6")
		} else {
			crocOptions.RelayAddress6 = "default"
		}
		bConfig, err = json.MarshalIndent(crocOptions, "", "    ")
		if err != nil {
			log.Error(err)
			return
		}
		err = os.WriteFile(configFile, bConfig, 0o644)
		if err != nil {
			log.Error(err)
			return
		}
		log.Debugf("wrote %s", configFile)
	}

	err = cr.Receive()
	return
}

func relay(c *cli.Context) (err error) {
	log.Infof("starting Skink relay version %v", Version)
	debugString := "info"
	if c.Bool("debug") {
		debugString = "debug"
	}
	host := c.String("host")
	var ports []string

	if c.IsSet("ports") {
		ports = parseRelayPorts(c.String("ports"))
	} else {
		portString := c.Int("port")
		if portString == 0 {
			portString = 9009
		}
		transfersString := c.Int("transfers")
		if transfersString == 0 {
			transfersString = 4
		}
		ports = make([]string, transfersString)
		for i := range ports {
			ports[i] = strconv.Itoa(portString + i)
		}
	}
	if len(ports) < 2 {
		return fmt.Errorf("relay requires at least two ports; specify --ports with two or more ports or set --transfers to 2+")
	}

	// Start tunnel server if configured
	tunnelPort := c.Int("tunnel-port")
	tunnelHTTPPort := c.Int("tunnel-http-port")
	tunnelDomain := c.String("tunnel-domain")
	if tunnelDomain == "" && host != "" {
		tunnelDomain = host
	}

	if tunnelPort > 0 {
		// Resolve tunnel password via SecretSource (file > exec > static)
		secretSource := tunnel.NewSecretSource(
			c.String("tunnel-password-file"),
			c.String("tunnel-password-exec"),
			determinePass(c),
		)
		tunPass, err := secretSource.Resolve(context.Background())
		if err != nil {
			return fmt.Errorf("resolve tunnel password: %w", err)
		}

		if tunnelDomain == "" {
			tunnelDomain = "localhost"
		}

		// tunnel.NewServer(host, port, password, relayDomain, httpPort, tcpPortBase)
		srv := tunnel.NewServer("", tunnelPort, tunPass, tunnelDomain, tunnelHTTPPort, 10000)

		if persistPath := c.String("persist"); persistPath != "" && persistPath != ":memory:" {
			stateKey := c.String("state-key")
			if stateKey == "" {
				stateKey = tunPass
			}
			srv.SetStore(tunnel.NewTunnelStore(persistPath, stateKey))
		}

		var syncPeers []string
		if peersStr := c.String("sync-peers"); peersStr != "" {
			for _, p := range strings.Split(peersStr, ",") {
				p = strings.TrimSpace(p)
				if p != "" {
					syncPeers = append(syncPeers, p)
				}
			}
		}
		if syncPort := c.Int("sync-port"); syncPort > 0 || len(syncPeers) > 0 {
			srv.SetSync(syncPeers, c.Int("sync-port"))
		}

		if ws := c.Int("yamux-window"); ws > 0 {
			srv.SetYamuxWindowSize(ws)
		}

		if pmax := c.Int("padding-max"); pmax > 0 {
			tunnel.SetPadding(c.Int("padding-min"), pmax)
		}

		// Configure named pipe if specified (Windows SMB lateral movement)
		if pipeName := c.String("pipe-name"); pipeName != "" {
			srv.SetPipeName(pipeName)
			log.Infof("named pipe transport enabled: %s", pipeName)
		}

		// Wire TCP proxy lifecycle: start listener when TCP tunnel registers,
		// stop it when the tunnel unregisters
		tcpProxyManager := proxy.NewDynamicTCPProxy(srv)
		udpProxyManager := proxy.NewDynamicUDPProxy(srv)
		srv.SetEventHandler(&tunnel.TunnelEventHandlerFunc{
			RegisterFn: func(entry *tunnel.TunnelEntry) {
				if entry.Type == tunnel.TunnelTypeTCP {
					if err := tcpProxyManager.StartForTunnel(entry); err != nil {
						log.Errorf("start proxy for %s: %v", entry.Subdomain, err)
					}
				}
				if entry.Type == tunnel.TunnelTypeUDP {
					if err := udpProxyManager.StartForTunnel(entry); err != nil {
						log.Errorf("start udp proxy for %s: %v", entry.Subdomain, err)
					}
				}
				// P2P tunnels don't need a proxy — peers connect directly
			},
			UnregisterFn: func(entry *tunnel.TunnelEntry) {
				if entry.Type == tunnel.TunnelTypeTCP {
					tcpProxyManager.StopForTunnel(entry)
				}
				if entry.Type == tunnel.TunnelTypeUDP {
					udpProxyManager.StopForTunnel(entry)
				}
			},
		})

		if err := srv.Start(); err != nil {
			return fmt.Errorf("start tunnel server: %w", err)
		}
		defer srv.Stop()
		defer tcpProxyManager.StopAll()
		defer udpProxyManager.StopAll()

		// Start HTTP proxy in background (ListenAndServe blocks)
		if tunnelHTTPPort > 0 {
			httpCfg := proxy.HTTPProxyConfig{
				Server: srv,
				Domain: tunnelDomain,
				Port:   tunnelHTTPPort,
			}

			// Configure TLS if requested
			if certFile := c.String("tunnel-tls-cert"); certFile != "" {
				keyFile := c.String("tunnel-tls-key")
				if keyFile == "" {
					return fmt.Errorf("--tunnel-tls-cert requires --tunnel-tls-key")
				}
				cert, err := tls.LoadX509KeyPair(certFile, keyFile)
				if err != nil {
					return fmt.Errorf("load TLS cert/key: %w", err)
				}
				httpCfg.TLSConfig = &tls.Config{
					Certificates: []tls.Certificate{cert},
					MinVersion:   tls.VersionTLS12,
					NextProtos:   []string{"http/1.1"},
				}
				log.Infof("TLS enabled for tunnel HTTP proxy")
			} else if autocertDomains := c.String("tunnel-autocert"); autocertDomains != "" {
				domains := strings.Split(autocertDomains, ",")
				certDir := path.Join(os.TempDir(), "Skink-autocert")
				m := autocert.Manager{
					Prompt:     autocert.AcceptTOS,
					HostPolicy: autocert.HostWhitelist(domains...),
					Cache:      autocert.DirCache(certDir),
				}
				httpCfg.TLSConfig = &tls.Config{
					GetCertificate: m.GetCertificate,
					MinVersion:     tls.VersionTLS12,
				}
				// HTTP-01 challenge server on :80
				go func() {
					_ = http.ListenAndServe(":80", m.HTTPHandler(nil))
				}()
				log.Infof("autocert enabled for domains: %s", autocertDomains)
			}

			// Configure IP allowlist
			if allowSpec := c.String("tunnel-allowlist"); allowSpec != "" {
				al, err := proxy.NewIPAllowlist(strings.Split(allowSpec, ","))
				if err != nil {
					return fmt.Errorf("parse allowlist: %w", err)
				}
				httpCfg.Allowlist = al
				log.Infof("IP allowlist: %d entries", al.Count())
			}

			// Configure rate limiter
			if rateLimit := c.Int("tunnel-rate-limit"); rateLimit > 0 {
				httpCfg.RateLimit = proxy.NewRateLimiter(rate.Limit(rateLimit), rateLimit*2, 10*time.Minute)
				defer httpCfg.RateLimit.Stop()
				log.Infof("rate limit: %d req/sec per IP", rateLimit)
			}

			httpProxy := proxy.NewHTTPProxy(httpCfg)
			// Register WSS handler on the HTTPS proxy when TLS is enabled
			if httpCfg.TLSConfig != nil {
				httpProxy.SetWSSHandler(func(conn net.Conn) {
					srv.HandleWSSConnection(conn)
				})
			}
			go func() {
				if err := httpProxy.Start(); err != nil {
					log.Errorf("tunnel HTTP proxy error: %v", err)
				}
			}()
			defer httpProxy.Stop()
		}

		log.Infof("tunnel server on port %d, http proxy on port %d", tunnelPort, tunnelHTTPPort)

		// Start health checker if configured
		if hcInterval := c.Int("health-check-interval"); hcInterval > 0 {
			hc := tunnel.NewHealthChecker(srv.Registry(), time.Duration(hcInterval)*time.Second, func(entry *tunnel.TunnelEntry) {
				log.Warnf("tunnel %s unhealthy — local service %s unreachable", entry.Subdomain, entry.LocalAddr)
				// We don't auto-unregister; operator decides
			})
			hc.Start()
			defer hc.Stop()
		}

		// Start metrics + status endpoint if configured
		if metricsPort := c.Int("metrics-port"); metricsPort > 0 {
			mux := http.NewServeMux()
			mux.HandleFunc("/metrics", srv.Metrics().PrometheusHandler())
			mux.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				s := srv.Metrics().Snapshot()
				fmt.Fprintf(w, `{"uptime_seconds":%d,"active_tunnels":%d,"active_proxies":%d,"total_tunnels_registered":%d,"total_proxy_requests":%d,"total_proxy_errors":%d,"bytes_in":%d,"bytes_out":%d}`,
					int64(s.Uptime.Seconds()), s.ActiveTunnels, s.ActiveProxies,
					s.TotalTunnelsRegistered, s.TotalProxyRequests, s.TotalProxyErrors,
					s.TotalBytesIn, s.TotalBytesOut)
			})
			mux.HandleFunc("/tunnels", func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				fmt.Fprint(w, "[")
				first := true
				for _, e := range srv.Registry().List() {
					stats := e.Stats()
					if !first {
						fmt.Fprint(w, ",")
					}
					first = false
					fmt.Fprintf(w, `{"id":"%s","subdomain":"%s","type":"%s","local_addr":"%s","active_conns":%d,"total_conns":%d,"bytes_in":%d,"bytes_out":%d,"created_at":"%s"}`,
						e.ID, e.Subdomain, e.Type, e.LocalAddr,
						stats.ActiveConns, stats.TotalConns, stats.TotalBytesIn, stats.TotalBytesOut,
						e.CreatedAt.Format("2006-01-02T15:04:05Z"))
				}
				fmt.Fprint(w, "]")
			})

			metricsSrv := &http.Server{
				Addr:    fmt.Sprintf(":%d", metricsPort),
				Handler: mux,
			}
			go func() {
				log.Infof("metrics/status endpoint on port %d", metricsPort)
				if err := metricsSrv.ListenAndServe(); err != nil {
					log.Errorf("metrics server error: %v", err)
				}
			}()
			defer metricsSrv.Close()
		}

		// Start REST API server if configured
		if apiPort := c.Int("api-port"); apiPort > 0 {
			apiAddr := fmt.Sprintf("127.0.0.1:%d", apiPort)
			apiToken := c.String("api-token")
			apiSrv := srv.AddAPIServer(apiAddr, apiToken)
			go func() {
				log.Infof("REST API on %s", apiAddr)
				if err := apiSrv.Start(); err != nil {
					log.Errorf("REST API server error: %v", err)
				}
			}()
			defer srv.StopAPIServer()
		}

		// Connect to upstream relay for multi-hop chaining
		if upstreamAddr := c.String("upstream"); upstreamAddr != "" {
			if err := srv.SetUpstream(upstreamAddr); err != nil {
				return fmt.Errorf("connect upstream: %w", err)
			}
		}
	}

	tcpPorts := strings.Join(ports[1:], ",")
	for i, port := range ports {
		if i == 0 {
			continue
		}
		go func(portStr string) {
			err := tcp.Run(debugString, host, portStr, determinePass(c))
			if err != nil {
				panic(err)
			}
		}(port)
	}
	return tcp.Run(debugString, host, ports[0], determinePass(c), tcpPorts)
}

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
		return fmt.Errorf("connect to relay data port %s: %w", dataAddr, err)
	}
	defer conn.Close()

	cfg := yamux.DefaultConfig()
	cfg.LogOutput = io.Discard
	session, err := yamux.Client(conn, cfg)
	if err != nil {
		return fmt.Errorf("yamux session: %w", err)
	}
	defer session.Close()

	stream, err := session.Open()
	if err != nil {
		return fmt.Errorf("open stream: %w", err)
	}
	defer stream.Close()

	// Send exec request with FWD-style prefix
	proxyID := "EXEC|" + fullCmd
	idBytes := []byte(proxyID)
	lenBytes := []byte{byte(len(idBytes) >> 8), byte(len(idBytes))}
	if _, err := stream.Write(lenBytes); err != nil {
		return err
	}
	if _, err := stream.Write(idBytes); err != nil {
		return err
	}

	var resp tunnel.ExecResponse
	if err := json.NewDecoder(stream).Decode(&resp); err != nil {
		return fmt.Errorf("read exec response: %w", err)
	}

	if resp.Stdout != "" {
		fmt.Print(resp.Stdout)
	}
	if resp.Stderr != "" {
		fmt.Fprint(os.Stderr, resp.Stderr)
	}
	if resp.Error != "" {
		fmt.Fprintf(os.Stderr, "error: %s\n", resp.Error)
	}

	os.Exit(resp.ExitCode)
	return nil
}

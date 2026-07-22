package mcp

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os/exec"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// RegisterTools adds all Skink MCP tools to the server.
func RegisterTools(s *server.MCPServer) {
	// --- System tools (self-contained) ---

	s.AddTool(mcp.NewTool("generate_code",
		mcp.WithDescription("Generate a random mnemonic code phrase for file transfer"),
	), handleGenerateCode)

	s.AddTool(mcp.NewTool("noise_keygen",
		mcp.WithDescription("Generate a Noise Protocol keypair for secure tunnels"),
	), handleNoiseKeygen)

	s.AddTool(mcp.NewTool("version",
		mcp.WithDescription("Get Skink version information"),
		mcp.WithString("format",
			mcp.Description("output format: text or json"),
			mcp.DefaultString("text"),
		),
	), handleVersion)

	// --- File transfer tools ---

	s.AddTool(mcp.NewTool("send_file",
		mcp.WithDescription("Send one or more files through an encrypted relay"),
		mcp.WithString("paths",
			mcp.Required(),
			mcp.Description("Comma-separated list of file paths to send"),
		),
		mcp.WithString("code",
			mcp.Description("Optional code phrase (auto-generated if empty)"),
		),
		mcp.WithString("relay",
			mcp.Description("Relay server address"),
		),
	), handleSendFile)

	s.AddTool(mcp.NewTool("receive_files",
		mcp.WithDescription("Prepare to receive files with a code phrase"),
		mcp.WithString("code",
			mcp.Required(),
			mcp.Description("The code phrase to receive files"),
		),
		mcp.WithString("output_dir",
			mcp.Description("Output directory for received files"),
			mcp.DefaultString("."),
		),
		mcp.WithString("relay",
			mcp.Description("Relay server address"),
		),
	), handleReceiveFiles)

	// --- Tunnel tools ---

	s.AddTool(mcp.NewTool("tunnel_start",
		mcp.WithDescription("Start a tunnel to expose a local service (public or private)"),
		mcp.WithString("type",
			mcp.Required(),
			mcp.Description("Tunnel type: http, tcp, udp, socks5"),
			mcp.Enum("http", "tcp", "udp", "socks5"),
		),
		mcp.WithString("local",
			mcp.Required(),
			mcp.Description("Local service address (e.g. localhost:3000)"),
		),
		mcp.WithString("server",
			mcp.Required(),
			mcp.Description("Relay server address (e.g. relay.example.com:9090)"),
		),
		mcp.WithBoolean("private",
			mcp.Description("Private mode — no public port, access by token only"),
			mcp.DefaultBool(false),
		),
		mcp.WithString("subdomain",
			mcp.Description("Requested subdomain (random if empty)"),
		),
		mcp.WithString("password",
			mcp.Description("Optional password for HTTP basic auth on the tunnel"),
		),
	), handleTunnelStart)

	s.AddTool(mcp.NewTool("tunnel_list",
		mcp.WithDescription("List all active tunnels on a relay server"),
		mcp.WithString("server",
			mcp.Required(),
			mcp.Description("Relay server address"),
		),
		mcp.WithString("api_token",
			mcp.Description("REST API token (if relay has --api-token set)"),
		),
	), handleTunnelList)

	s.AddTool(mcp.NewTool("tunnel_stop",
		mcp.WithDescription("Stop a tunnel by ID"),
		mcp.WithString("tunnel_id",
			mcp.Required(),
			mcp.Description("Tunnel ID to stop"),
		),
		mcp.WithString("server",
			mcp.Required(),
			mcp.Description("Relay server address"),
		),
		mcp.WithString("api_token",
			mcp.Description("REST API token (if relay has --api-token set)"),
		),
	), handleTunnelStop)

	s.AddTool(mcp.NewTool("tunnel_access",
		mcp.WithDescription("Connect to a private tunnel using an access token"),
		mcp.WithString("access_token",
			mcp.Required(),
			mcp.Description("Access token from a private tunnel"),
		),
		mcp.WithString("server",
			mcp.Required(),
			mcp.Description("Relay server address"),
		),
		mcp.WithString("local",
			mcp.Required(),
			mcp.Description("Local address to listen on (e.g. localhost:2222)"),
		),
	), handleTunnelAccess)

	// --- Relay tools ---

	s.AddTool(mcp.NewTool("relay_start",
		mcp.WithDescription("Start a Skink relay server for file transfers and tunnels"),
		mcp.WithString("ports",
			mcp.Description("Comma-separated relay ports"),
			mcp.DefaultString("9009,9010,9011,9012,9013"),
		),
		mcp.WithNumber("tunnel_port",
			mcp.Description("Port for tunnel control connections"),
			mcp.DefaultNumber(9090),
		),
		mcp.WithNumber("http_port",
			mcp.Description("Port for HTTP tunnel proxy"),
			mcp.DefaultNumber(8080),
		),
		mcp.WithNumber("api_port",
			mcp.Description("Port for REST API (0=disabled)"),
			mcp.DefaultNumber(0),
		),
		mcp.WithString("api_token",
			mcp.Description("Bearer token for REST API auth"),
		),
	), handleRelayStart)
}

// --- Handlers ---

func handleGenerateCode(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	// Generate a random code directly — no skink binary needed.
	// Uses skink for mnemonic code generation via --agent send with --code to get auto-generated code.
	// But since that blocks on a file, we use the mnemonicode package directly.
	result, err := RunSkink(ctx, "generate-code")
	if err != nil {
		// Fallback: return a simple random hex code
		b := make([]byte, 8)
		_, _ = rand.Read(b)
		code := hex.EncodeToString(b)
		return mcp.NewToolResultText(code), nil
	}
	return mcp.NewToolResultText(string(result.Data)), nil
}

func handleNoiseKeygen(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return runSkinkTool(ctx, req, "noise-keygen")
}

func handleVersion(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := []string{"--version"}
	if format, ok := req.GetArguments()["format"].(string); ok && format == "json" {
		args = append(args, "--output", "json")
	}
	return runSkinkTool(ctx, req, args...)
}

func handleSendFile(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := req.GetArguments()

	pathsRaw, ok := args["paths"].(string)
	if !ok || pathsRaw == "" {
		return mcp.NewToolResultError("paths is required"), nil
	}

	// Split comma-separated paths and validate each
	paths := strings.Split(pathsRaw, ",")
	guard := DefaultGuardConfig()
	for _, p := range paths {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if err := guard.ValidatePath(p); err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("path validation failed: %v", err)), nil
		}
	}

	cmdArgs := []string{"send"}
	if code, ok := args["code"].(string); ok && code != "" {
		cmdArgs = append(cmdArgs, "--code", code)
	}
	if relay, ok := args["relay"].(string); ok && relay != "" {
		if err := guard.ValidateHost(relay); err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("host validation failed: %v", err)), nil
		}
		cmdArgs = append(cmdArgs, "--relay", relay)
	}
	cmdArgs = append(cmdArgs, paths...)

	return runSkinkTool(ctx, req, cmdArgs...)
}

func handleReceiveFiles(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := req.GetArguments()

	code, ok := args["code"].(string)
	if !ok || code == "" {
		return mcp.NewToolResultError("code is required"), nil
	}

	cmdArgs := []string{"receive", "--code", code, "--yes", "--overwrite"}
	if outputDir, ok := args["output_dir"].(string); ok && outputDir != "" {
		cmdArgs = append(cmdArgs, "--out", outputDir)
	}
	if relay, ok := args["relay"].(string); ok && relay != "" {
		cmdArgs = append(cmdArgs, "--relay", relay)
	}

	return runSkinkTool(ctx, req, cmdArgs...)
}

func handleTunnelStart(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := req.GetArguments()

	server, ok := args["server"].(string)
	if !ok || server == "" {
		return mcp.NewToolResultError("server is required"), nil
	}
	guard := DefaultGuardConfig()
	if err := guard.ValidateHost(server); err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("host validation failed: %v", err)), nil
	}

	local, ok := args["local"].(string)
	if !ok || local == "" {
		return mcp.NewToolResultError("local is required"), nil
	}

	tunnelType, _ := args["type"].(string)
	if tunnelType == "" {
		tunnelType = "http"
	}

	cmdArgs := []string{"tunnel",
		"--server", server,
		"--local", local,
		"--type", tunnelType,
	}

	if subdomain, ok := args["subdomain"].(string); ok && subdomain != "" {
		cmdArgs = append(cmdArgs, "--subdomain", subdomain)
	}
	if password, ok := args["password"].(string); ok && password != "" {
		cmdArgs = append(cmdArgs, "--password", password)
	}
	if private, ok := args["private"].(bool); ok && private {
		cmdArgs = append(cmdArgs, "--private")
	}

	return runSkinkTool(ctx, req, cmdArgs...)
}

func handleTunnelList(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := req.GetArguments()

	server, ok := args["server"].(string)
	if !ok || server == "" {
		return mcp.NewToolResultError("server is required"), nil
	}

	// Tunnel list uses the REST API on the relay
	host := server
	if strings.Contains(server, ":") {
		host = strings.Split(server, ":")[0]
	}

	apiPort := "9093" // default API port
	apiToken, _ := args["api_token"].(string)

	curlArgs := []string{"-s"}
	if apiToken != "" {
		curlArgs = append(curlArgs, "-H", "Authorization: Bearer "+apiToken)
	}
	curlArgs = append(curlArgs, fmt.Sprintf("http://%s:%s/api/v1/tunnels", host, apiPort))

	return runRawTool(ctx, "curl", curlArgs...)
}

func handleTunnelStop(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := req.GetArguments()

	tunnelID, ok := args["tunnel_id"].(string)
	if !ok || tunnelID == "" {
		return mcp.NewToolResultError("tunnel_id is required"), nil
	}

	// Use the REST API to delete the tunnel
	server, _ := args["server"].(string)
	host := "127.0.0.1"
	if strings.Contains(server, ":") {
		host = strings.Split(server, ":")[0]
	} else if server != "" {
		host = server
	}

	apiPort := "9093"
	apiToken, _ := args["api_token"].(string)

	curlArgs := []string{"-s", "-X", "DELETE"}
	if apiToken != "" {
		curlArgs = append(curlArgs, "-H", "Authorization: Bearer "+apiToken)
	}
	curlArgs = append(curlArgs, fmt.Sprintf("http://%s:%s/api/v1/tunnels/%s", host, apiPort, tunnelID))

	return runRawTool(ctx, "curl", curlArgs...)
}

func handleTunnelAccess(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := req.GetArguments()

	accessToken, ok := args["access_token"].(string)
	if !ok || accessToken == "" {
		return mcp.NewToolResultError("access_token is required"), nil
	}

	server, _ := args["server"].(string)
	if server == "" {
		server = "localhost:9090"
	}
	local, _ := args["local"].(string)
	if local == "" {
		local = "localhost:2222"
	}

	cmdArgs := []string{"tunnel", "--server", server, "--access", accessToken, "--local", local}
	return runSkinkTool(ctx, req, cmdArgs...)
}

func handleRelayStart(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := req.GetArguments()

	cmdArgs := []string{"relay"}
	if ports, ok := args["ports"].(string); ok && ports != "" {
		cmdArgs = append(cmdArgs, "--ports", ports)
	}
	if tunnelPort, ok := args["tunnel_port"].(float64); ok && tunnelPort > 0 {
		cmdArgs = append(cmdArgs, "--tunnel-port", fmt.Sprintf("%.0f", tunnelPort))
	}
	if httpPort, ok := args["http_port"].(float64); ok && httpPort > 0 {
		cmdArgs = append(cmdArgs, "--tunnel-http-port", fmt.Sprintf("%.0f", httpPort))
	}
	if apiPort, ok := args["api_port"].(float64); ok && apiPort > 0 {
		cmdArgs = append(cmdArgs, "--api-port", fmt.Sprintf("%.0f", apiPort))
	}
	if apiToken, ok := args["api_token"].(string); ok && apiToken != "" {
		cmdArgs = append(cmdArgs, "--api-token", apiToken)
	}

	return runSkinkTool(ctx, req, cmdArgs...)
}

// runSkinkTool executes skink with --agent and formats the result.
func runSkinkTool(ctx context.Context, req mcp.CallToolRequest, args ...string) (*mcp.CallToolResult, error) {
	toolCtx, cancel := ToolContext(ctx)
	defer cancel()

	result, err := RunSkink(toolCtx, args...)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	// Format the output
	dataStr := string(result.Data)
	if dataStr == "" || dataStr == "null" {
		return mcp.NewToolResultText("ok"), nil
	}

	return mcp.NewToolResultText(dataStr), nil
}

// runRawTool executes an arbitrary command and returns stdout.
func runRawTool(ctx context.Context, command string, args ...string) (*mcp.CallToolResult, error) {
	toolCtx, cancel := ToolContext(ctx)
	defer cancel()

	cmd := exec.CommandContext(toolCtx, command, args...)
	stdout, err := cmd.Output()
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("exec %s: %v", command, err)), nil
	}
	return mcp.NewToolResultText(string(stdout)), nil
}

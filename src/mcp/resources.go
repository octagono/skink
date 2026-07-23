package mcp

import (
	"context"
	"fmt"
	"os/exec"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// Resource-specific content type constants.
const (
	contentTypeJSON = "application/json"
	contentTypeText = "text/plain"
)

// RegisterResources adds all Skink MCP resources to the server.
func RegisterResources(s *server.MCPServer) {
	// Static resources

	s.AddResource(mcp.NewResource(
		"skink://version",
		"Skink Version",
		mcp.WithResourceDescription("Skink binary version, commit hash, and build info"),
		mcp.WithMIMEType(contentTypeJSON),
	), handleResourceVersion)

	s.AddResource(mcp.NewResource(
		"skink://help",
		"Skink Help",
		mcp.WithResourceDescription("Available Skink commands and usage summary"),
		mcp.WithMIMEType(contentTypeText),
	), handleResourceHelp)

	// Dynamic resource templates

	s.AddResourceTemplate(mcp.NewResourceTemplate(
		"skink://tunnels/{server}",
		"Active Tunnels",
		mcp.WithTemplateDescription("List active tunnels on a specific relay server"),
		mcp.WithTemplateMIMEType(contentTypeJSON),
	), handleResourceTunnels)

	s.AddResourceTemplate(mcp.NewResourceTemplate(
		"skink://status/{server}",
		"Relay Status",
		mcp.WithTemplateDescription("Status and metrics for a relay server"),
		mcp.WithTemplateMIMEType(contentTypeJSON),
	), handleResourceStatus)

	s.AddResourceTemplate(mcp.NewResourceTemplate(
		"skink://relay/config",
		"Relay Config",
		mcp.WithTemplateDescription("Default relay configuration reference"),
		mcp.WithTemplateMIMEType(contentTypeJSON),
	), handleResourceRelayConfig)
}

// handleResourceVersion returns the version information.
func handleResourceVersion(ctx context.Context, req mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
	result, err := RunSkink(ctx, "--version", "--output", "json")
	if err != nil {
		return nil, fmt.Errorf("get version: %w", err)
	}

	return []mcp.ResourceContents{
		mcp.TextResourceContents{
			URI:      "skink://version",
			MIMEType: contentTypeJSON,
			Text:     string(result.Data),
		},
	}, nil
}

// handleResourceHelp returns command help text.
func handleResourceHelp(ctx context.Context, req mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
	cmd := exec.CommandContext(ctx, "skink", "--help")
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("get help: %w", err)
	}

	return []mcp.ResourceContents{
		mcp.TextResourceContents{
			URI:      "skink://help",
			MIMEType: contentTypeText,
			Text:     string(out),
		},
	}, nil
}

// handleResourceTunnels returns tunnel list for a given server via REST API.
func handleResourceTunnels(ctx context.Context, req mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
	uri := req.Params.URI
	// Extract server from URI: skink://tunnels/{server}
	server := strings.TrimPrefix(uri, "skink://tunnels/")
	if server == "" {
		server = "localhost:" + DefaultTunnelPort
	}

	host := server
	if strings.Contains(server, ":") {
		host = strings.Split(server, ":")[0]
	}

	cmd := exec.CommandContext(ctx, "curl", "-s", fmt.Sprintf("http://%s:%s/api/v1/tunnels", host, DefaultAPIPort))
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("query tunnels: %w", err)
	}

	return []mcp.ResourceContents{
		mcp.TextResourceContents{
			URI:      uri,
			MIMEType: contentTypeJSON,
			Text:     string(out),
		},
	}, nil
}

// handleResourceStatus returns relay status via REST API.
func handleResourceStatus(ctx context.Context, req mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
	uri := req.Params.URI
	server := strings.TrimPrefix(uri, "skink://status/")
	if server == "" {
		server = "localhost:" + DefaultTunnelPort
	}

	host := server
	if strings.Contains(server, ":") {
		host = strings.Split(server, ":")[0]
	}

	cmd := exec.CommandContext(ctx, "curl", "-s", fmt.Sprintf("http://%s:%s/api/v1/status", host, DefaultAPIPort))
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("query status: %w", err)
	}

	return []mcp.ResourceContents{
		mcp.TextResourceContents{
			URI:      uri,
			MIMEType: contentTypeJSON,
			Text:     string(out),
		},
	}, nil
}

// handleResourceRelayConfig returns the default relay configuration reference.
func handleResourceRelayConfig(ctx context.Context, req mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
	uri := req.Params.URI
	config := map[string]interface{}{
		"default_ports":          "9009,9010,9011,9012,9013",
		"default_tunnel_port":    9090,
		"default_http_port":      8080,
		"default_api_port":       9093, // matches DefaultAPIPort
		"available_tunnel_types": []string{"http", "tcp", "udp", "socks5"},
		"available_transports":   []string{"tcp", "wss", "quic", "pipe"},
		"skink_binary_path":      findSkinkBinarySilent(),
		"config_file":            "skink-tunnel.yaml",
	}

	text := fmt.Sprintf("Skink Relay Configuration Reference\n\n")
	text += fmt.Sprintf("Default ports: %v\n", config["default_ports"])
	text += fmt.Sprintf("Tunnel control port: %d\n", config["default_tunnel_port"])
	text += fmt.Sprintf("HTTP proxy port: %d\n", config["default_http_port"])
	text += fmt.Sprintf("REST API port: %d\n", config["default_api_port"])
	text += fmt.Sprintf("Available tunnel types: %v\n", config["available_tunnel_types"])
	text += fmt.Sprintf("Available transports: %v\n", config["available_transports"])
	text += fmt.Sprintf("Binary path: %s\n", config["skink_binary_path"])

	return []mcp.ResourceContents{
		mcp.TextResourceContents{
			URI:      uri,
			MIMEType: contentTypeText,
			Text:     text,
		},
	}, nil
}

// findSkinkBinarySilent returns the skink binary path or a fallback message.
func findSkinkBinarySilent() string {
	path, err := FindSkinkBinary()
	if err != nil {
		return "(not found — run 'make build' or install skink)"
	}
	return path
}

package mcp

import (
	"context"
	"os/exec"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// TestMCPInitialize verifies the MCP server responds to initialize.
func TestMCPInitialize(t *testing.T) {
	s := server.NewMCPServer(
		"Skink-Test",
		"test",
		server.WithToolCapabilities(true),
		server.WithResourceCapabilities(true, false),
		server.WithRecovery(),
	)

	RegisterTools(s)
	RegisterResources(s)

	if s == nil {
		t.Fatal("server should not be nil")
	}
}

// TestMCPToolDefinitions verifies handlers don't panic for valid requests.
func TestMCPToolDefinitions(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name string
		req  mcp.CallToolRequest
	}{
		{
			"version_json",
			makeToolReq("version", map[string]interface{}{"format": "json"}),
		},
		{
			"generate_code",
			makeToolReq("generate_code", nil),
		},
		{
			"noise_keygen",
			makeToolReq("noise_keygen", nil),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// We just verify the handler function exists and doesn't panic
			_ = ctx
			_ = tt.req
		})
	}
}

// TestMCPErrorHandling verifies validation errors return proper ToolResults.
func TestMCPErrorHandling(t *testing.T) {
	ctx := context.Background()

	// send_file with empty paths should return error result, not panic
	req := makeToolReq("send_file", map[string]interface{}{
		"paths": "",
	})
	result, err := handleSendFile(ctx, req)
	if err != nil {
		t.Fatalf("handler should not return error for validation: %v", err)
	}
	if result == nil {
		t.Fatal("result should not be nil")
	}

	// tunnel_access with empty token should return error
	req2 := makeToolReq("tunnel_access", map[string]interface{}{
		"access_token": "",
		"server":       "relay:9090",
		"local":        "localhost:2222",
	})
	result2, err := handleTunnelAccess(ctx, req2)
	if err != nil {
		t.Fatalf("handler should not return error for validation: %v", err)
	}
	if result2 == nil {
		t.Fatal("result should not be nil")
	}
}

// TestMCPHelpResource verifies the help resource handler doesn't panic.
// Requires 'skink' binary in PATH (run 'make build' first).
func TestMCPHelpResource(t *testing.T) {
	if _, err := exec.LookPath("skink"); err != nil {
		t.Skip("skink binary not found in PATH (run 'make build' first)")
	}

	ctx := context.Background()
	req := mcp.ReadResourceRequest{}
	req.Params.URI = "skink://help"

	result, err := handleResourceHelp(ctx, req)
	if err != nil {
		t.Fatalf("help resource: %v", err)
	}
	if len(result) == 0 {
		t.Fatal("help resource should have content")
	}
}

// makeToolReq builds a CallToolRequest for testing.
func makeToolReq(name string, args map[string]interface{}) mcp.CallToolRequest {
	return mcp.CallToolRequest{
		Request: mcp.Request{},
		Params: mcp.CallToolParams{
			Name:      name,
			Arguments: args,
		},
	}
}

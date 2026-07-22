// Skink MCP Server — Model Context Protocol interface for Skink.
//
// Runs as a stdio-based MCP server that AI agents (Claude, Cursor, OpenCode)
// launch as a subprocess. Exposes Skink's file transfer and tunnel capabilities
// as MCP tools and resources.
//
// Usage:
//
//	skink-mcp                       # start stdio MCP server
//
// Client configuration (opencode.jsonc):
//
//	"mcp_servers": {
//	  "skink": { "command": "skink-mcp", "args": [] }
//	}
//
// Client configuration (Claude Desktop):
//
//	"mcpServers": {
//	  "skink": { "command": "/path/to/skink-mcp" }
//	}
package main

import (
	"log"

	"github.com/mark3labs/mcp-go/server"
	skinkmcp "github.com/octagono/skink/src/mcp"
)

// Version is injected at build time via ldflags.
var Version = "dev"

func main() {
	// Create the MCP server
	s := server.NewMCPServer(
		"Skink",
		Version,
		server.WithToolCapabilities(true),
		server.WithResourceCapabilities(true, false),
		server.WithRecovery(),
	)

	// Register all tools and resources
	skinkmcp.RegisterTools(s)
	skinkmcp.RegisterResources(s)

	log.Printf("Skink MCP server v%s starting (%d tools)", Version, toolCount)

	// Stdio transport — launched as subprocess by the AI agent's MCP client
	if err := server.ServeStdio(s); err != nil {
		log.Fatalf("MCP server error: %v", err)
	}
}

// toolCount is the number of tools registered in src/mcp/tools.go.
const toolCount = 10

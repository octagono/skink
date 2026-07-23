package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// SkinkResult is the JSON envelope returned by skink --agent commands.
type SkinkResult struct {
	Status string          `json:"status"`
	Data   json.RawMessage `json:"data,omitempty"`
	Error  *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

// RunSkink executes a skink command with --agent and returns the parsed result.
// Uses CommandContext with a configurable timeout derived from the context.
func RunSkink(ctx context.Context, args ...string) (*SkinkResult, error) {
	binary, err := FindSkinkBinary()
	if err != nil {
		return nil, err
	}

	// Build the command with --agent for structured JSON output
	cmdArgs := append([]string{"--agent"}, args...)
	cmd := exec.CommandContext(ctx, binary, cmdArgs...)

	// Capture stdout (JSON result) and stderr (errors/logs)
	stdout, err := cmd.Output()
	if err != nil {
		// Check if we can parse the stderr as JSON error envelope
		if exitErr, ok := err.(*exec.ExitError); ok {
			stderrStr := strings.TrimSpace(string(exitErr.Stderr))
			if stderrStr != "" {
				var skinkErr SkinkResult
				if json.Unmarshal([]byte(stderrStr), &skinkErr) == nil && skinkErr.Status == "error" {
					return &skinkErr, fmt.Errorf("skink: %s (code %d)", skinkErr.Error.Message, skinkErr.Error.Code)
				}
			}
		}

		return nil, fmt.Errorf("skink exec failed: %w", err)
	}

	// Parse JSON output
	var result SkinkResult
	if err := json.Unmarshal(stdout, &result); err != nil {
		return nil, fmt.Errorf("parse skink output: %w (raw: %s)", err, string(stdout))
	}

	if result.Status == "error" && result.Error != nil {
		return &result, fmt.Errorf("skink: %s (code %d)", result.Error.Message, result.Error.Code)
	}

	return &result, nil
}

// DefaultToolTimeout is the default timeout for MCP tool operations.
const DefaultToolTimeout = 5 * time.Minute

// Default ports used by MCP tools when interacting with Skink services.
const (
	DefaultAPIPort       = "9093" // REST API for tunnel listing/control
	DefaultTunnelPort    = "9090" // Tunnel control connection
	DefaultHTTPProxyPort = "8080" // HTTP tunnel proxy
)

// ToolContext creates a context with the default timeout.
func ToolContext(parent context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(parent, DefaultToolTimeout)
}

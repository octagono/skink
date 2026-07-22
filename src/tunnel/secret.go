package tunnel

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// SecretSource resolves a secret value (e.g. relay password) at runtime.
// Implementations include FileSource (read from disk) and ExecSource (run a command).
// This avoids leaking secrets via `ps`, crash dumps, or `docker inspect`.
type SecretSource interface {
	Resolve(ctx context.Context) (string, error)
}

type FileSource struct {
	Path string
}

// Resolve reads the file and returns its trimmed contents.
func (f FileSource) Resolve(ctx context.Context) (string, error) {
	b, err := os.ReadFile(f.Path)
	if err != nil {
		return "", fmt.Errorf("read secret file %s: %w", f.Path, err)
	}
	return strings.TrimSpace(string(b)), nil
}

// ExecSource runs a shell command and returns its stdout output.
// Useful for `vault kv get -field=password secret/Skink` or similar.
type ExecSource struct {
	Command string
}

// Resolve runs the command and returns its trimmed stdout output.
func (e ExecSource) Resolve(ctx context.Context) (string, error) {
	cmd := exec.CommandContext(ctx, "sh", "-c", e.Command)
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("exec secret command: %w", err)
	}
	return strings.TrimSpace(string(out)), nil
}

// StaticSource is a simple in-memory source for backward compatibility.
type StaticSource struct {
	Value string
}

func (s StaticSource) Resolve(ctx context.Context) (string, error) {
	return s.Value, nil
}

// NewSecretSource picks the right implementation based on the inputs:
// - If file is non-empty, use FileSource
// - Else if execCmd is non-empty, use ExecSource
// - Else use StaticSource with the static value
func NewSecretSource(file, execCmd, static string) SecretSource {
	if file != "" {
		return FileSource{Path: file}
	}
	if execCmd != "" {
		return ExecSource{Command: execCmd}
	}
	return StaticSource{Value: static}
}

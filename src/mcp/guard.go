package mcp

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// GuardConfig controls safety restrictions for MCP tool operations.
type GuardConfig struct {
	// AllowedDirs restricts file operations to these directories.
	// If empty, file operations are disabled unless UnsafePaths is set.
	AllowedDirs []string

	// UnsafePaths allows file operations on any path.
	// Only effective when explicitly configured.
	UnsafePaths bool

	// AllowedHosts restricts tunnel/relay connections to these hosts.
	// If empty, all hosts are allowed (default).
	AllowedHosts []string

	// MaxFileSize is the maximum file size in bytes for transfers (0 = no limit).
	MaxFileSize int64
}

// DefaultGuardConfig returns a safe default configuration.
func DefaultGuardConfig() GuardConfig {
	return GuardConfig{
		AllowedDirs:  []string{"."},
		UnsafePaths:  false,
		AllowedHosts: nil, // all hosts allowed
		MaxFileSize:  0,   // no limit
	}
}

// ValidatePath checks that the given path is within allowed directories.
func (g GuardConfig) ValidatePath(path string) error {
	if g.UnsafePaths {
		return nil
	}

	abs, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("invalid path %q: %w", path, err)
	}

	// Check the file exists and is readable
	info, err := os.Stat(abs)
	if err != nil {
		return fmt.Errorf("path %q: %w", path, err)
	}

	// Check file size limit
	if g.MaxFileSize > 0 && info.Size() > g.MaxFileSize {
		return fmt.Errorf("file %q exceeds max size (%d > %d)", path, info.Size(), g.MaxFileSize)
	}

	for _, dir := range g.AllowedDirs {
		absDir, err := filepath.Abs(dir)
		if err != nil {
			continue
		}
		if strings.HasPrefix(abs, absDir) {
			return nil
		}
	}

	return fmt.Errorf("path %q is not in allowed directories %v", path, g.AllowedDirs)
}

// ValidateHost checks that the given host is allowed.
func (g GuardConfig) ValidateHost(host string) error {
	if len(g.AllowedHosts) == 0 {
		return nil // all hosts allowed
	}

	for _, allowed := range g.AllowedHosts {
		if host == allowed || strings.HasSuffix(host, ":"+allowed) {
			return nil
		}
	}

	return fmt.Errorf("host %q is not in allowed hosts list", host)
}

// SkipBinaryCheck is set when skink binary path is configured.
var SkipBinaryCheck bool

// FindSkinkBinary locates the skink binary.
func FindSkinkBinary() (string, error) {
	if SkipBinaryCheck {
		return "skink", nil
	}

	// Search PATH first — handles ~/.local/bin, /usr/bin, brew, nix, go install, etc.
	if path, err := exec.LookPath("skink"); err == nil {
		return path, nil
	}

	// Fall back to common locations for dev builds not yet in PATH.
	candidates := []string{
		"./skink",
		filepath.Join(os.Getenv("HOME"), "go", "bin", "skink"),
		filepath.Join(os.Getenv("HOME"), ".local", "bin", "skink"),
		"/usr/local/bin/skink",
		"/usr/bin/skink",
	}

	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c, nil
		}
	}

	return "", fmt.Errorf("skink binary not found — install it via 'make build' or add it to PATH")
}

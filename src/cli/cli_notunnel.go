//go:build notunnel

package cli

// This file disables tunnel commands when building with -tags notunnel.
// The tunnel subcommands (relay, tunnel, exec, noise-keygen) are
// conditionally not registered, producing a smaller binary for file transfer only.

import (
	"github.com/octagono/skink/src/models"
	"github.com/schollz/cli/v2"
)

func init() {
	// Override the tunnel-related commands added by cli.go
	// This is handled by the build tag conditional registration
}

// registerTunnelCommands is a no-op when building with notunnel tag.
func registerTunnelCommands(app *cli.App, commands *[]*cli.Command) {}

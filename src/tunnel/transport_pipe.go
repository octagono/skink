// Package tunnel provides named pipe transport for Windows lateral movement.
// On Windows, traffic goes over SMB named pipes (\\Server\pipe\skink-tunnel)
// instead of TCP, making it appear as normal Windows domain traffic.

package tunnel

import (
	"fmt"
	"net"
)

type PipeConfig struct {
	// PipeName is the name of the named pipe (e.g., "skink-tunnel").
	PipeName string
	// ServerAddr is the remote server address for client connections.
	// Format: "hostname" (uses \\hostname\pipe\name).
	ServerAddr string
}

func DefaultPipeConfig() PipeConfig {
	return PipeConfig{
		PipeName: "skink-tunnel",
	}
}

// pipeDialer is set by platform-specific init() to the appropriate dial function.
var pipeDialer func(addr, pipeName string) (net.Conn, error)

// pipeListener is set by platform-specific init() to the appropriate listen function.
var pipeListener func(pipeName string) (net.Listener, error)

// DialPipe connects to a named pipe on a remote server.
// This is a forward declaration — the actual implementation is platform-specific.
func DialPipe(addr, pipeName string) (net.Conn, error) {
	if pipeDialer == nil {
		return nil, fmt.Errorf("named pipe transport not supported on this platform")
	}
	return pipeDialer(addr, pipeName)
}

// ListenPipe creates a named pipe listener.
// This is a forward declaration — the actual implementation is platform-specific.
func ListenPipe(pipeName string) (net.Listener, error) {
	if pipeListener == nil {
		return nil, fmt.Errorf("named pipe transport not supported on this platform")
	}
	return pipeListener(pipeName)
}

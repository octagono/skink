//go:build windows
// +build windows

package tunnel

import (
	"fmt"
	"net"

	"github.com/Microsoft/go-winio"
	log "github.com/schollz/logger"
)

func init() {
	pipeDialer = windowsPipeDialer
	pipeListener = windowsPipeListener
}

// windowsPipeDialer connects to a named pipe on a remote server.
// Uses SMB to reach \\addr\pipe\pipeName.
func windowsPipeDialer(addr string, pipeName string) (net.Conn, error) {
	if pipeName == "" {
		pipeName = "skink-tunnel"
	}

	pipePath := fmt.Sprintf(`\\%s\pipe\%s`, addr, pipeName)
	log.Debugf("pipe dial: %s", pipePath)

	conn, err := winio.DialPipe(pipePath, nil)
	if err != nil {
		return nil, fmt.Errorf("dial pipe %s: %w", pipePath, err)
	}

	return conn, nil
}

// windowsPipeListener creates a named pipe listener.
func windowsPipeListener(pipeName string) (net.Listener, error) {
	if pipeName == "" {
		pipeName = "skink-tunnel"
	}

	pipePath := fmt.Sprintf(`\\.\pipe\%s`, pipeName)
	log.Infof("pipe listen: %s", pipePath)

	listener, err := winio.ListenPipe(pipePath, nil)
	if err != nil {
		return nil, fmt.Errorf("listen pipe %s: %w", pipePath, err)
	}

	return listener, nil
}

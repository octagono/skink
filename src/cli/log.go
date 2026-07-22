package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	log "github.com/schollz/logger"
)

// jsonLogWriter formats log output as newline-delimited JSON.
type jsonLogWriter struct {
	mu     sync.Mutex
	w      io.Writer
	prefix string
}

func (j *jsonLogWriter) Write(b []byte) (int, error) {
	j.mu.Lock()
	defer j.mu.Unlock()

	line := string(b)
	// Parse the existing log format: "[level]\tmessage"
	// Extract level and message
	level := "info"
	msg := strings.TrimSpace(line)

	// Detect level prefix
	switch {
	case strings.HasPrefix(line, "[trace]"):
		level = "trace"
		msg = strings.TrimSpace(line[7:])
	case strings.HasPrefix(line, "[debug]"):
		level = "debug"
		msg = strings.TrimSpace(line[7:])
	case strings.HasPrefix(line, "[info]"):
		level = "info"
		msg = strings.TrimSpace(line[6:])
	case strings.HasPrefix(line, "[warn]"):
		level = "warn"
		msg = strings.TrimSpace(line[6:])
	case strings.HasPrefix(line, "[error]"):
		level = "error"
		msg = strings.TrimSpace(line[7:])
	}

	// Remove file/line info (after the first space after timestamp)
	// The log format includes: "timestamp file:line message"
	// We want just the message part
	if idx := strings.Index(msg, " "); idx > 0 {
		after := strings.TrimSpace(msg[idx+1:])
		if after != "" {
			msg = after
		}
	}

	entry := map[string]interface{}{
		"level":     level,
		"message":   msg,
		"timestamp": time.Now().UTC().Format(time.RFC3339Nano),
		"app":       "skink",
	}

	data, err := json.Marshal(entry)
	if err != nil {
		return len(b), nil
	}

	data = append(data, '\n')
	_, err = j.w.Write(data)
	if err != nil {
		return 0, err
	}
	return len(b), nil
}

// SetJSONLogging enables JSON-structured log output.
// Pass "--log-format json" to the CLI to enable.
func SetJSONLogging() {
	w := &jsonLogWriter{
		w: os.Stderr,
	}
	log.SetOutput(w)
	fmt.Fprint(os.Stderr, `{"level":"info","message":"JSON logging enabled","app":"skink","timestamp":"`)
	fmt.Fprint(os.Stderr, time.Now().UTC().Format(time.RFC3339Nano))
	fmt.Fprintln(os.Stderr, `"}`)
}

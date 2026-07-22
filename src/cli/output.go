package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// Exit codes for semantic error signaling to AI agents and automation.
const (
	ExitCodeOK          = 0
	ExitCodeGeneral     = 1 // unexpected error
	ExitCodeAuth        = 2 // authentication/authorization failure
	ExitCodeNetwork     = 3 // network/connection error
	ExitCodeBadInput    = 4 // invalid input, missing file, bad flag
	ExitCodeTimeout     = 5 // operation timed out
	ExitCodeUnavailable = 6 // resource not found or unavailable
)

// ExitError carries a semantic exit code for agent-friendly error handling.
type ExitError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (e *ExitError) Error() string { return e.Message }

// ExitCode returns the exit code for the error.
func ExitCode(err error) int {
	if err == nil {
		return ExitCodeOK
	}
	if e, ok := err.(*ExitError); ok {
		return e.Code
	}
	// Classify common error patterns from the error string
	msg := err.Error()
	switch {
	case containsAny(msg, "authentication", "authorization", "password", "token", "auth", "unauthorized", "forbidden", "secret", "code phrase"):
		return ExitCodeAuth
	case containsAny(msg, "connection", "dial", "timeout", "refused", "network", "no route", "reset", "broken pipe", "EOF"):
		return ExitCodeNetwork
	case containsAny(msg, "not found", "no such file", "permission denied", "invalid", "bad", "required", "unsupported"):
		return ExitCodeBadInput
	default:
		return ExitCodeGeneral
	}
}

func containsAny(s string, substrs ...string) bool {
	for _, sub := range substrs {
		if strings.Contains(strings.ToLower(s), strings.ToLower(sub)) {
			return true
		}
	}
	return false
}

// JSONResult is the standard JSON envelope for all command output.
// Every command that supports --output json wraps its result in this struct.
type JSONResult struct {
	Status string      `json:"status"`          // "ok" or "error"
	Data   interface{} `json:"data,omitempty"`  // command-specific payload
	Error  *JSONError  `json:"error,omitempty"` // error details on failure
}

// JSONError carries structured error information.
type JSONError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// OutputResult writes a structured result. If outputFmt is "json", writes
// a JSON envelope to stdout. Otherwise, calls printFn for human-friendly output.
func OutputResult(outputFmt string, data interface{}, printFn func()) {
	if outputFmt == "json" {
		result := JSONResult{Status: "ok", Data: data}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "")
		enc.Encode(result)
		return
	}
	if printFn != nil {
		printFn()
	}
}

// OutputError writes a structured error. If outputFmt is "json", writes
// a JSON error envelope to stderr. Otherwise, prints the error message to stderr.
// Returns an ExitError with the appropriate exit code so the caller can os.Exit with it.
func OutputError(outputFmt string, err error, code int) error {
	if outputFmt == "json" {
		jsonErr := JSONResult{
			Status: "error",
			Error: &JSONError{
				Code:    code,
				Message: err.Error(),
			},
		}
		enc := json.NewEncoder(os.Stderr)
		enc.SetIndent("", "")
		enc.Encode(jsonErr)
	}
	return &ExitError{Code: code, Message: err.Error()}
}

// OutputVersion writes version info. Supports --json format.
func OutputVersion(version, commit, goVersion, buildDate string, outputFmt string) {
	data := map[string]string{
		"version":    version,
		"commit":     commit,
		"go_version": goVersion,
		"build_date": buildDate,
	}
	if outputFmt == "json" {
		result := JSONResult{Status: "ok", Data: data}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "")
		enc.Encode(result)
		return
	}
	fmt.Printf("Skink %s\n", version)
	if commit != "" {
		fmt.Printf("  commit:     %s\n", commit)
	}
	if goVersion != "" {
		fmt.Printf("  go:         %s\n", goVersion)
	}
	if buildDate != "" {
		fmt.Printf("  build date: %s\n", buildDate)
	}
}

// AgentDefaults returns a set of flag overrides for --agent mode.
// This reduces the flag boilerplate agents need to pass.
func AgentDefaults() map[string]interface{} {
	return map[string]interface{}{
		"quiet":      true,
		"log-format": "json",
		"yes":        true,
		"output":     "json",
	}
}

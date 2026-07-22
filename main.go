package main

//go:generate go run src/install/updateversion.go
//go:generate git commit -am "bump $VERSION"
//go:generate git tag -af v$VERSION -m "v$VERSION"

import (
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/octagono/skink/src/cli"
	"github.com/octagono/skink/src/utils"
)

func main() {
	// Create a channel to receive OS signals
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		if err := cli.Run(); err != nil {
			code := cli.ExitCode(err)
			// In agent mode, errors are already written as JSON by OutputError.
			// In text mode, print the error message.
			if code != cli.ExitCodeGeneral || !strings.HasPrefix(err.Error(), "{") {
				fmt.Fprintln(os.Stderr, err)
			}
			os.Exit(code)
		}
		// Exit the program gracefully
		utils.RemoveMarkedFiles()
		os.Exit(cli.ExitCodeOK)
	}()

	// Wait for a termination signal
	<-sigs
	utils.RemoveMarkedFiles()

	// Exit the program gracefully
	os.Exit(0)
}

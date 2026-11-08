package main

import (
	"fmt"
	"os"

	"bouclier/cmd"
	"bouclier/internal/cli"
)

func main() {
	if err := cmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(cli.ExitCode(err))
	}
}

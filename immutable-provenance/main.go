package main

import (
	"fmt"
	"os"

	"github.com/had-nu/immutable-provenance/cli"
)

func main() {
	if err := cli.RootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

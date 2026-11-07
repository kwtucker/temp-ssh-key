package main

import (
	"fmt"
	"os"

	"github.com/kwtucker/temp-ssh-key/internal/cli"
)

// version is set by GoReleaser with -X main.version=...
var version = "dev"

func main() {
	app := cli.NewApp(version)
	root := cli.NewRootCmd(app)
	if err := root.Execute(); err != nil {
		fmt.Fprintf(app.Err, "temp-ssh-key: %v\n", err)
		os.Exit(1)
	}
}

// Command f2b is fail2ban with an API, and an interface to it: the engine runs fail2ban beside
// the host's firewall, and the web serves the interface and signs people in.
package main

import (
	"os"
	"time"

	"f2b/internal/cli"
)

func main() {
	// Everything stored and logged is UTC.
	time.Local = time.UTC
	os.Exit(cli.Execute(os.Args[1:]))
}

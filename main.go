// devmux - create reverse tunnels to remote servers and proxy requests to local ports.
package main

import (
	"fmt"
	"os"
	"strings"
)

var pid = os.Getpid()

func warnf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "devmux: "+format+"\n", args...)
}

func removeStatus() {
	_ = os.Remove(statusFile(pid))
}

const usage = `Usage: devmux [-config FILE] [COMMAND [flags] [args]]

Reverse SSH tunnels: each one opens a loopback port on a remote host and
routes the HTTP requests that arrive there to local ports by path prefix.
With no command, a screen to switch tunnels and routes on and off and to
inspect the requests.

Commands:
  run [NAME...]                 serve the tunnels (all, or those named) with
                                no screen; requests printed to stdout
  ls [-json]                    tunnels in the config, and which are up where
  requests [-tunnel N] [-n 20] [-json]
                                latest requests, newest first
  request [-json] ID            one request and its response, in full
  route add TUNNEL PREFIX PORT  add a route to the config file
  route rm TUNNEL PREFIX        remove one; a running devmux reloads within 2 s

Every command takes -config FILE. Config: ./devmux_init.filo, else
%s
  (tunnel "dev" "my-vps" "10000"   ;; name, ~/.ssh/config alias or host, remote port
    (list (tuple "api" "3000")     ;; /api/... -> 127.0.0.1:3000/...
          (tuple "api/v1" "3001")));; the longest prefix wins

Requests are logged as JSON lines in %s.

Example: devmux run dev, then https://my-vps/api/users reaches 127.0.0.1:3000/users
`

func printUsage() {
	fmt.Printf(usage, defaultConfig(), logsDir())
}

func main() {
	args := os.Args[1:]
	name := ""
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		name, args = args[0], args[1:]
	}
	os.Exit(runCommand(name, args))
}

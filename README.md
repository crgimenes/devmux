# devmux - Development Multiplexer

[![Go Version](https://img.shields.io/badge/Go-1.27+-blue.svg)](https://golang.org/doc/install)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A powerful reverse tunnel proxy tool that creates secure tunnels to remote servers and intelligently routes HTTP requests to local development ports. Perfect for exposing multiple local services through a single remote endpoint.

## Features

- **Several tunnels at once**: each one is an SSH session to its own host that opens a loopback port there; switch tunnels and single routes on and off while it runs.
- **Path routing**: requests go to local ports by path prefix; the longest prefix wins and is stripped.
- **Request inspector**: a screen that lists the requests as they arrive and opens headers and bodies of the request and the response (JSON indented).
- **CLI for scripts and AI agents**: `devmux ls`, `devmux requests`, `devmux request ID`, with `-json`; a Claude Code skill ships in `skills/devmux`.
- **Reconnects on its own**: a dropped session comes back with backoff (1 s to 30 s).
- **SSH as you have it**: `~/.ssh/config`, ssh-agent, `known_hosts` checked.
- **Filo configuration**: [Filo](https://github.com/crgimenes/filo) scripting language.

## Installation

```bash
git clone https://github.com/crgimenes/devmux.git
cd devmux
go build -o devmux .
```

Requirements: Go 1.27 or higher, SSH access to a remote server, a key in
ssh-agent or an `IdentityFile`.

## Quick Start

1. Put the remote side's web server in front of the loopback port. Caddy
   (`/etc/caddy/Caddyfile`):

   ```
   server.example.com {
   	reverse_proxy 127.0.0.1:10000
   }
   ```

2. Declare the tunnel in `~/.config/devmux/init.filo` (or
   `./devmux_init.filo`, or any file with `-config FILE`):

   ```scheme
   ;; (tunnel NAME HOST REMOTE-PORT ROUTES)
   (tunnel "dev" "server.example.com" "10000"
     (list
       (tuple "api"    "3000")    ;; /api/...    -> 127.0.0.1:3000/...
       (tuple "api/v2" "3002")    ;; /api/v2/... -> 127.0.0.1:3002/...
       (tuple "web"    "8080")))  ;; /web/...    -> 127.0.0.1:8080/...
   ```

   `HOST` is an `~/.ssh/config` alias or a host name. Declare as many
   tunnels as you like; names must be unique. The older form with the
   `Host`, `RemotePort` and `Routes` globals is still read, as one tunnel
   named after its host.

3. Run `devmux` and press space on the tunnel, or serve it with no screen:

   ```bash
   devmux run dev
   ```

4. `https://server.example.com/api/users` now reaches `127.0.0.1:3000/users`.

## The screen

`devmux` with no command opens it. All tunnels start off.

| Screen | Keys |
|---|---|
| tunnels | space on/off, enter routes, r requests, q quit |
| routes of a tunnel | space switches the route (an off route answers 503), a adds, e or enter edits, d deletes (y confirms), r requests; shows whether something listens on each local port |
| requests | newest first, live; enter opens one |
| request | headers and bodies, ↑↓ PgUp PgDn to scroll; esc goes back |

Adding, editing and deleting a route writes the config file at once and
takes effect on the running tunnel. Only that tunnel's `(tunnel ...)` form is
rewritten, so comments inside it are lost; the rest of the file stays as it
was. A config in the older `Host`/`Routes` form is edited by hand.

Quitting closes the tunnels, waiting a few seconds for requests in flight.

## Command line

```
devmux ls [-json]                         tunnels, and which are up in which process
devmux requests [-tunnel N] [-n 20] [-json]
devmux request [-json] ID
devmux route add TUNNEL PREFIX PORT       add a route to the config file
devmux route rm TUNNEL PREFIX             remove one
devmux run [NAME...]                      all tunnels, or those named; requests on stdout
```

A running devmux (screen or `run`) checks the config file every 2 s and
reloads the routes when it changes, whether by `devmux route`, another
devmux or an editor. Tunnels added or removed in the file need a restart.

Every request is appended as one JSON line to
`~/.local/state/devmux/logs/<tunnel>-<date>.jsonl` (`$XDG_STATE_HOME` is
honoured), mode 0600: they hold headers, tokens included. Each running
devmux writes its tunnels' state to `~/.local/state/devmux/run/<pid>.json`,
which `devmux ls` reads. Bodies are kept up to 64 KiB in the log; what goes
to the service is never cut.

For Claude Code, link the skill:

```bash
ln -s "$PWD/skills/devmux" ~/.claude/skills/devmux
```

## SSH Configuration

devmux respects your SSH configuration and supports:

• **SSH Agent**: Automatic key discovery through SSH agent
• **SSH Config**: Uses `~/.ssh/config` for host-specific settings
• **Known Hosts**: Validates server identity using `~/.ssh/known_hosts`
• **Key Files**: Direct SSH key file specification

`Host` in the config is looked up in `~/.ssh/config`; without a matching
`Hostname` it is used as the host name itself, and the port defaults to 22.

### Example SSH Config

```ssh
Host your-server.com
    User your-username
    Port 22
    IdentityFile ~/.ssh/id_rsa
    ServerAliveInterval 60
    ServerAliveCountMax 3
```

## Troubleshooting

### Common Issues

#### Connection Refused

- Verify your SSH credentials and server access
- Check if the remote port is available and not blocked by firewall

#### Route Not Working

- Ensure your local service is running on the specified port
- Check that the route path matches your request URL

#### SSH Key Issues

- Verify your SSH key is added to the SSH agent: `ssh-add -l`
- Test SSH connection manually: `ssh your-server.com`

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Author

Created by [Cesar Gimenes](https://github.com/crgimenes)

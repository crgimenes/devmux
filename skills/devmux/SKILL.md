---
name: devmux
description: See the user's devmux reverse SSH tunnels (which are up, where, which routes are off) and read the HTTP requests that arrived through them — headers, bodies, status, timing — via the devmux CLI. Use whenever you need to know what a webhook, callback or remote client actually sent to a local service exposed by devmux, or whether a tunnel is up, instead of guessing or asking the user to copy logs. Opening a tunnel exposes local ports: only with the user's OK.
---

# devmux

devmux opens a loopback port on a remote host over SSH and routes the HTTP
requests that arrive there to local ports by path prefix (the longest
prefix wins and is stripped). Tunnels are declared in init.filo; the user
switches them on in the devmux screen (`devmux` with no command) or with
`devmux run`. Every request is logged as one JSON line, whichever process
served it, so you read them without touching the running process.

## Commands

```
devmux ls [-json]                        name;host;remote_port;state;pid(mode);routes;routes_off
devmux requests [-tunnel N] [-n 20] [-json]
                                         id;time;tunnel;method;url;status;ms, newest first
devmux request [-json] ID                one request and its response, in full
devmux route add TUNNEL PREFIX PORT      add a route to the config file
devmux route rm TUNNEL PREFIX            remove one
devmux run [NAME...]                     serve tunnels with no screen (blocks)
```

Every command takes `-config FILE`; flags go before the positional
arguments. Exit 0 success, 1 failure (message on stderr, `devmux: ...`),
2 usage error.

## How to use it as an agent

- Start with `devmux ls`: `state` is `up`, `connecting`, `retry` (with the
  error in `-json`) or `off`; `pid(mode)` says which process holds it
  (`screen` is the user's TUI, `run` a headless one).
- **Read requests with `-json`.** `devmux request -json ID` gives
  `request_headers`/`response_headers` (maps of lists), `request_body` and
  `response_body` as a string when the body is UTF-8 (JSON arrives as the
  text that was sent: parse it), or `{"base64": "..."}` when binary.
  `request_truncated`/`response_truncated` mean the body was cut at 64 KiB
  in the log (the service still got all of it). `url` is the path as it
  arrived, before the route prefix was stripped; `target` is the local
  service. `note` explains a refusal: `no route` (404) or `route is off`
  (503). Status 502 means the local service did not answer.
- The logs keep everything, headers included: `Authorization`, cookies
  and tokens are there. Quote only what the task needs, never a secret.
- You cannot switch a tunnel or route on or off in the user's screen; ask
  the user to do it there (space on the tunnel or route).
- **`route add` and `route rm` change the user's config file and, within
  2 s, every running devmux** (the screen included): a new route exposes
  that local port to the remote host. Run them only when the user asked for
  that route in this conversation, and say what you changed. They print the
  tunnel's routes after the change (`prefix=port,...`). `add` refuses a
  prefix that exists (exit 1): `rm` first to change its port. A config in
  the old `Host`/`Routes` form cannot be edited this way (exit 1).
- **`devmux run` exposes local ports to the remote host. Start it only
  when the user asked for that tunnel in this conversation**; run it in the
  background and stop it (SIGINT) when done. Two processes cannot open the
  same remote port: if `ls` shows the tunnel up, use it as it is.

## Examples

```bash
devmux ls
devmux requests -tunnel gauss -n 5
devmux request -json dmsniyviqif4
```

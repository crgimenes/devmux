# devmux - Development Multiplexer

[![Go Version](https://img.shields.io/badge/Go-1.24+-blue.svg)](https://golang.org/doc/install)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A powerful reverse tunnel proxy tool that creates secure tunnels to remote servers and intelligently routes HTTP requests to local development ports. Perfect for exposing multiple local services through a single remote endpoint.

## Features

• 🔒 **Secure SSH Tunneling**: Create encrypted reverse tunnels using SSH with key-based authentication
• 🔀 **Intelligent HTTP Routing**: Route requests to different local ports based on URL paths
• 🛠️ **Lua Configuration**: Flexible configuration system with Lua scripting support
• 📊 **Request Logging**: Detailed logging of HTTP requests with colored output for better debugging
• 🔑 **SSH Agent Support**: Seamless integration with SSH agent for key management
• 🌐 **Multi-Service Support**: Expose multiple local development services through one tunnel
• ⚡ **Keep-Alive**: Automatic connection maintenance to prevent tunnel timeouts

## Installation

### From Source

```bash
git clone https://github.com/crgimenes/devmux.git
cd devmux
go build -o devmux .
```

### Requirements

• Go 1.24 or higher
• SSH access to a remote server
• SSH key configured for authentication

## Quick Start

1. **Create your configuration file**:

   ```bash
   mkdir -p ~/.config/devmux
   ```

2. **Configure your routes** (`~/.config/devmux/init.lua`):

   ```lua
   Host       = "your-server.com"
   RemotePort = "10000"
   Routes     = {
       ["api"]     = "3000",  -- Routes /api to localhost:3000
       ["web"]     = "8080",  -- Routes /web to localhost:8080
       ["admin"]   = "9000",  -- Routes /admin to localhost:9000
   }
   ```

3. **Start the tunnel**:

   ```bash
   ./devmux
   ```

4. **Access your services**:
   - `http://your-server.com:10000/api` → `localhost:3000`
   - `http://your-server.com:10000/web` → `localhost:8080`
   - `http://your-server.com:10000/admin` → `localhost:9000`

## Configuration

devmux uses Lua for configuration, providing powerful customization options. The configuration file should be placed at `~/.config/devmux/init.lua` or as `devmux_init.lua` in your current directory.

### Basic Configuration

```lua
-- Remote server settings
Host = "your-remote-server.com"
RemotePort = "10000"

-- Route configuration
Routes = {
    ["api"] = "3000",      -- API service on port 3000
    ["web"] = "8080",      -- Web frontend on port 8080
    ["docs"] = "4000",     -- Documentation on port 4000
    ["metrics"] = "9090",  -- Monitoring on port 9090
}
```

### Route Patterns

Routes are defined as path prefixes that map to local ports:

```lua
Routes = {
    ["app"]        = "3000",  -- /app/* → localhost:3000/*
    ["api/v1"]     = "8001",  -- /api/v1/* → localhost:8001/*
    ["api/v2"]     = "8002",  -- /api/v2/* → localhost:8002/*
    ["static"]     = "8080",  -- /static/* → localhost:8080/*
    ["websocket"]  = "3001",  -- /websocket/* → localhost:3001/*
}
```

## How It Works

1. **SSH Tunnel Creation**: devmux establishes a reverse SSH tunnel to your remote server
2. **HTTP Proxy Server**: A local HTTP server captures incoming requests from the tunnel
3. **Route Matching**: Requests are analyzed and routed based on URL path prefixes
4. **Local Forwarding**: Matched requests are proxied to the corresponding local port
5. **Response Relay**: Responses are sent back through the tunnel to the client

## Use Cases

### Development Environment Exposure

Expose your local development stack to remote collaborators or testing environments:

```lua
Routes = {
    ["frontend"] = "3000",    -- React/Vue/Angular dev server
    ["backend"]  = "8000",    -- API server
    ["db-admin"] = "8080",    -- Database administration tool
}
```

### Microservices Development

Route different API paths to different microservices:

```lua
Routes = {
    ["auth"]     = "3001",    -- Authentication service
    ["users"]    = "3002",    -- User management service
    ["orders"]   = "3003",    -- Order processing service
    ["payments"] = "3004",    -- Payment service
}
```

### Demo and Testing

Share your work-in-progress with clients or stakeholders:

```lua
Routes = {
    ["demo"]     = "3000",    -- Demo application
    ["admin"]    = "3001",    -- Admin interface
    ["docs"]     = "4000",    -- Documentation site
}
```

## SSH Configuration

devmux respects your SSH configuration and supports:

• **SSH Agent**: Automatic key discovery through SSH agent
• **SSH Config**: Uses `~/.ssh/config` for host-specific settings
• **Known Hosts**: Validates server identity using `~/.ssh/known_hosts`
• **Key Files**: Direct SSH key file specification

### Example SSH Config

```ssh
Host your-server.com
    User your-username
    Port 22
    IdentityFile ~/.ssh/id_rsa
    ServerAliveInterval 60
    ServerAliveCountMax 3
```

## Logging and Debugging

devmux provides detailed request logging with color-coded output:

• **Green**: Successful request routing
• **Yellow**: Warning messages and connection events
• **Red**: Errors and failed requests
• **Blue**: Request details and headers
• **Cyan**: Response information

Example log output:

```text
[2025-08-02 10:30:15] 🔀 Routing: /api → localhost:3000
[2025-08-02 10:30:15] 📊 GET /api/users HTTP/1.1
[2025-08-02 10:30:15] ✅ Response: 200 OK (45ms)
```

## Security Features

• **SSH Encryption**: All traffic is encrypted through SSH tunnels
• **Key-Based Authentication**: No password authentication for enhanced security
• **Local Binding**: Proxy server only binds to localhost
• **Request Validation**: HTTP request parsing and validation
• **Connection Timeout**: Automatic cleanup of stale connections

## Advanced Configuration

### Custom Request Processing

```lua
-- Add custom headers or modify requests
function ProcessRequest(path, method, headers)
    -- Custom logic here
    return true  -- Continue processing
end

-- Custom response handling
function ProcessResponse(status, headers, body)
    -- Custom logic here
    return status, headers, body
end
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

### Debug Mode

Enable verbose logging by setting environment variables:

```bash
export DEBUG=1
./devmux
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Author

Created by [Cesar Gimenes](https://github.com/crgimenes)

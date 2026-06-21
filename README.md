# ServerKit Agent

A lightweight, cross-platform agent for remote server management. Connects to a ServerKit control plane to enable Docker management, system monitoring, and remote command execution.

## Features

- **Cross-Platform**: Supports Linux (amd64, arm64, arm), Windows (amd64, arm64), and macOS (amd64, arm64)
- **Lightweight**: Single binary, ~15MB RAM typical usage
- **Docker Integration**: Full Docker API access for container management
- **System Metrics**: Real-time CPU, memory, disk, and network monitoring
- **Secure Communication**: TLS encryption with HMAC-SHA256 authentication
- **Auto-Reconnect**: Automatic reconnection with exponential backoff
- **Self-Update**: Built-in auto-update with periodic version checks

## Quick Start

### Linux (One-liner)

```bash
curl -fsSL https://your-serverkit.com/install.sh | sudo bash -s -- \
  --token "sk_reg_your_token" \
  --server "https://your-serverkit.com"
```

### Windows (PowerShell as Administrator)

```powershell
irm https://your-serverkit.com/install.ps1 | iex
Install-ServerKitAgent -Token "sk_reg_your_token" -Server "https://your-serverkit.com"
```

> **Most Windows users should install the MSI instead** (see *Package
> Installation* below). The MSI registers the `ServerKitAgent` Windows service
> and opens a native pairing wizard right after install — no token handling and
> no browser required.

### Pairing (recommended)

Instead of baking a long registration token into an install command, you can
adopt an agent with a short, human-friendly code:

```bash
serverkit-agent pair --server "https://your-serverkit.com"
```

The agent generates an Ed25519 keypair, prints a short pairing code (and
passphrase), and waits. In the panel's **Add Server** screen, enter the code +
passphrase and verify the displayed key fingerprint to approve the device. On
Windows the MSI launches this wizard automatically. See the
[ServerKit pairing documentation](https://github.com/jhd3197/ServerKit/blob/main/docs/pairing.md)
for the full flow and security properties.

### Docker (Recommended for containerized environments)

```bash
# Pull the image
docker pull jhd3197/serverkit-agent:latest

# Register the agent (one-time setup)
docker run --rm -v serverkit-agent-config:/etc/serverkit-agent \
  jhd3197/serverkit-agent:latest register \
  --token "sk_reg_your_token" \
  --server "https://your-serverkit.com"

# Start the agent
docker run -d --name serverkit-agent \
  --restart unless-stopped \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  -v serverkit-agent-config:/etc/serverkit-agent \
  jhd3197/serverkit-agent:latest
```

Or use Docker Compose:

```bash
# Clone and navigate to the repo
git clone https://github.com/jhd3197/serverkit-agent.git
cd serverkit-agent

# Register (one-time setup)
docker compose run --rm agent register -s https://your-serverkit.com -t YOUR_TOKEN

# Start the agent
docker compose up -d

# View logs
docker compose logs -f
```

### Package Installation

**Debian/Ubuntu (.deb):**
```bash
curl -LO https://github.com/jhd3197/serverkit-agent/releases/latest/download/serverkit-agent_VERSION_amd64.deb
sudo dpkg -i serverkit-agent_VERSION_amd64.deb
sudo serverkit-agent register --token "YOUR_TOKEN" --server "https://your-serverkit.com"
sudo systemctl start serverkit-agent
```

**RHEL/CentOS/Fedora (.rpm):**
```bash
sudo rpm -i https://github.com/jhd3197/serverkit-agent/releases/latest/download/serverkit-agent-VERSION-1.x86_64.rpm
sudo serverkit-agent register --token "YOUR_TOKEN" --server "https://your-serverkit.com"
sudo systemctl start serverkit-agent
```

**Windows (.msi):**
Download and run the MSI installer from the releases page, then:
```powershell
serverkit-agent register --token "YOUR_TOKEN" --server "https://your-serverkit.com"
Start-Service ServerKitAgent
```

### Manual Installation

1. Download the appropriate binary for your platform from the releases page
2. Register the agent:
   ```bash
   ./serverkit-agent register --token "sk_reg_xxx" --server "https://your-serverkit.com"
   ```
3. Start the agent:
   ```bash
   ./serverkit-agent start
   ```

## Building from Source

### Prerequisites

- Go 1.23 or later (matches CI)
- Make (optional, for using Makefile)

### Build

```bash
# Clone the repository
git clone https://github.com/jhd3197/serverkit-agent.git
cd serverkit-agent

# Download dependencies
go mod download

# Build for current platform
make build

# Or build for all platforms
make build-all
```

### Build Outputs

Binaries are placed in the `dist/` directory:
- `serverkit-agent-{version}-linux-amd64`
- `serverkit-agent-{version}-linux-arm64`
- `serverkit-agent-{version}-windows-amd64.exe`
- `serverkit-agent-{version}-darwin-amd64`
- `serverkit-agent-{version}-darwin-arm64`

## Usage

### Commands

```
serverkit-agent [command]

Available Commands:
  start       Start the agent service
  register    Register with a ServerKit instance (pre-shared token)
  pair        Pair with a panel using a short code (recommended)
  setup       Run the guided setup wizard
  status      Show agent status
  config      Configuration management
  update      Check for and apply self-updates
  tray        Run the system-tray app (desktop)
  console     Open the desktop console (WebView2)
  version     Show version information
  help        Help about any command

Run with no command to launch the desktop app: the pairing wizard if the agent
is not yet configured, otherwise the system tray.

Flags:
  -c, --config string   config file path
  -d, --debug           enable debug logging
  -h, --help            help for serverkit-agent
```

### Register

```bash
serverkit-agent register \
  --token "sk_reg_xxx" \
  --server "https://your-serverkit.com" \
  --name "my-server"
```

### Start

```bash
# Foreground
serverkit-agent start

# With debug logging
serverkit-agent start --debug
```

## Configuration

Configuration file location:
- **Linux**: `/etc/serverkit-agent/config.yaml`
- **Windows**: `C:\ProgramData\ServerKit\Agent\config.yaml`

### Example Configuration

```yaml
server:
  url: wss://your-serverkit.com/agent/ws
  reconnect_interval: 5s
  max_reconnect_interval: 5m
  ping_interval: 30s

agent:
  id: "auto-generated"
  name: "my-server"

features:
  docker: true
  metrics: true
  logs: true
  file_access: false
  exec: false

metrics:
  enabled: true
  interval: 10s
  include_per_cpu: true
  include_docker_stats: true

docker:
  socket: /var/run/docker.sock
  timeout: 30s

logging:
  level: info
  file: /var/log/serverkit-agent/agent.log
  max_size_mb: 100
  max_backups: 5
  max_age_days: 30
  compress: true
```

## Security

### Authentication

The agent uses HMAC-SHA256 signatures for authentication:
1. During registration, the agent receives an API key and secret
2. Each WebSocket connection is authenticated using HMAC-signed messages
3. Session tokens are issued after successful authentication

### Credentials Storage

Credentials are encrypted at rest using AES-256-GCM with a **host-stable** key
derived from:
- Hostname
- Machine ID (Linux) / Computer name (Windows)

The key is deliberately **independent of the logged-in user**. On Windows this
lets the `LocalSystem` service decrypt credentials that were written during
user-context pairing. (Mixing in the Windows username broke exactly this and was
removed in 1.6.14.) Because the key is host-bound, a copied credential file
cannot be reused on another machine.

> **Treat `agent.key` as a host-equivalent secret.** Anyone who can read this
> file on the host (or recreate the host-derived key) can recover the agent's
> API credentials. Combined with remote command execution (see below), a leaked
> key file is equivalent to full control of that host.

### Network Security

- All communication uses TLS (WSS)
- Certificate validation is enforced in production
- Replay attack protection via timestamps and nonces

## Systemd Service (Linux)

The installation script automatically creates a systemd service:

```bash
# Check status
systemctl status serverkit-agent

# View logs
journalctl -u serverkit-agent -f

# Restart
systemctl restart serverkit-agent
```

## Windows Service & Desktop App

On Windows the agent has two cooperating parts:

**1. The background service** — a true Windows Service (`ServerKitAgent`)
registered through the Service Control Manager, running as `LocalSystem` and set
to start automatically. This is what stays connected to the panel.

```powershell
# Check status
Get-Service ServerKitAgent

# View logs
Get-Content "C:\ProgramData\ServerKit\Agent\logs\agent.log" -Tail 50

# Restart
Restart-Service ServerKitAgent
```

**2. The desktop app** — an optional per-user UI auto-started via the `HKCU\...\Run`
key:

- **Pairing/setup wizard** — runs after install (or on first launch) to adopt the
  agent into a panel.
- **System tray** — shows connection status and quick actions.
- **Desktop console** — a WebView2-hosted view of status, logs, activity, and
  actions (no external browser required).

> **Windows limitations to be aware of:** system metrics report a single volume
> (`C:\`), and the remote file browser currently lists the agent's working drive
> rather than enumerating all drives. Multi-drive support is tracked for a future
> release.

### Windows environment variables

| Variable | Purpose |
|----------|---------|
| `SERVERKIT_INSECURE_TLS` | Disable TLS certificate verification (**dev/testing only**) |
| `SERVERKIT_WS_COMPRESSION` | Enable WebSocket permessage-deflate (off by default; some tunnels corrupt compressed frames) |
| `SERVERKIT_AGENT_LEGACY_WIZARD` | Use the legacy native setup wizard instead of the WebView2 one |

## Docker Deployment

### Building the Image

```bash
# Build with version info
docker build \
  --build-arg VERSION=1.0.0 \
  --build-arg BUILD_TIME=$(date -u +"%Y-%m-%dT%H:%M:%SZ") \
  --build-arg GIT_COMMIT=$(git rev-parse --short HEAD) \
  -t jhd3197/serverkit-agent:latest .
```

### Running with Docker

```bash
# Register the agent first
docker run --rm \
  -v serverkit-agent-config:/etc/serverkit-agent \
  jhd3197/serverkit-agent:latest register \
  --token "sk_reg_xxx" \
  --server "https://your-serverkit.com" \
  --name "my-server"

# Run the agent
docker run -d \
  --name serverkit-agent \
  --restart unless-stopped \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  -v serverkit-agent-config:/etc/serverkit-agent \
  -v serverkit-agent-logs:/var/log/serverkit-agent \
  jhd3197/serverkit-agent:latest
```

### Running with Docker Compose

```yaml
# docker-compose.yml
services:
  agent:
    image: jhd3197/serverkit-agent:latest
    container_name: serverkit-agent
    restart: unless-stopped
    user: root
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - serverkit-config:/etc/serverkit-agent
      - serverkit-logs:/var/log/serverkit-agent
    environment:
      - TZ=UTC

volumes:
  serverkit-config:
  serverkit-logs:
```

```bash
# Register
docker compose run --rm agent register -s https://your-serverkit.com -t YOUR_TOKEN

# Start
docker compose up -d

# Logs
docker compose logs -f

# Stop
docker compose down
```

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `TZ` | Timezone | `UTC` |

### Volumes

| Path | Description |
|------|-------------|
| `/etc/serverkit-agent` | Configuration and credentials |
| `/var/log/serverkit-agent` | Log files |
| `/var/run/docker.sock` | Docker socket (mount read-only) |

## Development

### Project Structure

```
serverkit-agent/
├── cmd/agent/          # Main entry point (+ Windows service/console glue)
├── internal/
│   ├── agent/          # Core agent logic & command handlers
│   ├── agentui/        # Desktop console UI (WebView2)
│   ├── auth/           # HMAC authentication
│   ├── capabilities/   # Host capability probing
│   ├── cloudflared/    # Cloudflare tunnel management
│   ├── config/         # Configuration management
│   ├── cron/           # Remote cron management
│   ├── docker/         # Docker client wrapper
│   ├── ipc/            # Local IPC (desktop UI <-> agent)
│   ├── jobs/           # Background job runner
│   ├── logger/         # Structured logging
│   ├── metrics/        # System metrics collection
│   ├── pairing/        # Pairing client & keypair enrollment
│   ├── setupui/        # First-run setup wizard (Windows)
│   ├── terminal/       # Remote terminal sessions
│   ├── transport/      # WebSocket + HTTP-poll transports
│   ├── tray/           # System tray integration
│   ├── updater/        # Self-update mechanism
│   └── ws/             # WebSocket client
├── pkg/protocol/       # Message protocol (shared contract with the panel)
├── packaging/          # MSI / deb / rpm packaging
├── scripts/            # Build and install scripts
├── ui/                 # Agent desktop UI (React)
├── Makefile
└── go.mod
```

### Running Tests

```bash
make test
```

### Code Formatting

```bash
make fmt
```

## Troubleshooting

### Agent won't connect

1. Check the server URL is correct
2. Verify the registration token is valid
3. Check firewall allows outbound WebSocket connections
4. Review logs: `journalctl -u serverkit-agent -n 50`

### Docker commands fail

1. Ensure Docker is installed and running
2. Verify the agent user has Docker permissions:
   ```bash
   sudo usermod -aG docker serverkit-agent
   ```
3. Check Docker socket permissions

### High CPU/Memory usage

1. Increase the metrics interval in config
2. Disable per-CPU metrics if not needed
3. Check for log rotation issues

## License

MIT License - see LICENSE file for details.

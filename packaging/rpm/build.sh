#!/bin/bash
# Build .rpm package for ServerKit Agent
# Usage: ./build.sh <version> <architecture> <binary_path> <output_dir>
# Example: ./build.sh 1.0.0 x86_64 ../../dist/serverkit-agent-linux-amd64 ./packages

set -e

VERSION="${1:-1.0.0}"
ARCH="${2:-x86_64}"
BINARY_PATH="${3:-../../dist/serverkit-agent-linux-amd64}"
PACKAGE_NAME="serverkit-agent"

# Convert paths to absolute before any cd commands
BINARY_PATH="$(cd "$(dirname "$BINARY_PATH")" && pwd)/$(basename "$BINARY_PATH")"
OUTPUT_DIR="${4:-./output}"
mkdir -p "$OUTPUT_DIR"
OUTPUT_DIR="$(cd "$OUTPUT_DIR" && pwd)"

# Map Go arch to RPM arch
case "$ARCH" in
    amd64) RPM_ARCH="x86_64" ;;
    arm64) RPM_ARCH="aarch64" ;;
    *) RPM_ARCH="$ARCH" ;;
esac

echo "Building .rpm package..."
echo "  Version: $VERSION"
echo "  Architecture: $RPM_ARCH"
echo "  Binary: $BINARY_PATH"
echo "  Output: $OUTPUT_DIR"

# Create build directory structure
BUILD_ROOT="$(mktemp -d)"
mkdir -p "$BUILD_ROOT"/{BUILD,RPMS,SOURCES,SPECS,SRPMS}

# Create source tarball
SOURCE_DIR="$BUILD_ROOT/SOURCES/serverkit-agent-$VERSION"
mkdir -p "$SOURCE_DIR"

# Copy binary
cp "$BINARY_PATH" "$SOURCE_DIR/serverkit-agent"

# Create systemd service file
cat > "$SOURCE_DIR/serverkit-agent.service" << EOF
[Unit]
Description=ServerKit Agent
Documentation=https://github.com/jhd3197/serverkit-agent
After=network-online.target docker.service
Wants=network-online.target
Requires=docker.service

[Service]
Type=simple
User=serverkit-agent
Group=serverkit-agent
ExecStart=/usr/local/bin/serverkit-agent start
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=serverkit-agent

# Security hardening — run as a dedicated unprivileged account, matching the
# script installer (agent/scripts/install.sh). In this mode the agent cannot
# overwrite its own root-owned binary, so self-update is disabled and updates
# flow through the OS package manager (dnf/yum) instead — the signature-checked
# path. systemd/package-management handlers need root; if you require them,
# deliberately run as root or configure passwordless sudo for this account.
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ReadWritePaths=/etc/serverkit-agent /var/log/serverkit-agent /var/lib/serverkit /var/serverkit
# \`register\` is usually run via sudo (as root), so the credential files it
# writes can end up root-owned and unreadable by this service account. Fix
# ownership at start regardless of how the operator registered. The leading
# '+' runs this step as root even though the service drops to User= above.
ExecStartPre=+/usr/bin/chown -R serverkit-agent:serverkit-agent /etc/serverkit-agent

[Install]
WantedBy=multi-user.target
EOF

# Create default config file
cat > "$SOURCE_DIR/config.yaml" << EOF
# ServerKit Agent Configuration
# This file is created during installation.
# Run 'serverkit-agent register' to configure the agent.

server:
  url: ""
  reconnect_interval: 5s
  max_reconnect_interval: 5m
  ping_interval: 30s

agent:
  id: ""
  name: ""

features:
  docker: true
  metrics: true
  logs: true
  file_access: false
  exec: false

metrics:
  enabled: true
  interval: 10s

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
EOF

# Create tarball
cd "$BUILD_ROOT/SOURCES"
tar -czvf "serverkit-agent-$VERSION.tar.gz" "serverkit-agent-$VERSION"
rm -rf "serverkit-agent-$VERSION"

# Create spec file
cat > "$BUILD_ROOT/SPECS/serverkit-agent.spec" << EOF
Name:           serverkit-agent
Version:        $VERSION
Release:        1%{?dist}
Summary:        ServerKit Agent - Remote server management agent

License:        MIT
URL:            https://github.com/jhd3197/serverkit-agent
Source0:        serverkit-agent-%{version}.tar.gz

Requires:       ca-certificates

%description
ServerKit Agent connects your server to a ServerKit control plane,
enabling remote Docker management, monitoring, and more.

Features:
- Docker container management
- System metrics collection
- Secure WebSocket communication
- Auto-reconnect with exponential backoff

%prep
%setup -q

%install
rm -rf %{buildroot}

# Install binary
install -D -m 755 serverkit-agent %{buildroot}/usr/local/bin/serverkit-agent

# Install systemd service
install -D -m 644 serverkit-agent.service %{buildroot}/usr/lib/systemd/system/serverkit-agent.service

# Install config directory and default config
install -D -m 644 config.yaml %{buildroot}/etc/serverkit-agent/config.yaml

# Create log directory
install -d -m 755 %{buildroot}/var/log/serverkit-agent

%files
%attr(755, root, root) /usr/local/bin/serverkit-agent
%attr(644, root, root) /usr/lib/systemd/system/serverkit-agent.service
%config(noreplace) %attr(640, serverkit-agent, serverkit-agent) /etc/serverkit-agent/config.yaml
%dir %attr(750, serverkit-agent, serverkit-agent) /etc/serverkit-agent
%dir %attr(750, serverkit-agent, serverkit-agent) /var/log/serverkit-agent

%pre
# Create the dedicated, unprivileged service account before files are laid
# down so the %files ownership attrs resolve. Idempotent across upgrades.
getent group serverkit-agent >/dev/null || groupadd --system serverkit-agent
getent passwd serverkit-agent >/dev/null || \
    useradd --system --gid serverkit-agent --no-create-home --shell /sbin/nologin serverkit-agent

%post
%systemd_post serverkit-agent.service

# Let the agent reach the Docker socket without root.
if getent group docker >/dev/null; then
    usermod -aG docker serverkit-agent || true
fi

# State/data dirs the agent writes to, owned by the service account. Also
# re-chown the config dir so an existing root-owned agent.key (previous root
# install, or \`sudo register\`) becomes readable by the unprivileged service.
mkdir -p /var/lib/serverkit/apps /var/serverkit/apps /var/log/serverkit-agent
chown -R serverkit-agent:serverkit-agent \
    /var/lib/serverkit /var/serverkit /var/log/serverkit-agent /etc/serverkit-agent 2>/dev/null || true

echo ""
echo "ServerKit Agent installed successfully!"
echo ""
echo "To complete setup:"
echo "  1. Register the agent (runs as the service account):"
echo "     sudo -u serverkit-agent serverkit-agent register --token YOUR_TOKEN --server https://your-serverkit.com"
echo ""
echo "  2. Start the service:"
echo "     sudo systemctl start serverkit-agent"
echo ""
echo "  3. Check status:"
echo "     sudo systemctl status serverkit-agent"
echo ""

%preun
%systemd_preun serverkit-agent.service

%postun
%systemd_postun_with_restart serverkit-agent.service

if [ \$1 -eq 0 ]; then
    # Complete uninstall - remove config and logs
    rm -rf /etc/serverkit-agent 2>/dev/null || true
    rm -rf /var/log/serverkit-agent 2>/dev/null || true
fi

%changelog
* $(date '+%a %b %d %Y') ServerKit <support@serverkit.dev> - $VERSION-1
- Release $VERSION
EOF

# Build the RPM (disable build-id for Go binaries, use --target for cross-arch)
rpmbuild --define "_topdir $BUILD_ROOT" --define "_build_id_links none" --target "$RPM_ARCH" -bb "$BUILD_ROOT/SPECS/serverkit-agent.spec"

# Copy output
cp "$BUILD_ROOT/RPMS/$RPM_ARCH"/*.rpm "$OUTPUT_DIR/"

# Cleanup
rm -rf "$BUILD_ROOT"

echo ""
echo "Package built successfully!"
echo "Output: $OUTPUT_DIR/"
ls -la "$OUTPUT_DIR"/*.rpm

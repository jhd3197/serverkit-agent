# ServerKit Agent Changelog

All notable changes to the **ServerKit agent** are documented here.

The agent is versioned and released independently from the ServerKit control
panel. Release builds are produced by the `Agent Release` workflow and tagged
`vX.Y.Z`; each tag publishes Linux (amd64/arm64) binaries + `.deb`/`.rpm`,
Windows (x64/arm64) `.msi` installers, and a multi-arch Docker image.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

Substantial work has landed since the last tagged release (`v1.0.4`) and is
awaiting the next release cut. Highlights:

### Added

- **Native Windows experience** — Windows service host, native first-run setup
  wizard, system tray, dark-mode aware UI, and an MSI installer that opens the
  pairing wizard right after install (no browser or external WebView2 runtime
  required). ARM64 Windows builds included.
- **Desktop console UI** — embedded React UI (`agent/ui`) served over local IPC
  for status, logs, activity, and actions.
- **Pairing flows** — short-code and passphrase pairing with keypair enrollment
  and the `sk1` connection-string format.
- **Dual transport** — Socket.IO/WebSocket primary transport with automatic,
  permanent fallback to HTTP polling when the WebSocket connection flaps.
- **Remote operations** — handlers for files, packages, services, cron, sudo,
  Docker (incl. extra ops), Cloudflare tunnels, runtime management, and streamed
  job progress.
- **Capability probing** — host capability detection reported to the panel and
  re-sent on a periodic cadence; system info pushed and persisted.
- **Self-update** — built-in updater with periodic version checks.

### Fixed

- Stopped dropping capability/system-info payloads on transient `/poll` failures.
- Resolved silent failures around empty logs, dead WebSocket connections, and
  locked-out agents.
- Windows builds use the `-H=windowsgui` subsystem so Start-menu launches no
  longer flash a stray console window; CLI subcommands still re-hook stdio when
  run from a real terminal.
- Pinned the Go toolchain to 1.23 for CI compatibility; fixed Docker and MSI
  (WiX v5) builds in the release workflow.

## [1.0.4] - 2026-03-28
## [1.0.3] - 2026-03-24
## [1.0.2] - 2026-03-03
## [1.0.1] - 2026-01-24
## [1.0.0] - 2026-01-24

Initial tagged agent releases: cross-platform Go agent with HMAC-SHA256
authentication, Docker integration, system metrics, and auto-reconnect, plus the
multi-platform release pipeline (binaries, `.deb`/`.rpm`, MSI, Docker).

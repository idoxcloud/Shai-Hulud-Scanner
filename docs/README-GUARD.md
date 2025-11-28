# Shai-Hulud Guard

**Cross-platform system-level protection against npm supply chain attacks**

## Overview

Shai-Hulud Guard is a lightweight, zero-dependency binary that enforces secure npm registry usage by:
- ✅ Blocking access to public npm registry (registry.npmjs.org)
- ✅ Redirecting all npm traffic to internal Nexus registry (VPN required)
- ✅ System-level enforcement via hosts file modification
- ✅ Works on Linux, macOS, and Windows

## Features

- **Zero external dependencies** - Uses only Go standard library
- **Static binary** - Single executable, no runtime required
- **Cross-platform** - Linux, macOS (Intel/ARM), Windows
- **VPN validation** - Ensures developers are connected to corporate VPN
- **Reversible** - Easy uninstall with full restoration

## Installation

### Download Pre-built Binaries

Download the appropriate binary for your platform from the releases page:
- **Linux**: `shai-hulud-guard-linux-amd64`
- **macOS Intel**: `shai-hulud-guard-darwin-amd64`
- **macOS Apple Silicon**: `shai-hulud-guard-darwin-arm64`
- **Windows**: `shai-hulud-guard-windows-amd64.exe`

### Build from Source

```bash
# Clone repository
git clone git@github.com:idoxcloud/Shai-Hulud-Scanner.git
cd Shai-Hulud-Scanner

# Build all platforms
make build

# Or build for current platform only
make quick
```

## Usage

### Install Protection

**Linux/macOS:**
```bash
sudo ./shai-hulud-guard --install
```

**Windows (run as Administrator):**
```powershell
.\shai-hulud-guard.exe --install
```

This will:
1. Backup your current hosts file
2. Block registry.npmjs.org via hosts file
3. Configure npm to use internal Nexus registry
4. Verify VPN connectivity

### Check Status

```bash
sudo ./shai-hulud-guard --status
```

Output:
```
Shai-Hulud Guard Status:
═══════════════════════════
  ✓ npm public registry blocked
  ✓ npm configured for Nexus
  ✓ VPN connectivity

✓ Protection is ACTIVE
```

### Uninstall Protection

```bash
sudo ./shai-hulud-guard --uninstall
```

This will:
1. Restore original hosts file from backup
2. Reset npm registry configuration
3. Remove all modifications

### Scan for Threats

```bash
sudo ./shai-hulud-guard --scan
```

## How It Works

### 1. Hosts File Blocking

Adds entries to system hosts file:
```
# SHAI-HULUD-GUARD-START
127.0.0.1 registry.npmjs.org
127.0.0.1 registry.npmjs.com
127.0.0.1 npm.pkg.github.com
# SHAI-HULUD-GUARD-END
```

**Locations:**
- Linux/macOS: `/etc/hosts`
- Windows: `C:\Windows\System32\drivers\etc\hosts`

### 2. NPM Configuration

Updates global npm config:
```bash
npm config set registry https://infra.gla.eim.idoxgroup.local/nexus/repository/npm-public --location=global
```

Also creates system-level `.npmrc`:
- Linux: `/etc/npmrc`
- Windows: `C:\ProgramData\npm\npmrc`

### 3. VPN Validation

Checks connectivity to internal Nexus:
1. DNS resolution of `infra.gla.eim.idoxgroup.local`
2. HTTP connection test to Nexus

## Requirements

- **Privileges**: Must run with sudo/administrator
- **VPN**: Required for access to internal Nexus registry
- **npm**: Must be installed on the system

## Security

- **No external dependencies**: Only Go stdlib - reduced attack surface
- **Static binary**: No dynamic linking, no runtime dependencies
- **Backup & restore**: All changes are reversible
- **Transparent**: All modifications are clearly marked

## Troubleshooting

### "This tool must be run with sudo"
Run with elevated privileges:
```bash
sudo ./shai-hulud-guard --install
```

### "VPN check failed"
Ensure you're connected to corporate VPN before running install.

### npm install still tries public registry
1. Check status: `sudo ./shai-hulud-guard --status`
2. Verify hosts file contains Shai-Hulud entries
3. Re-run install: `sudo ./shai-hulud-guard --install`

## Development

### Build

```bash
make build          # All platforms
make quick          # Current platform only
make build-linux    # Linux only
make build-darwin   # macOS only
make build-windows  # Windows only
```

### Project Structure

```
cmd/shai-hulud-guard/
├── main.go          # Entry point and CLI
├── hosts.go         # Hosts file manipulation
├── npm.go           # npm configuration
├── vpn.go           # VPN connectivity checks
├── admin_unix.go    # Unix privilege checks
└── admin_windows.go # Windows privilege checks
```

## License

See LICENSE file.

## Related

- [Shai-Hulud Scanner](./README.md) - Bash-based detection scanner for Shai-Hulud malware

# Scanner Scripts

This directory contains the legacy detection scripts for the Shai-Hulud malware scanner.

## Scripts

### `Check-ShaiHulud-Dynamic.ps1`
PowerShell scanner for Windows environments.

### `Check-ShaiHulud-Dynamic.sh`
Bash scanner for Linux/macOS/WSL environments.

### `Check-ShaiHulud-Dynamic-macOS.sh`
Enhanced Bash scanner optimized for macOS with additional categorization features.

### `s3-bucket-scanner.sh`
S3 bucket scanner that downloads and scans npm packages from S3 storage.

## Recommended Usage

**For new deployments, use the Go-based CLI tool instead:**

```bash
# Install protection
sudo shai-hulud-guard --install

# Check status
sudo shai-hulud-guard --status

# Scan for threats (coming soon)
sudo shai-hulud-guard --scan
```

See the main [README.md](../README.md) and [README-GUARD.md](../README-GUARD.md) for more information.

## Caching Behavior

The scanner scripts automatically cache compromised package lists in the system temp directory:
- **Unix/Linux/macOS**: `${TMPDIR:-/tmp}/shai-hulud-scanner-cache/`
- **Windows**: `%TEMP%\shai-hulud-scanner-cache\`

Cache is refreshed automatically every 24 hours when the scanner runs. If network fetch fails, stale cache data will be used with a warning.

These scripts are maintained for compatibility but the Go CLI tool (`shai-hulud-guard`) is the recommended approach for new installations.

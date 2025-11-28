# Certificate Setup for Nexus Registry

The `shai-hulud-guard` tool automatically configures SSL/TLS certificates for npm to communicate with the internal Nexus registry.

## Automatic Certificate Configuration

When you run `shai-hulud-guard --install`, the tool will:

1. Detect your operating system
2. Find or create an appropriate CA certificate bundle
3. Configure npm to use the certificate bundle via `npm config set cafile`

## OS-Specific Behavior

### macOS

The tool automatically extracts certificates from the System Keychain:

```bash
security find-certificate -a -p /Library/Keychains/System.keychain > ~/.npm-block-certs.pem
npm config set cafile ~/.npm-block-certs.pem --location=global
```

The certificate bundle is created at: `~/.npm-block-certs.pem`

### Linux

The tool auto-detects your distribution's CA bundle:

- **Debian/Ubuntu**: `/etc/ssl/certs/ca-certificates.crt`
- **RedHat/CentOS (7.x)**: `/etc/pki/tls/certs/ca-bundle.crt`
- **RedHat/CentOS (8+)**: `/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem`
- **Arch Linux**: `/etc/ca-certificates/extracted/tls-ca-bundle.pem`

### Windows

**Currently requires manual setup:**

1. Open Certificate Manager: `certmgr.msc`
2. Navigate to: Trusted Root Certification Authorities → Certificates
3. Export all certificates:
   - Right-click → All Tasks → Export
   - Choose "Base-64 encoded X.509 (.CER)"
   - Save to: `%USERPROFILE%\.npm-block-certs.pem`
4. Run `shai-hulud-guard --install` again

## VPN Connectivity Verification

The tool uses **Node.js** as the primary verification method:

```javascript
node -e "require('https').get('https://infra.gla.eim.idoxgroup.local/nexus/repository/npm-public/', res=>console.log('ok')).on('error',e=>console.error(e))"
```

This ensures the verification uses the **same SSL/TLS stack as npm**, providing accurate connectivity testing.

If Node.js is not installed, the tool falls back to Go's HTTP client.

## Manual Certificate Configuration

If automatic configuration fails, you can set it up manually:

### Option 1: npm config

```bash
npm config set cafile "<path-to-cert-bundle>" --location=global
```

### Option 2: Environment Variable

```bash
export NODE_EXTRA_CA_CERTS=<path-to-cert-bundle>
```

Add to your `.bashrc`, `.zshrc`, or equivalent for persistence.

**Note**: Running `nvm` may reset the `NODE_EXTRA_CA_CERTS` environment variable.

## Verification

Check if certificates are configured:

```bash
npm config get cafile
```

Should output the path to your certificate bundle.

## Troubleshooting

### Certificate Not Found

**Error**: `no CA certificate bundle found in standard locations`

**Solution**: Your distribution may use a non-standard path. Find your CA bundle:

```bash
# Linux
find /etc -name "ca-certificates.crt" -o -name "ca-bundle.crt" 2>/dev/null

# macOS
security find-certificate -a -p /Library/Keychains/System.keychain > ~/custom-certs.pem
npm config set cafile ~/custom-certs.pem --location=global
```

### SSL/TLS Errors

**Error**: `unable to get local issuer certificate`

**Causes**:
1. Certificate bundle is outdated
2. Internal CA certificate not in bundle
3. VPN not connected

**Solution**:
1. Ensure VPN is connected
2. Regenerate certificate bundle (macOS):
   ```bash
   rm ~/.npm-block-certs.pem
   shai-hulud-guard --install
   ```
3. Contact IT to ensure internal CA is in System Keychain (macOS) or system trust store (Linux)

### Node.js Not Found

The tool will warn but continue using Go HTTP client. For best results:

```bash
# macOS
brew install node

# Debian/Ubuntu
sudo apt install nodejs npm

# RedHat/CentOS
sudo yum install nodejs npm
```

## Removal

Running `shai-hulud-guard --uninstall` will:
1. Remove the npm `cafile` configuration
2. Delete the certificate bundle (if created)
3. Restore npm to default configuration

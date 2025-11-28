package main

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"
)

// SystemVPNChecker implements VPNChecker for real VPN connectivity checks
type SystemVPNChecker struct {
	DryRun bool
}

// Verify implements VPNChecker.Verify
func (c *SystemVPNChecker) Verify() error {
	if c.DryRun {
		fmt.Println("  [DRY RUN] Would verify VPN connection")
		host := "infra.gla.eim.idoxgroup.local"
		fmt.Printf("    • Target host: %s\n", host)
		fmt.Printf("    • Nexus URL: %s\n", NexusURL)
		if isNodeInstalled() {
			fmt.Println("    • Would use Node.js for verification (preferred)")
		} else {
			fmt.Println("    • Node.js not available, would use Go HTTP client")
		}
		return nil
	}
	return verifyVPNConnection()
}

// IsConnected implements VPNChecker.IsConnected
func (c *SystemVPNChecker) IsConnected() bool {
	if c.DryRun {
		return false
	}
	return isVPNConnected()
}

func verifyVPNConnection() error {
host := "infra.gla.eim.idoxgroup.local"

fmt.Printf("  Checking VPN connectivity to %s...\n", host)

// Try Node.js verification first if available
if isNodeInstalled() {
	if err := verifyVPNWithNode(); err == nil {
		fmt.Println("  ✓ VPN connection verified via Node.js")
		return nil
	}
	fmt.Println("  ⚠ Node.js verification failed, falling back to Go HTTP client")
}

addrs, err := net.LookupHost(host)
if err != nil {
return fmt.Errorf("DNS resolution failed (VPN likely not connected): %w", err)
}

fmt.Printf("  ✓ DNS resolved to: %v\n", addrs)

client := &http.Client{
Timeout: 5 * time.Second,
}

resp, err := client.Get(NexusURL)
if err != nil {
return fmt.Errorf("HTTP connection failed: %w", err)
}
defer resp.Body.Close()

fmt.Printf("  ✓ HTTP connection successful (status: %d)\n", resp.StatusCode)
return nil
}

func isVPNConnected() bool {
	err := verifyVPNConnection()
	return err == nil
}

// isNodeInstalled checks if Node.js is available
func isNodeInstalled() bool {
	cmd := exec.Command("node", "--version")
	return cmd.Run() == nil
}

// verifyVPNWithNode uses Node.js to verify Nexus connectivity
// This is the preferred method as it uses the same SSL/TLS stack as npm
func verifyVPNWithNode() error {
	script := fmt.Sprintf(
		"require('https').get('%s', res=>{console.log('ok');process.exit(0)}).on('error',e=>{console.error(e.message);process.exit(1)})",
		NexusURL,
	)

	cmd := exec.Command("node", "-e", script)
	
	// Set NODE_EXTRA_CA_CERTS to use our certificate bundle
	// Note: npm config cafile doesn't affect Node.js HTTPS requests directly
	certMgr := &SystemCertificateManager{}
	if certPath, err := certMgr.GetCertBundle(); err == nil {
		cmd.Env = append(os.Environ(), fmt.Sprintf("NODE_EXTRA_CA_CERTS=%s", certPath))
	}
	
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("Node.js verification failed: %w (output: %s)", err, strings.TrimSpace(string(output)))
	}

	if !strings.Contains(string(output), "ok") {
		return fmt.Errorf("unexpected output from Node.js: %s", strings.TrimSpace(string(output)))
	}

	return nil
}

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const (
	hostsMarkerStart = "# SHAI-HULUD-GUARD-START"
	hostsMarkerEnd   = "# SHAI-HULUD-GUARD-END"
	backupSuffix     = ".npm-block.backup"
)

var blockedHosts = []string{
	"registry.npmjs.org",
	"registry.npmjs.com",
	"npm.pkg.github.com",
}

// SystemHostsManager implements HostsFileManager for real system modifications
type SystemHostsManager struct {
	DryRun bool
}

// Block implements HostsFileManager.Block
func (m *SystemHostsManager) Block() error {
	if m.DryRun {
		fmt.Println("  [DRY RUN] Would block npm registry in hosts file")
		hostsPath := getHostsFilePath()
		backupPath := hostsPath + backupSuffix
		fmt.Printf("    • Hosts file: %s\\n", hostsPath)
		fmt.Printf("    • Backup will be created at: %s\\n", backupPath)
		fmt.Printf("    • Will add entries for: %v\\n", blockedHosts)
		return nil
	}
	return blockNPMRegistry()
}

// Restore implements HostsFileManager.Restore
func (m *SystemHostsManager) Restore() error {
	if m.DryRun {
		hostsPath := getHostsFilePath()
		backupPath := hostsPath + backupSuffix
		fmt.Println("  [DRY RUN] Would restore hosts file from backup")
		fmt.Printf("    • Backup location: %s\\n", backupPath)
		if _, err := os.Stat(backupPath); os.IsNotExist(err) {
			fmt.Println("    • Will remove Shai-Hulud entries (no backup found)")
		} else {
			fmt.Printf("    • Will restore from: %s\\n", backupPath)
		}
		return nil
	}
	return restoreHostsFile()
}

// IsBlocked implements HostsFileManager.IsBlocked
func (m *SystemHostsManager) IsBlocked() bool {
	return isNPMRegistryBlocked()
}

// GetBackupPath implements HostsFileManager.GetBackupPath
func (m *SystemHostsManager) GetBackupPath() string {
	return getHostsFilePath() + backupSuffix
}

func getHostsFilePath() string {
if runtime.GOOS == "windows" {
return filepath.Join(os.Getenv("SystemRoot"), "System32", "drivers", "etc", "hosts")
}
return "/etc/hosts"
}

func blockNPMRegistry() error {
	hostsPath := getHostsFilePath()
	backupPath := hostsPath + backupSuffix

	// Check if backup exists before attempting to create it
	backupExists := false
	if _, err := os.Stat(backupPath); err == nil {
		backupExists = true
	}

	if err := backupFile(hostsPath, backupPath); err != nil {
		return fmt.Errorf("backup failed: %w", err)
	}

	content, err := os.ReadFile(hostsPath)
	if err != nil {
		return fmt.Errorf("read failed: %w", err)
	}

	if strings.Contains(string(content), hostsMarkerStart) {
		fmt.Println("  npm registry is already blocked in hosts file")
		if backupExists {
			fmt.Printf("  ℹ Your original hosts file is preserved at: %s\n", backupPath)
		}
		return nil
	}

	var blockLines []string
	blockLines = append(blockLines, "", hostsMarkerStart)
	blockLines = append(blockLines, fmt.Sprintf("# Added by Shai-Hulud Guard on %s", time.Now().Format(time.RFC3339)))
	blockLines = append(blockLines, "# Blocks npm public registry to prevent supply chain attacks")
	for _, host := range blockedHosts {
		blockLines = append(blockLines, fmt.Sprintf("127.0.0.1 %s", host))
	}
	blockLines = append(blockLines, hostsMarkerEnd, "")

	f, err := os.OpenFile(hostsPath, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("open for append failed: %w", err)
	}
	defer f.Close()

	for _, line := range blockLines {
		if _, err := f.WriteString(line + "\n"); err != nil {
			return fmt.Errorf("write failed: %w", err)
		}
	}

	fmt.Println("  ✓ npm registry blocked in hosts file")
	return nil
}

func restoreHostsFile() error {
hostsPath := getHostsFilePath()
backupPath := hostsPath + backupSuffix

if _, err := os.Stat(backupPath); os.IsNotExist(err) {
return removeHostsEntries(hostsPath)
}

if err := os.Rename(backupPath, hostsPath); err != nil {
return fmt.Errorf("restore failed: %w", err)
}

fmt.Println("  ✓ hosts file restored from backup")
return nil
}

func removeHostsEntries(hostsPath string) error {
content, err := os.ReadFile(hostsPath)
if err != nil {
return err
}

lines := strings.Split(string(content), "\n")
var filtered []string
inBlock := false

for _, line := range lines {
if strings.Contains(line, hostsMarkerStart) {
inBlock = true
continue
}
if strings.Contains(line, hostsMarkerEnd) {
inBlock = false
continue
}
if !inBlock {
filtered = append(filtered, line)
}
}

if err := os.WriteFile(hostsPath, []byte(strings.Join(filtered, "\n")), 0644); err != nil {
return err
}

fmt.Println("  ✓ Shai-Hulud entries removed from hosts file")
return nil
}

func isNPMRegistryBlocked() bool {
hostsPath := getHostsFilePath()
content, err := os.ReadFile(hostsPath)
if err != nil {
return false
}
return strings.Contains(string(content), hostsMarkerStart)
}

func backupFile(src, dst string) error {
	// If backup already exists, don't overwrite it - preserve the original
	if _, err := os.Stat(dst); err == nil {
		fmt.Printf("  ℹ Backup already exists at %s (preserving original)\n", dst)
		return nil
	}

	input, err := os.ReadFile(src)
	if err != nil {
		return err
	}

	if err := os.WriteFile(dst, input, 0644); err != nil {
		return err
	}

	fmt.Printf("  ✓ Backup created at %s\n", dst)
	return nil
}
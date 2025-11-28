package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
)

// runScanner executes the embedded scanner script for the current OS
// It extracts the script to a temporary file, makes it executable, and runs it
func runScanner(args []string) error {
	var script string
	var ext string
	var shell string
	var shellArgs []string

	// Select the appropriate script and shell based on OS
	switch runtime.GOOS {
	case "linux":
		script = scriptLinux
		ext = ".sh"
		shell = "/bin/bash"
		shellArgs = []string{"-c"}
	case "darwin":
		script = scriptDarwin
		ext = ".sh"
		shell = "/bin/bash"
		shellArgs = []string{"-c"}
	case "windows":
		script = scriptWindows
		ext = ".ps1"
		shell = "powershell.exe"
		shellArgs = []string{"-ExecutionPolicy", "Bypass", "-File"}
	default:
		return fmt.Errorf("unsupported operating system: %s", runtime.GOOS)
	}

	// Create a temporary file for the script
	tmpDir := os.TempDir()
	scriptPath := filepath.Join(tmpDir, "shai-hulud-scanner"+ext)

	// Write the script to the temp file
	if err := os.WriteFile(scriptPath, []byte(script), 0755); err != nil {
		return fmt.Errorf("failed to write script: %w", err)
	}

	// Clean up the temp file when done
	defer os.Remove(scriptPath)

	// Build the command
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		// For Windows PowerShell
		cmdArgs := append(shellArgs, scriptPath)
		cmdArgs = append(cmdArgs, args...)
		cmd = exec.Command(shell, cmdArgs...)
	} else {
		// For Unix-like systems (Linux, macOS)
		// Build a single command string with the script path and all arguments
		cmdLine := scriptPath
		for _, arg := range args {
			// Simple shell escaping - wrap in single quotes and escape existing single quotes
			escapedArg := "'" + shellEscape(arg) + "'"
			cmdLine += " " + escapedArg
		}
		cmd = exec.Command(shell, append(shellArgs, cmdLine)...)
	}

	// Set up standard streams
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin

	// Run the script
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("scanner failed: %w", err)
	}

	return nil
}

// shellEscape escapes a string for use in shell commands
func shellEscape(s string) string {
	// Replace single quotes with '\''
	result := ""
	for _, c := range s {
		if c == '\'' {
			result += "'\\''"
		} else {
			result += string(c)
		}
	}
	return result
}

// runS3Scanner executes the embedded S3 scanner script
// It extracts the script to a temporary file, makes it executable, and runs it
func runS3Scanner(args []string) error {
	if runtime.GOOS == "windows" {
		return fmt.Errorf("S3 scanner is only supported on Linux and macOS")
	}

	// Create a temporary file for the script
	tmpDir := os.TempDir()
	scriptPath := filepath.Join(tmpDir, "shai-hulud-s3-scanner.sh")

	// Write the script to the temp file
	if err := os.WriteFile(scriptPath, []byte(scriptS3Scanner), 0755); err != nil {
		return fmt.Errorf("failed to write S3 scanner script: %w", err)
	}

	// Clean up the temp file when done
	defer os.Remove(scriptPath)

	// Set PROJECT_ROOT environment variable to the temp directory
	// so the S3 scanner can find the resources
	env := os.Environ()
	env = append(env, fmt.Sprintf("PROJECT_ROOT=%s", filepath.Dir(scriptPath)))

	// Build the command with arguments
	cmdArgs := []string{scriptPath}
	cmdArgs = append(cmdArgs, args...)

	cmd := exec.Command("/bin/bash", cmdArgs...)
	cmd.Env = env

	// Set up standard streams
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin

	// Run the script
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("S3 scanner failed: %w", err)
	}

	return nil
}

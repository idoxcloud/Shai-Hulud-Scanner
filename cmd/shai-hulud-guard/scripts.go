package main

import (
	_ "embed"
)

// Embedded scanner scripts for different operating systems
// These scripts are bundled into the binary at compile time

//go:embed scripts/Check-ShaiHulud-Dynamic.sh
var scriptLinux string

//go:embed scripts/Check-ShaiHulud-Dynamic-macOS.sh
var scriptDarwin string

//go:embed scripts/Check-ShaiHulud-Dynamic.ps1
var scriptWindows string

//go:embed scripts/s3-bucket-scanner.sh
var scriptS3Scanner string

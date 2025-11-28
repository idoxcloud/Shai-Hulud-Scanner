//go:build windows
// +build windows

package main

import (
"syscall"
)

var (
shell32           = syscall.NewLazyDLL("shell32.dll")
procIsUserAnAdmin = shell32.NewProc("IsUserAnAdmin")
)

func isWindowsAdmin() bool {
ret, _, _ := procIsUserAnAdmin.Call()
return ret != 0
}

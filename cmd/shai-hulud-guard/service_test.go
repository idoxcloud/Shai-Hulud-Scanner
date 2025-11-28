package main

import (
	"errors"
	"testing"
)

func TestProtectionService_Install_Success(t *testing.T) {
	hosts := &MockHostsManager{IsBlockedVal: false}
	npm := &MockNPMManager{IsConfiguredVal: false}
	vpn := &MockVPNChecker{IsConnectedVal: true}
	cert := &MockCertificateManager{GetCertBundleResult: "/tmp/test-certs.pem"}
	
	service := NewMockProtectionService(hosts, npm, vpn, cert, false)
	
	err := service.Install()
	if err != nil {
		t.Errorf("Install() failed: %v", err)
	}
	
	if !hosts.BlockCalled {
		t.Error("Block() was not called on hosts manager")
	}
	
	if !npm.ConfigureCalled {
		t.Error("Configure() was not called on npm manager")
	}
}

func TestProtectionService_Install_HostsBlockFailure(t *testing.T) {
	hosts := &MockHostsManager{BlockErr: errors.New("block failed")}
	npm := &MockNPMManager{}
	vpn := &MockVPNChecker{}
	cert := &MockCertificateManager{}
	
	service := NewMockProtectionService(hosts, npm, vpn, cert, false)
	
	err := service.Install()
	if err == nil {
		t.Error("Expected error when hosts block fails")
	}
	
	if npm.ConfigureCalled {
		t.Error("Configure() should not be called when hosts block fails")
	}
}

func TestProtectionService_Install_DryRun(t *testing.T) {
	hosts := &MockHostsManager{}
	npm := &MockNPMManager{}
	vpn := &MockVPNChecker{}
	cert := &MockCertificateManager{}
	
	service := NewMockProtectionService(hosts, npm, vpn, cert, true)
	
	err := service.Install()
	if err != nil {
		t.Errorf("DryRun Install() failed: %v", err)
	}
	
	// In dry-run mode, methods are called but BlockCalled/ConfigureCalled flags should NOT be set
	if hosts.BlockCalled {
		t.Error("Block() flag should not be set in dry-run mode")
	}
	
	if npm.ConfigureCalled {
		t.Error("Configure() flag should not be set in dry-run mode")
	}
}

func TestProtectionService_Uninstall_Success(t *testing.T) {
	hosts := &MockHostsManager{IsBlockedVal: true}
	npm := &MockNPMManager{IsConfiguredVal: true}
	vpn := &MockVPNChecker{}
	cert := &MockCertificateManager{}
	
	service := NewMockProtectionService(hosts, npm, vpn, cert, false)
	
	err := service.Uninstall()
	if err != nil {
		t.Errorf("Uninstall() failed: %v", err)
	}
	
	if !hosts.RestoreCalled {
		t.Error("Restore() was not called on hosts manager")
	}
	
	if !npm.RestoreCalled {
		t.Error("Restore() was not called on npm manager")
	}
}

func TestProtectionService_Uninstall_DryRun(t *testing.T) {
	hosts := &MockHostsManager{IsBlockedVal: true}
	npm := &MockNPMManager{IsConfiguredVal: true}
	vpn := &MockVPNChecker{}
	cert := &MockCertificateManager{}
	
	service := NewMockProtectionService(hosts, npm, vpn, cert, true)
	
	err := service.Uninstall()
	if err != nil {
		t.Errorf("DryRun Uninstall() failed: %v", err)
	}
	
	// In dry-run mode, methods are called but RestoreCalled flags should NOT be set
	if hosts.RestoreCalled {
		t.Error("Restore() flag should not be set in dry-run mode")
	}
	
	if npm.RestoreCalled {
		t.Error("Restore() flag should not be set in dry-run mode")
	}
}

func TestProtectionService_Status(t *testing.T) {
	tests := []struct {
		name              string
		hostsBlocked      bool
		npmConfigured     bool
		vpnConnected      bool
	}{
		{"All active", true, true, true},
		{"Hosts only", true, false, false},
		{"NPM only", false, true, false},
		{"None active", false, false, false},
		{"All but VPN", true, true, false},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hosts := &MockHostsManager{IsBlockedVal: tt.hostsBlocked}
			npm := &MockNPMManager{IsConfiguredVal: tt.npmConfigured}
			vpn := &MockVPNChecker{IsConnectedVal: tt.vpnConnected}
			cert := &MockCertificateManager{}
			
			service := NewMockProtectionService(hosts, npm, vpn, cert, false)
			
			blocked, configured, connected := service.Status()
			
			if blocked != tt.hostsBlocked {
				t.Errorf("Expected blocked=%v, got %v", tt.hostsBlocked, blocked)
			}
			if configured != tt.npmConfigured {
				t.Errorf("Expected configured=%v, got %v", tt.npmConfigured, configured)
			}
			if connected != tt.vpnConnected {
				t.Errorf("Expected connected=%v, got %v", tt.vpnConnected, connected)
			}
		})
	}
}

func TestHostsManager_GetBackupPath(t *testing.T) {
	manager := &SystemHostsManager{}
	path := manager.GetBackupPath()
	
	if path == "" {
		t.Error("GetBackupPath() returned empty string")
	}
	
	if !contains(path, ".npm-block.backup") {
		t.Errorf("Backup path should contain '.npm-block.backup', got: %s", path)
	}
}

func TestMockHostsManager_GetBackupPath(t *testing.T) {
	manager := &MockHostsManager{BackupPath: "/custom/backup/path"}
	path := manager.GetBackupPath()
	
	if path != "/custom/backup/path" {
		t.Errorf("Expected custom backup path, got: %s", path)
	}
}

func TestMockHostsManager_DefaultBackupPath(t *testing.T) {
	manager := &MockHostsManager{}
	path := manager.GetBackupPath()
	
	if path != "/tmp/test-hosts.backup" {
		t.Errorf("Expected default test backup path, got: %s", path)
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr) && findSubstring(s, substr))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

package main

// MockHostsManager is a mock implementation for testing
type MockHostsManager struct {
	BlockCalled   bool
	RestoreCalled bool
	BlockErr      error
	RestoreErr    error
	IsBlockedVal  bool
	BackupPath    string
	DryRun        bool
}

func (m *MockHostsManager) Block() error {
	if !m.DryRun {
		m.BlockCalled = true
	}
	return m.BlockErr
}

func (m *MockHostsManager) Restore() error {
	if !m.DryRun {
		m.RestoreCalled = true
	}
	return m.RestoreErr
}

func (m *MockHostsManager) IsBlocked() bool {
	return m.IsBlockedVal
}

func (m *MockHostsManager) GetBackupPath() string {
	if m.BackupPath != "" {
		return m.BackupPath
	}
	return "/tmp/test-hosts.backup"
}

// MockNPMManager is a mock implementation for testing
type MockNPMManager struct {
	ConfigureCalled bool
	RestoreCalled   bool
	ConfigureErr    error
	RestoreErr      error
	IsConfiguredVal bool
	DryRun          bool
}

func (m *MockNPMManager) Configure() error {
	if !m.DryRun {
		m.ConfigureCalled = true
	}
	return m.ConfigureErr
}

func (m *MockNPMManager) Restore() error {
	if !m.DryRun {
		m.RestoreCalled = true
	}
	return m.RestoreErr
}

func (m *MockNPMManager) IsConfigured() bool {
	return m.IsConfiguredVal
}

// MockVPNChecker is a mock implementation for testing
type MockVPNChecker struct {
	VerifyErr      error
	IsConnectedVal bool
	DryRun         bool
}

func (m *MockVPNChecker) Verify() error {
	return m.VerifyErr
}

func (m *MockVPNChecker) IsConnected() bool {
	if m.DryRun {
		return false
	}
	return m.IsConnectedVal
}

// MockCertificateManager is a mock implementation for testing
type MockCertificateManager struct {
	GetCertBundleResult string
	GetCertBundleErr    error
	CreateCertBundleResult string
	CreateCertBundleErr error
}

func (m *MockCertificateManager) GetCertBundle() (string, error) {
	return m.GetCertBundleResult, m.GetCertBundleErr
}

func (m *MockCertificateManager) CreateCertBundle() (string, error) {
	return m.CreateCertBundleResult, m.CreateCertBundleErr
}

// NewMockProtectionService creates a test service with mocks
func NewMockProtectionService(hostsManager *MockHostsManager, npmManager *MockNPMManager, vpnChecker *MockVPNChecker, certManager *MockCertificateManager, dryRun bool) *ProtectionService {
	hostsManager.DryRun = dryRun
	npmManager.DryRun = dryRun
	vpnChecker.DryRun = dryRun
	return &ProtectionService{
		HostsManager: hostsManager,
		NPMManager:   npmManager,
		VPNChecker:   vpnChecker,
		CertManager:  certManager,
		DryRun:       dryRun,
	}
}

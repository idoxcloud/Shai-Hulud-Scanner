package main

// HostsFileManager defines the interface for managing hosts file entries
type HostsFileManager interface {
	Block() error
	Restore() error
	IsBlocked() bool
	GetBackupPath() string
}

// NPMConfigManager defines the interface for managing npm configuration
type NPMConfigManager interface {
	Configure() error
	Restore() error
	IsConfigured() bool
}

// VPNChecker defines the interface for verifying VPN connectivity
type VPNChecker interface {
	Verify() error
	IsConnected() bool
}

// PrivilegeChecker defines the interface for checking admin/root privileges
type PrivilegeChecker interface {
	IsAdmin() bool
}

// ProtectionService orchestrates the protection installation/removal
type ProtectionService struct {
	HostsManager HostsFileManager
	NPMManager   NPMConfigManager
	VPNChecker   VPNChecker
	CertManager  CertificateManager
	DryRun       bool
}

// NewProtectionService creates a new protection service with real implementations
func NewProtectionService(dryRun bool) *ProtectionService {
	return &ProtectionService{
		HostsManager: &SystemHostsManager{DryRun: dryRun},
		NPMManager:   &SystemNPMManager{DryRun: dryRun},
		VPNChecker:   &SystemVPNChecker{DryRun: dryRun},
		CertManager:  &SystemCertificateManager{},
		DryRun:       dryRun,
	}
}

// Install performs the complete protection installation
func (s *ProtectionService) Install() error {
	if s.DryRun {
		println("\n=== DRY RUN MODE - No changes will be made ===")
	}
	
	println("\nStep 1: Blocking npm registry in hosts file")
	if err := s.HostsManager.Block(); err != nil {
		return err
	}
	
	println("\nStep 2: Configuring npm to use internal registry")
	if err := s.NPMManager.Configure(); err != nil {
		return err
	}
	
	println("\nStep 3: Verifying VPN connectivity")
	if err := s.VPNChecker.Verify(); err != nil {
		// VPN check is a warning, not a failure
		println("  ⚠ Warning: VPN verification failed but continuing...")
	}
	
	if s.DryRun {
		println("\n=== DRY RUN COMPLETE - No changes were made ===")
	}
	return nil
}

// Uninstall removes all protection modifications
func (s *ProtectionService) Uninstall() error {
	if s.DryRun {
		println("\n=== DRY RUN MODE - No changes will be made ===")
	}
	
	println("\nStep 1: Restoring hosts file from backup")
	if err := s.HostsManager.Restore(); err != nil {
		return err
	}
	
	println("\nStep 2: Restoring npm configuration")
	if err := s.NPMManager.Restore(); err != nil {
		return err
	}
	
	if s.DryRun {
		println("\n=== DRY RUN COMPLETE - No changes were made ===")
	}
	return nil
}

// Status returns the current protection status
func (s *ProtectionService) Status() (blocked, configured, vpnConnected bool) {
	return s.HostsManager.IsBlocked(), s.NPMManager.IsConfigured(), s.VPNChecker.IsConnected()
}



package sharemount

import (
	"testing"
)

func TestExtractRemoteHost(t *testing.T) {
	tests := []struct {
		name   string
		source string
		fsType string
		want   string
	}{
		{
			name:   "cifs_ip",
			source: "//192.168.1.10/share",
			fsType: "cifs",
			want:   "192.168.1.10",
		},
		{
			name:   "cifs_hostname",
			source: "//fileserver.corp.local/documents",
			fsType: "cifs",
			want:   "fileserver.corp.local",
		},
		{
			name:   "smbfs_ip",
			source: "//10.0.0.5/public",
			fsType: "smbfs",
			want:   "10.0.0.5",
		},
		{
			name:   "nfs_ip",
			source: "192.168.1.20:/export/data",
			fsType: "nfs",
			want:   "192.168.1.20",
		},
		{
			name:   "nfs4_hostname",
			source: "nfsserver.local:/var/nfs/shared",
			fsType: "nfs4",
			want:   "nfsserver.local",
		},
		{
			name:   "nfs_no_colon",
			source: "192.168.1.20",
			fsType: "nfs",
			want:   "192.168.1.20",
		},
		{
			name:   "cifs_bare_host",
			source: "//myhost",
			fsType: "cifs",
			want:   "myhost",
		},
		{
			name:   "unknown_fstype",
			source: "something",
			fsType: "ext4",
			want:   "something",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractRemoteHost(tt.source, tt.fsType)
			if got != tt.want {
				t.Errorf("extractRemoteHost(%q, %q): got %q, want %q", tt.source, tt.fsType, got, tt.want)
			}
		})
	}
}

func TestNetworkFSTypesFiltering(t *testing.T) {
	// Verify which filesystem types are considered network shares.
	networkTypes := []string{"cifs", "nfs", "nfs4", "smbfs"}
	for _, fsType := range networkTypes {
		if !networkFSTypes[fsType] {
			t.Errorf("expected %q to be a network FS type", fsType)
		}
	}

	nonNetworkTypes := []string{"ext4", "tmpfs", "proc", "sysfs", "devtmpfs", "xfs", "btrfs"}
	for _, fsType := range nonNetworkTypes {
		if networkFSTypes[fsType] {
			t.Errorf("expected %q to NOT be a network FS type", fsType)
		}
	}
}

func TestMountLineParsing(t *testing.T) {
	// Simulate the parsing logic from readNetworkMounts using synthetic lines.
	lines := []struct {
		line       string
		wantParsed bool
		wantFSType string
		wantHost   string
		wantMount  string
	}{
		{
			line:       "//192.168.1.10/share /mnt/share cifs username=admin,password=secret 0 0",
			wantParsed: true,
			wantFSType: "cifs",
			wantHost:   "192.168.1.10",
			wantMount:  "/mnt/share",
		},
		{
			line:       "nfsserver:/export /mnt/nfs nfs rw,vers=4 0 0",
			wantParsed: true,
			wantFSType: "nfs",
			wantHost:   "nfsserver",
			wantMount:  "/mnt/nfs",
		},
		{
			line:       "server.local:/data /mnt/data nfs4 rw,sec=krb5 0 0",
			wantParsed: true,
			wantFSType: "nfs4",
			wantHost:   "server.local",
			wantMount:  "/mnt/data",
		},
		{
			line:       "/dev/sda1 / ext4 rw,relatime 0 1",
			wantParsed: false,
		},
		{
			line:       "tmpfs /tmp tmpfs rw,nosuid,nodev 0 0",
			wantParsed: false,
		},
		{
			line:       "proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0",
			wantParsed: false,
		},
		{
			line:       "short line",
			wantParsed: false,
		},
	}

	for _, tt := range lines {
		t.Run(tt.line, func(t *testing.T) {
			fields := splitFields(tt.line)
			if len(fields) < 4 {
				if tt.wantParsed {
					t.Error("expected line to be parsed but too few fields")
				}
				return
			}
			fsType := fields[2]
			isNetwork := networkFSTypes[fsType]

			if isNetwork != tt.wantParsed {
				t.Errorf("isNetwork: got %v, want %v", isNetwork, tt.wantParsed)
				return
			}
			if !isNetwork {
				return
			}

			source := fields[0]
			mountPoint := fields[1]
			host := extractRemoteHost(source, fsType)

			if fsType != tt.wantFSType {
				t.Errorf("fsType: got %q, want %q", fsType, tt.wantFSType)
			}
			if host != tt.wantHost {
				t.Errorf("host: got %q, want %q", host, tt.wantHost)
			}
			if mountPoint != tt.wantMount {
				t.Errorf("mountPoint: got %q, want %q", mountPoint, tt.wantMount)
			}
		})
	}
}

func TestMountDiffing(t *testing.T) {
	baseline := map[string]mountInfo{
		"/mnt/share": {Source: "//192.168.1.10/share", MountPoint: "/mnt/share", FSType: "cifs"},
	}
	current := map[string]mountInfo{
		"/mnt/share": {Source: "//192.168.1.10/share", MountPoint: "/mnt/share", FSType: "cifs"},
		"/mnt/nfs":   {Source: "nfsserver:/export", MountPoint: "/mnt/nfs", FSType: "nfs"},
	}

	// New mounts.
	var newMounts []string
	for mp := range current {
		if _, existed := baseline[mp]; !existed {
			newMounts = append(newMounts, mp)
		}
	}
	if len(newMounts) != 1 || newMounts[0] != "/mnt/nfs" {
		t.Errorf("expected new mount '/mnt/nfs', got %v", newMounts)
	}

	// Removed mounts.
	baseline2 := map[string]mountInfo{
		"/mnt/old": {Source: "//10.0.0.1/old", MountPoint: "/mnt/old", FSType: "cifs"},
	}
	current2 := map[string]mountInfo{}
	var removedMounts []string
	for mp := range baseline2 {
		if _, exists := current2[mp]; !exists {
			removedMounts = append(removedMounts, mp)
		}
	}
	if len(removedMounts) != 1 || removedMounts[0] != "/mnt/old" {
		t.Errorf("expected removed mount '/mnt/old', got %v", removedMounts)
	}
}

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if !cfg.Enabled {
		t.Error("expected Enabled=true")
	}
	if cfg.PollIntervalS != 10 {
		t.Errorf("expected PollIntervalS=10, got %d", cfg.PollIntervalS)
	}
}

// splitFields is a test helper that replicates strings.Fields behavior.
func splitFields(s string) []string {
	var fields []string
	field := ""
	for _, c := range s {
		if c == ' ' || c == '\t' {
			if field != "" {
				fields = append(fields, field)
				field = ""
			}
		} else {
			field += string(c)
		}
	}
	if field != "" {
		fields = append(fields, field)
	}
	return fields
}

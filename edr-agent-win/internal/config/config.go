// internal/config/config.go
// YAML configuration loader — Windows paths and monitor defaults.

package config

import (
	"fmt"
	"os"

	"github.com/spf13/viper"
)

type Config struct {
	Agent       AgentConfig       `mapstructure:"agent"`
	Monitors    MonitorsConfig    `mapstructure:"monitors"`
	Buffer      BufferConfig      `mapstructure:"buffer"`
	Log         LogConfig         `mapstructure:"log"`
	SelfProtect SelfProtectConfig `mapstructure:"self_protect"`
}

type AgentConfig struct {
	ID         string    `mapstructure:"id"`
	IDFile     string    `mapstructure:"id_file"`
	Hostname   string    `mapstructure:"hostname"`
	BackendURL string    `mapstructure:"backend_url"`
	TLS        TLSConfig `mapstructure:"tls"`
	Tags       []string  `mapstructure:"tags"`
	Env        string    `mapstructure:"env"`
	Notes      string    `mapstructure:"notes"`
}

type TLSConfig struct {
	Cert     string `mapstructure:"cert"`
	Key      string `mapstructure:"key"`
	CA       string `mapstructure:"ca"`
	Insecure bool   `mapstructure:"insecure"`
}

type MonitorsConfig struct {
	Process  ProcessMonitorConfig  `mapstructure:"process"`
	Network  NetworkMonitorConfig  `mapstructure:"network"`
	File     FileMonitorConfig     `mapstructure:"file"`
	Registry RegistryMonitorConfig `mapstructure:"registry"`
	DNS      DNSMonitorConfig      `mapstructure:"dns"`
	Auth     AuthMonitorConfig     `mapstructure:"auth"`
	Command  CommandMonitorConfig  `mapstructure:"command"`
	Browser  BrowserMonitorConfig  `mapstructure:"browser"`
	Driver   DriverMonitorConfig   `mapstructure:"driver"`
	USB      USBMonitorConfig      `mapstructure:"usb"`
	Pipe     PipeMonitorConfig     `mapstructure:"pipe"`
	Share    ShareMonitorConfig    `mapstructure:"share"`
	MemMon   MemMonConfig          `mapstructure:"memmon"`
	SchTask  SchTaskMonitorConfig  `mapstructure:"schtask"`
	TLSSNI   TLSSNIConfig          `mapstructure:"tlssni"`
	FIM      FIMConfig             `mapstructure:"fim"`
	Vuln     VulnMonitorConfig     `mapstructure:"vuln"`
}

type ProcessMonitorConfig struct {
	Enabled          bool     `mapstructure:"enabled"`
	MaxAncestryDepth int      `mapstructure:"max_ancestry_depth"`
	CaptureEnv       bool     `mapstructure:"capture_env"`
	SuspiciousParents []string `mapstructure:"suspicious_parents"`
}

type NetworkMonitorConfig struct {
	Enabled         bool     `mapstructure:"enabled"`
	IgnoreLocalhost bool     `mapstructure:"ignore_localhost"`
	WatchedPorts    []uint16 `mapstructure:"watched_ports"`
}

type FileMonitorConfig struct {
	Enabled     bool     `mapstructure:"enabled"`
	WatchPaths  []string `mapstructure:"watch_paths"`
	HashOnWrite bool     `mapstructure:"hash_on_write"`
}

type RegistryMonitorConfig struct {
	Enabled    bool     `mapstructure:"enabled"`
	ExtraKeys  []string `mapstructure:"extra_keys"`
}

type DNSMonitorConfig struct {
	Enabled bool `mapstructure:"enabled"`
}

type AuthMonitorConfig struct {
	Enabled bool `mapstructure:"enabled"`
}

type CommandMonitorConfig struct {
	Enabled bool `mapstructure:"enabled"`
}

type BrowserMonitorConfig struct {
	Enabled    bool   `mapstructure:"enabled"`
	ListenAddr string `mapstructure:"listen_addr"`
}

type DriverMonitorConfig struct {
	Enabled       bool `mapstructure:"enabled"`
	PollIntervalS int  `mapstructure:"poll_interval_s"`
}

type USBMonitorConfig struct {
	Enabled       bool `mapstructure:"enabled"`
	PollIntervalS int  `mapstructure:"poll_interval_s"`
}

type PipeMonitorConfig struct {
	Enabled       bool `mapstructure:"enabled"`
	PollIntervalS int  `mapstructure:"poll_interval_s"`
}

type ShareMonitorConfig struct {
	Enabled       bool `mapstructure:"enabled"`
	PollIntervalS int  `mapstructure:"poll_interval_s"`
}

type MemMonConfig struct {
	Enabled       bool     `mapstructure:"enabled"`
	PollIntervalS int      `mapstructure:"poll_interval_s"`
	IgnoreComms   []string `mapstructure:"ignore_comms"`
}

type SchTaskMonitorConfig struct {
	Enabled       bool `mapstructure:"enabled"`
	PollIntervalS int  `mapstructure:"poll_interval_s"`
}

type TLSSNIConfig struct {
	Enabled bool `mapstructure:"enabled"`
}

type FIMConfig struct {
	Enabled       bool     `mapstructure:"enabled"`
	PollIntervalS int      `mapstructure:"poll_interval_s"`
	WatchPaths    []string `mapstructure:"watch_paths"`
	BaselinePath  string   `mapstructure:"baseline_path"`
	AutoBaseline  bool     `mapstructure:"auto_baseline"`
}

type VulnMonitorConfig struct {
	Enabled bool `mapstructure:"enabled"`
}

type BufferConfig struct {
	Path           string `mapstructure:"path"`
	MaxSizeMB      int    `mapstructure:"max_size_mb"`
	FlushIntervalS int    `mapstructure:"flush_interval_s"`
}

type LogConfig struct {
	Level  string `mapstructure:"level"`
	Format string `mapstructure:"format"`
	Path   string `mapstructure:"path"`
}

type SelfProtectConfig struct {
	BinPath  string `mapstructure:"bin_path"`
	Watchdog bool   `mapstructure:"watchdog"`
}

// Load reads configuration from the given YAML file path.
func Load(path string) (*Config, error) {
	v := viper.New()

	// Windows default paths.
	v.SetDefault("agent.backend_url", "localhost:50051")
	v.SetDefault("agent.tls.insecure", true)
	v.SetDefault("agent.id_file", `C:\ProgramData\TraceGuard\agent.id`)

	// ETW-based monitors.
	v.SetDefault("monitors.process.enabled", true)
	v.SetDefault("monitors.process.max_ancestry_depth", 5)
	v.SetDefault("monitors.network.enabled", true)
	v.SetDefault("monitors.network.ignore_localhost", true)
	v.SetDefault("monitors.file.enabled", true)
	v.SetDefault("monitors.file.watch_paths", []string{
		`C:\Windows\System32\`,
		`C:\Users\`,
		`C:\ProgramData\`,
		`C:\Windows\Temp\`,
	})
	v.SetDefault("monitors.file.hash_on_write", true)
	v.SetDefault("monitors.registry.enabled", true)
	v.SetDefault("monitors.dns.enabled", true)
	v.SetDefault("monitors.auth.enabled", true)
	v.SetDefault("monitors.command.enabled", true)
	v.SetDefault("monitors.browser.enabled", false)
	v.SetDefault("monitors.browser.listen_addr", "127.0.0.1:9999")
	v.SetDefault("monitors.driver.enabled", true)
	v.SetDefault("monitors.driver.poll_interval_s", 5)
	v.SetDefault("monitors.usb.enabled", true)
	v.SetDefault("monitors.usb.poll_interval_s", 10)
	v.SetDefault("monitors.pipe.enabled", true)
	v.SetDefault("monitors.pipe.poll_interval_s", 10)
	v.SetDefault("monitors.share.enabled", true)
	v.SetDefault("monitors.share.poll_interval_s", 10)
	v.SetDefault("monitors.memmon.enabled", true)
	v.SetDefault("monitors.memmon.poll_interval_s", 15)
	v.SetDefault("monitors.memmon.ignore_comms", []string{
		"java.exe", "node.exe", "python.exe", "python3.exe",
		"firefox.exe", "chrome.exe", "msedge.exe", "code.exe",
	})
	v.SetDefault("monitors.schtask.enabled", true)
	v.SetDefault("monitors.schtask.poll_interval_s", 30)
	v.SetDefault("monitors.tlssni.enabled", false) // requires Npcap
	v.SetDefault("monitors.vuln.enabled", true)
	v.SetDefault("monitors.fim.enabled", true)
	v.SetDefault("monitors.fim.poll_interval_s", 300)
	v.SetDefault("monitors.fim.auto_baseline", true)
	v.SetDefault("monitors.fim.baseline_path", `C:\ProgramData\TraceGuard\fim_baseline.json`)
	v.SetDefault("monitors.fim.watch_paths", []string{
		`C:\Windows\System32\drivers\etc\hosts`,
		`C:\Windows\System32\config\SAM`,
		`C:\Windows\System32\config\SECURITY`,
		`C:\Windows\System32\config\SYSTEM`,
		`C:\Windows\System32\GroupPolicy`,
		`C:\Windows\Tasks`,
		`C:\Windows\System32\sethc.exe`,
		`C:\Windows\System32\utilman.exe`,
		`C:\Windows\System32\cmd.exe`,
		`C:\Windows\System32\osk.exe`,
	})

	v.SetDefault("buffer.path", `C:\ProgramData\TraceGuard\events.db`)
	v.SetDefault("buffer.max_size_mb", 512)
	v.SetDefault("buffer.flush_interval_s", 5)
	v.SetDefault("log.level", "info")
	v.SetDefault("log.format", "json")
	v.SetDefault("log.path", `C:\ProgramData\TraceGuard\Logs\agent.log`)
	v.SetDefault("self_protect.watchdog", false) // Windows uses service recovery instead

	if path != "" {
		v.SetConfigFile(path)
		if err := v.ReadInConfig(); err != nil {
			if !os.IsNotExist(err) {
				return nil, fmt.Errorf("read config %q: %w", path, err)
			}
		}
	}

	v.SetEnvPrefix("EDR")
	v.AutomaticEnv()

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("unmarshal config: %w", err)
	}

	if cfg.Agent.Hostname == "" {
		cfg.Agent.Hostname, _ = os.Hostname()
	}

	return &cfg, nil
}

func DefaultConfig() *Config {
	cfg, _ := Load("")
	return cfg
}

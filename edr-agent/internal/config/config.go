// internal/config/config.go
// YAML configuration loader with hot-reload support.

package config

import (
	"fmt"
	"os"

	"github.com/spf13/viper"
)

// Config is the root configuration structure.
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
	Insecure bool   `mapstructure:"insecure"` // skip verify — dev only
}

type MonitorsConfig struct {
	Process  ProcessMonitorConfig  `mapstructure:"process"`
	Network  NetworkMonitorConfig  `mapstructure:"network"`
	File     FileMonitorConfig     `mapstructure:"file"`
	Registry RegistryMonitorConfig `mapstructure:"registry"`
	Browser  BrowserMonitorConfig  `mapstructure:"browser"`
	KMod     KModMonitorConfig     `mapstructure:"kmod"`
	USB      USBMonitorConfig      `mapstructure:"usb"`
	Pipe     PipeMonConfig         `mapstructure:"pipe"`
	Share    ShareMonConfig        `mapstructure:"share"`
	MemMon   MemMonConfig          `mapstructure:"memmon"`
	CronMon  CronMonConfig         `mapstructure:"cronmon"`
	TLSSNI   TLSSNIConfig          `mapstructure:"tlssni"`
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
	CapturePayload  bool     `mapstructure:"capture_payload"` // off by default (privacy)
	WatchedPorts    []uint16 `mapstructure:"watched_ports"`   // alert on these even if private
}

type FileMonitorConfig struct {
	Enabled          bool     `mapstructure:"enabled"`
	WatchPaths       []string `mapstructure:"watch_paths"`
	HashOnWrite      bool     `mapstructure:"hash_on_write"`
	CaptureAllWrites bool     `mapstructure:"capture_all_writes"`
}

type RegistryMonitorConfig struct {
	Enabled     bool     `mapstructure:"enabled"`
	ExtraPaths  []string `mapstructure:"extra_paths"`
}

type BrowserMonitorConfig struct {
	Enabled    bool   `mapstructure:"enabled"`
	ListenAddr string `mapstructure:"listen_addr"`
}

type KModMonitorConfig struct {
	Enabled       bool `mapstructure:"enabled"`
	PollIntervalS int  `mapstructure:"poll_interval_s"`
}

type USBMonitorConfig struct {
	Enabled       bool `mapstructure:"enabled"`
	PollIntervalS int  `mapstructure:"poll_interval_s"`
}

type PipeMonConfig struct {
	Enabled       bool     `mapstructure:"enabled"`
	PollIntervalS int      `mapstructure:"poll_interval_s"` // default 10
	WatchPaths    []string `mapstructure:"watch_paths"`
}

type ShareMonConfig struct {
	Enabled       bool `mapstructure:"enabled"`
	PollIntervalS int  `mapstructure:"poll_interval_s"` // default 10
}

type MemMonConfig struct {
	Enabled       bool     `mapstructure:"enabled"`
	PollIntervalS int      `mapstructure:"poll_interval_s"` // default 15
	IgnoreComms   []string `mapstructure:"ignore_comms"`    // JIT processes to skip
}

type CronMonConfig struct {
	Enabled    bool     `mapstructure:"enabled"`
	WatchPaths []string `mapstructure:"watch_paths"`
}

type TLSSNIConfig struct {
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
	ImmutableBin bool `mapstructure:"immutable_bin"`
}

// Load reads configuration from the given YAML file path.
func Load(path string) (*Config, error) {
	v := viper.New()

	// Defaults.
	v.SetDefault("agent.backend_url", "localhost:50051")
	v.SetDefault("agent.tls.insecure", true) // dev default — override in production config
	v.SetDefault("agent.id_file", "/var/lib/edr/agent.id")
	v.SetDefault("monitors.process.enabled", true)
	v.SetDefault("monitors.process.max_ancestry_depth", 5)
	v.SetDefault("monitors.network.enabled", true)
	v.SetDefault("monitors.network.ignore_localhost", true)
	v.SetDefault("monitors.file.enabled", true)
	v.SetDefault("monitors.file.watch_paths", []string{
		"/etc", "/usr/bin", "/usr/sbin", "/usr/local/bin",
		"/tmp", "/var/tmp", "/dev/shm",
	})
	v.SetDefault("monitors.file.hash_on_write", true)
	v.SetDefault("monitors.registry.enabled", true)
	v.SetDefault("monitors.browser.enabled", false)
	v.SetDefault("monitors.browser.listen_addr", "127.0.0.1:9999")
	v.SetDefault("monitors.kmod.enabled", true)
	v.SetDefault("monitors.kmod.poll_interval_s", 5)
	v.SetDefault("monitors.usb.enabled", true)
	v.SetDefault("monitors.usb.poll_interval_s", 10)
	v.SetDefault("monitors.pipe.enabled", true)
	v.SetDefault("monitors.pipe.poll_interval_s", 10)
	v.SetDefault("monitors.pipe.watch_paths", []string{"/tmp", "/var/tmp", "/dev/shm", "/run"})
	v.SetDefault("monitors.share.enabled", true)
	v.SetDefault("monitors.share.poll_interval_s", 10)
	v.SetDefault("monitors.memmon.enabled", true)
	v.SetDefault("monitors.memmon.poll_interval_s", 15)
	v.SetDefault("monitors.memmon.ignore_comms", []string{
		"java", "node", "python3", "python", "firefox",
		"chrome", "chromium", "code",
	})
	v.SetDefault("monitors.cronmon.enabled", true)
	v.SetDefault("monitors.cronmon.watch_paths", []string{
		"/etc/crontab", "/etc/cron.d", "/etc/cron.daily",
		"/etc/cron.hourly", "/etc/cron.weekly", "/etc/cron.monthly",
		"/var/spool/cron",
	})
	v.SetDefault("monitors.tlssni.enabled", true)
	v.SetDefault("buffer.path", "/var/lib/edr/events.db")
	v.SetDefault("buffer.max_size_mb", 512)
	v.SetDefault("buffer.flush_interval_s", 5)
	v.SetDefault("log.level", "info")
	v.SetDefault("log.format", "json")
	v.SetDefault("log.path", "/var/log/edr/agent.log")
	v.SetDefault("self_protect.watchdog", true)

	if path != "" {
		v.SetConfigFile(path)
		if err := v.ReadInConfig(); err != nil {
			if !os.IsNotExist(err) {
				return nil, fmt.Errorf("read config %q: %w", path, err)
			}
			// Config file not found — use defaults (first run).
		}
	}

	// Allow ENV overrides: EDR_AGENT_BACKEND_URL etc.
	v.SetEnvPrefix("EDR")
	v.AutomaticEnv()

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("unmarshal config: %w", err)
	}

	// Auto-detect hostname if not set.
	if cfg.Agent.Hostname == "" {
		cfg.Agent.Hostname, _ = os.Hostname()
	}

	return &cfg, nil
}

// DefaultConfig returns a Config with all defaults applied.
func DefaultConfig() *Config {
	cfg, _ := Load("")
	return cfg
}

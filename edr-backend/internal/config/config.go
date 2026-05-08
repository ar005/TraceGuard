package config

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/viper"
)

type Config struct {
	Server     ServerConfig     `mapstructure:"server"`
	Database   DatabaseConfig   `mapstructure:"database"`
	Log        LogConfig        `mapstructure:"log"`
	Auth       AuthConfig       `mapstructure:"auth"`
	Retention  RetentionConfig  `mapstructure:"retention"`
	RateLimit  RateLimitConfig  `mapstructure:"rate_limit"`
	IOCFeed    IOCFeedConfig    `mapstructure:"ioc_feed"`
	NATS       NATSConfig       `mapstructure:"nats"`
	Enrichment EnrichmentConfig `mapstructure:"enrichment"`
}

type EnrichmentConfig struct {
	VirusTotalAPIKey string `mapstructure:"virustotal_api_key"`
	AbuseIPDBAPIKey  string `mapstructure:"abuseipdb_api_key"`
	MaxMindDBPath    string `mapstructure:"maxmind_db_path"`
	WhoisEnabled     bool   `mapstructure:"whois_enabled"`
}

type ServerConfig struct {
	GRPCAddr string    `mapstructure:"grpc_addr"`
	HTTPAddr string    `mapstructure:"http_addr"`
	NodeID   string    `mapstructure:"node_id"`
	TLS      TLSConfig `mapstructure:"tls"`
}

type TLSConfig struct {
	Enabled  bool   `mapstructure:"enabled"`
	CertFile string `mapstructure:"cert_file"`
	KeyFile  string `mapstructure:"key_file"`
	CAFile   string `mapstructure:"ca_file"`
}

type DatabaseConfig struct {
	DSN      string `mapstructure:"dsn"`
	Host     string `mapstructure:"host"`
	Port     int    `mapstructure:"port"`
	Name     string `mapstructure:"name"`
	User     string `mapstructure:"user"`
	Password string `mapstructure:"password"`
	SSLMode  string `mapstructure:"ssl_mode"`
	// ReadURL is an optional full DSN for a read replica.
	// When set, read-heavy queries route there; writes always use the primary.
	ReadURL  string `mapstructure:"read_url"`
}

func (d *DatabaseConfig) DSNString() string {
	if d.DSN != "" {
		return d.DSN
	}
	return fmt.Sprintf(
		"host=%s port=%d dbname=%s user=%s password=%s sslmode=%s",
		d.Host, d.Port, d.Name, d.User, d.Password, d.SSLMode,
	)
}

type LogConfig struct {
	Level  string `mapstructure:"level"`
	Format string `mapstructure:"format"`
}

type AuthConfig struct {
	APIKey string `mapstructure:"api_key"`
}

type RetentionConfig struct {
	EventDays int `mapstructure:"event_days"` // 0 = disabled
	AlertDays int `mapstructure:"alert_days"` // 0 = disabled (only CLOSED)
	FlowDays  int `mapstructure:"flow_days"`  // xdr_network_flows partition retention; 0 = use DB setting (default 7)
}

type RateLimitConfig struct {
	Enabled           bool    `mapstructure:"enabled"`
	RequestsPerSecond float64 `mapstructure:"requests_per_second"`
	Burst             int     `mapstructure:"burst"`
}

type IOCFeedConfig struct {
	Enabled      bool          `mapstructure:"enabled"`
	SyncInterval time.Duration `mapstructure:"sync_interval"`
}

type NATSConfig struct {
	// URL is the NATS server connection string. Leave empty to disable NATS
	// and run detection synchronously (single-node EDR mode).
	URL     string `mapstructure:"url"`
	Enabled bool   `mapstructure:"enabled"`
}

func Load(path string) (*Config, error) {
	v := viper.New()

	v.SetDefault("server.grpc_addr", ":50051")
	v.SetDefault("server.http_addr", ":8080")
	v.SetDefault("database.host",     "postgres")  // Docker service name
	v.SetDefault("database.port",     5432)
	v.SetDefault("database.name",     "edr")
	v.SetDefault("database.user",     "edr")
	v.SetDefault("database.password", "edr")
	v.SetDefault("database.ssl_mode", "disable")
	v.SetDefault("log.level",  "info")
	v.SetDefault("log.format", "json")
	v.SetDefault("retention.event_days", 90)
	v.SetDefault("retention.alert_days", 0)   // keep CLOSED alerts by default
	v.SetDefault("rate_limit.enabled", true)
	v.SetDefault("rate_limit.requests_per_second", 20)
	v.SetDefault("rate_limit.burst", 40)
	v.SetDefault("ioc_feed.enabled", true)
	v.SetDefault("ioc_feed.sync_interval", 6*time.Hour)
	v.SetDefault("nats.enabled", false)
	v.SetDefault("nats.url", "nats://nats:4222")

	// Allow env overrides with EDR_ prefix, replacing _ with . for nesting
	v.SetEnvPrefix("EDR")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	if path != "" {
		v.SetConfigFile(path)
		if err := v.ReadInConfig(); err != nil {
			if !os.IsNotExist(err) {
				return nil, fmt.Errorf("read config: %w", err)
			}
		}
	}

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("unmarshal config: %w", err)
	}
	return &cfg, nil
}

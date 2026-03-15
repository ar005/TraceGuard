package config

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/viper"
)

type Config struct {
	Server    ServerConfig    `mapstructure:"server"`
	Database  DatabaseConfig  `mapstructure:"database"`
	Log       LogConfig       `mapstructure:"log"`
	Auth      AuthConfig      `mapstructure:"auth"`
	Retention RetentionConfig `mapstructure:"retention"`
}

type ServerConfig struct {
	GRPCAddr string    `mapstructure:"grpc_addr"`
	HTTPAddr string    `mapstructure:"http_addr"`
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

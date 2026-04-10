// internal/logger/logger.go
// Structured logger using zerolog.

package logger

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/rs/zerolog"

	"github.com/youredr/edr-agent/internal/config"
)

// New creates a zerolog.Logger from the LogConfig.
func New(cfg config.LogConfig) zerolog.Logger {
	var writers []io.Writer

	// Console / file output.
	if cfg.Format == "text" {
		writers = append(writers, zerolog.ConsoleWriter{
			Out:        os.Stderr,
			TimeFormat: time.RFC3339,
		})
	} else {
		writers = append(writers, os.Stderr)
	}

	// File output (if configured).
	if cfg.Path != "" {
		if err := os.MkdirAll(filepath.Dir(cfg.Path), 0755); err == nil {
			f, err := os.OpenFile(cfg.Path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0640)
			if err == nil {
				writers = append(writers, f)
			}
		}
	}

	var w io.Writer
	if len(writers) == 1 {
		w = writers[0]
	} else {
		w = io.MultiWriter(writers...)
	}

	level := zerolog.InfoLevel
	switch strings.ToLower(cfg.Level) {
	case "debug":
		level = zerolog.DebugLevel
	case "warn", "warning":
		level = zerolog.WarnLevel
	case "error":
		level = zerolog.ErrorLevel
	}

	return zerolog.New(w).
		Level(level).
		With().
		Timestamp().
		Str("service", "edr-agent").
		Logger()
}

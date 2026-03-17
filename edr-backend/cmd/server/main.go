// cmd/server/main.go
// EDR Backend Server — starts gRPC ingest + REST API.

package main

import (
	"context"
	"crypto/rand"
	"flag"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/youredr/edr-backend/internal/api"
	"github.com/youredr/edr-backend/internal/sse"
	"github.com/youredr/edr-backend/internal/llm"
	"github.com/youredr/edr-backend/internal/apikeys"
	"github.com/youredr/edr-backend/internal/audit"
	"github.com/youredr/edr-backend/internal/config"
	"github.com/youredr/edr-backend/internal/db"
	"github.com/youredr/edr-backend/internal/detection"
	"github.com/youredr/edr-backend/internal/ingest"
	"github.com/youredr/edr-backend/internal/models"
	"github.com/youredr/edr-backend/internal/store"
	"github.com/youredr/edr-backend/internal/users"

	// Register JSON codec for gRPC
	_ "github.com/youredr/edr-backend/internal/proto"
)

func main() {
	cfgPath := flag.String("config", "config/server.yaml", "path to config file")
	flag.Parse()

	// ── Config ────────────────────────────────────────────────────────────────
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		log.Fatal().Err(err).Msg("load config")
	}

	// ── Logger ────────────────────────────────────────────────────────────────
	level, _ := zerolog.ParseLevel(cfg.Log.Level)
	zerolog.SetGlobalLevel(level)

	var logger zerolog.Logger
	if cfg.Log.Format == "text" {
		logger = zerolog.New(zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: time.RFC3339}).
			With().Timestamp().Logger()
	} else {
		logger = zerolog.New(os.Stdout).With().Timestamp().Logger()
	}
	logger.Info().Str("grpc", cfg.Server.GRPCAddr).Str("http", cfg.Server.HTTPAddr).Msg("EDR backend starting")

	// ── Database ──────────────────────────────────────────────────────────────
	database, err := db.Open(cfg.Database.DSNString())
	if err != nil {
		logger.Fatal().Err(err).Msg("connect to postgres")
	}
	defer database.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	if err := db.RunMigrations(ctx, database, logger); err != nil {
		cancel()
		logger.Fatal().Err(err).Msg("run migrations")
	}
	cancel()
	logger.Info().Msg("database ready")

	// ── Store ─────────────────────────────────────────────────────────────────
	st := store.New(database)

	// ── JWT secret: env var or random ─────────────────────────────────────────
	jwtSecret := []byte(os.Getenv("EDR_JWT_SECRET"))
	if len(jwtSecret) == 0 {
		jwtSecret = make([]byte, 32)
		if _, err := rand.Read(jwtSecret); err != nil {
			logger.Fatal().Err(err).Msg("generate jwt secret")
		}
		logger.Warn().Msg("EDR_JWT_SECRET not set — using ephemeral secret (sessions will not survive restarts)")
	}

	// ── User Manager ──────────────────────────────────────────────────────────
	um := users.New(database, jwtSecret)
	if username, password, created, err := um.Bootstrap(context.Background()); err != nil {
		logger.Warn().Err(err).Msg("user bootstrap failed")
	} else if created {
		logger.Warn().
			Str("username", username).
			Str("password", password).
			Msg("╔══════════════════════════════════════════════════════════╗")
		logger.Warn().
			Str("username", username).
			Str("password", password).
			Msg("║  ADMIN PORTAL FIRST RUN — SAVE THESE CREDENTIALS        ║")
		logger.Warn().
			Str("username", username).
			Str("password", password).
			Msg("╚══════════════════════════════════════════════════════════╝")
	}

	// ── Audit Logger ──────────────────────────────────────────────────────────
	al := audit.New(database)

	// ── API Key Manager ───────────────────────────────────────────────────────
	km := apikeys.New(database)
	if err := km.Bootstrap(context.Background(), cfg.Auth.APIKey); err != nil {
		logger.Warn().Err(err).Msg("api key bootstrap failed")
	}

	// ── Detection Engine ──────────────────────────────────────────────────────
		// SSE broker — fans live events to connected browser clients.
	sseBroker := sse.New(logger)

	engine := detection.New(st, logger, func(ctx context.Context, alert *models.Alert) {
		if err := st.InsertAlert(ctx, alert); err != nil {
			logger.Error().Err(err).Str("rule", alert.RuleID).Msg("persist alert failed")
		} else {
			logger.Warn().
				Str("alert_id",  alert.ID).
				Str("rule",      alert.RuleName).
				Str("hostname",  alert.Hostname).
				Int("severity",  int(alert.Severity)).
				Msg("ALERT FIRED")
		}
	})
	if err := engine.Reload(context.Background()); err != nil {
		logger.Fatal().Err(err).Msg("load detection rules")
	}

	// ── gRPC Ingest Server ────────────────────────────────────────────────────
	grpcServer := ingest.New(st, engine, sseBroker, logger, ingest.TLSConfig{
		Enabled:  cfg.Server.TLS.Enabled,
		CertFile: cfg.Server.TLS.CertFile,
		KeyFile:  cfg.Server.TLS.KeyFile,
		CAFile:   cfg.Server.TLS.CAFile,
	})
	go func() {
		if err := grpcServer.Listen(cfg.Server.GRPCAddr); err != nil {
			logger.Fatal().Err(err).Msg("gRPC server failed")
		}
	}()

	// ── REST API Server ───────────────────────────────────────────────────────
	// LLM client (Ollama) — disabled unless OLLAMA_ENABLED=true
	llmClient := llm.New(logger)
	if llmClient.Enabled() {
		logger.Info().Str("model", os.Getenv("OLLAMA_MODEL")).Msg("Ollama LLM enabled")
	} else {
		logger.Info().Msg("Ollama LLM disabled (set OLLAMA_ENABLED=true to enable)")
	}

	apiServer := api.New(st, engine, km, um, al, llmClient, sseBroker, logger, cfg.Auth.APIKey)
	go func() {
		if err := apiServer.Listen(cfg.Server.HTTPAddr); err != nil {
			if err.Error() != "http: Server closed" {
				logger.Fatal().Err(err).Msg("HTTP server failed")
			}
		}
	}()

	// ── Agent heartbeat monitor ───────────────────────────────────────────────
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			if err := st.MarkStaleAgentsOffline(context.Background(), 90*time.Second); err != nil {
				logger.Warn().Err(err).Msg("stale agent sweep failed")
			}
		}
	}()

	// ── Retention sweep (runs every 6 hours) ────────────────────────────────
	go func() {
		if cfg.Retention.EventDays == 0 && cfg.Retention.AlertDays == 0 {
			return // retention disabled
		}
		runSweep := func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
			defer cancel()
			// Read retention settings from DB (configurable via UI)
			evtDays, alrtDays := st.GetRetentionDays(ctx)
			if evtDays > 0 {
				cutoff := time.Now().AddDate(0, 0, -evtDays)
				if n, err := st.DeleteOldEvents(ctx, cutoff); err != nil {
					logger.Error().Err(err).Msg("retention: event sweep failed")
				} else if n > 0 {
					logger.Info().Int64("deleted", n).Int("days", evtDays).Msg("retention: events pruned")
				}
			}
			if alrtDays > 0 {
				cutoff := time.Now().AddDate(0, 0, -alrtDays)
				if n, err := st.DeleteOldAlerts(ctx, cutoff); err != nil {
					logger.Error().Err(err).Msg("retention: alert sweep failed")
				} else if n > 0 {
					logger.Info().Int64("deleted", n).Int("days", alrtDays).Msg("retention: alerts pruned")
				}
			}
		}
		runSweep() // run once at startup
		ticker := time.NewTicker(6 * time.Hour)
		defer ticker.Stop()
		for range ticker.C {
			runSweep()
		}
	}()

	// ── Graceful shutdown ─────────────────────────────────────────────────────
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	sig := <-quit
	logger.Info().Str("signal", sig.String()).Msg("shutting down")

	grpcServer.Stop()

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()
	if err := apiServer.Shutdown(shutdownCtx); err != nil {
		logger.Error().Err(err).Msg("HTTP shutdown error")
	}

	logger.Info().Msg("EDR backend stopped")
}

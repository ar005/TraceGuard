// cmd/server/main.go
// EDR Backend Server — starts gRPC ingest + REST API.

package main

import (
	"context"
	"crypto/rand"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/youredr/edr-backend/internal/api"
	"github.com/youredr/edr-backend/internal/cvecache"
	"github.com/youredr/edr-backend/internal/sse"
	"github.com/youredr/edr-backend/internal/llm"
	"github.com/youredr/edr-backend/internal/apikeys"
	"github.com/youredr/edr-backend/internal/audit"
	"github.com/youredr/edr-backend/internal/config"
	"github.com/youredr/edr-backend/internal/db"
	"github.com/youredr/edr-backend/internal/detection"
	"github.com/youredr/edr-backend/internal/ingest"
	"github.com/youredr/edr-backend/internal/iocfeed"
	"github.com/youredr/edr-backend/internal/liveresponse"
	"github.com/youredr/edr-backend/internal/metrics"
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

	// Incident correlation window — alerts on the same agent within this
	// window are grouped into a single incident.
	const incidentWindow = 30 * time.Minute

	engine := detection.New(st, logger, func(ctx context.Context, alert *models.Alert) {
		if err := st.InsertAlert(ctx, alert); err != nil {
			logger.Error().Err(err).Str("rule", alert.RuleID).Msg("persist alert failed")
			return
		}
		logger.Warn().
			Str("alert_id",  alert.ID).
			Str("rule",      alert.RuleName).
			Str("hostname",  alert.Hostname).
			Int("severity",  int(alert.Severity)).
			Msg("ALERT FIRED")

		// ── Incident correlation ─────────────────────────────────────────
		existing, err := st.FindOpenIncident(ctx, alert.AgentID, incidentWindow)
		if err != nil {
			logger.Warn().Err(err).Msg("incident lookup failed — creating new incident")
		}
		if existing != nil {
			// Append alert to existing incident.
			if err := st.AddAlertToIncident(ctx, existing.ID, alert); err != nil {
				logger.Error().Err(err).Str("incident", existing.ID).Msg("add alert to incident failed")
			} else {
				_ = st.SetAlertIncident(ctx, alert.ID, existing.ID)
				logger.Info().
					Str("incident", existing.ID).
					Str("alert", alert.ID).
					Int("alert_count", existing.AlertCount+1).
					Msg("alert correlated into existing incident")
			}
		} else {
			// Create a new incident for this alert.
			incID := "inc-" + uuid.New().String()
			inc := &models.Incident{
				ID:          incID,
				Title:       fmt.Sprintf("Incident on %s", alert.Hostname),
				Description: fmt.Sprintf("Auto-correlated incident starting with: %s", alert.Title),
				Severity:    alert.Severity,
				Status:      "OPEN",
				AlertIDs:    []string{alert.ID},
				AgentIDs:    []string{alert.AgentID},
				Hostnames:   []string{alert.Hostname},
				MitreIDs:    alert.MitreIDs,
				AlertCount:  1,
				FirstSeen:   time.Now(),
				LastSeen:    time.Now(),
			}
			if err := st.InsertIncident(ctx, inc); err != nil {
				logger.Error().Err(err).Msg("create incident failed")
			} else {
				_ = st.SetAlertIncident(ctx, alert.ID, incID)
				logger.Info().
					Str("incident", incID).
					Str("alert", alert.ID).
					Str("hostname", alert.Hostname).
					Msg("new incident created")
			}
		}
	})
	if err := engine.Reload(context.Background()); err != nil {
		logger.Fatal().Err(err).Msg("load detection rules")
	}

	// ── Live Response Manager ─────────────────────────────────────────────────
	lrManager := liveresponse.NewManager(logger)

	// Wire auto-response: detection engine sends quarantine/block_ip commands
	// to agents via live response when IOC matches are found.
	engine.SetAutoResponder(lrManager)

	// ── gRPC Ingest Server ────────────────────────────────────────────────────
	grpcServer := ingest.New(st, engine, sseBroker, lrManager, logger, ingest.TLSConfig{
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
	// LLM client — reads env vars for backward compat, then overrides from DB
	llmClient := llm.New(logger)

	// Load LLM settings from database (overrides env vars if configured via UI)
	if provider := st.GetSetting(context.Background(), "llm_provider", ""); provider != "" {
		llmClient.Configure(llm.Config{
			Provider: provider,
			Model:    st.GetSetting(context.Background(), "llm_model", ""),
			BaseURL:  st.GetSetting(context.Background(), "llm_base_url", ""),
			APIKey:   st.GetSetting(context.Background(), "llm_api_key", ""),
			Enabled:  st.GetSetting(context.Background(), "llm_enabled", "false") == "true",
		})
	}

	if llmClient.Enabled() {
		logger.Info().Str("provider", llmClient.ProviderName()).Str("model", llmClient.ModelName()).Msg("AI provider enabled")
	} else {
		logger.Info().Msg("AI not configured (configure via Settings page or OLLAMA_ENABLED env var)")
	}

	// ── IOC Feed Syncer ──────────────────────────────────────────────────────
	iocSyncer := iocfeed.New(st, logger, iocfeed.Config{
		Enabled:      cfg.IOCFeed.Enabled,
		SyncInterval: cfg.IOCFeed.SyncInterval,
	})
	go iocSyncer.Start(context.Background())

	apiServer := api.New(st, engine, km, um, al, llmClient, lrManager, iocSyncer, sseBroker, logger, cfg.Auth.APIKey,
		api.RateLimitConfig{
			Enabled:           cfg.RateLimit.Enabled,
			RequestsPerSecond: cfg.RateLimit.RequestsPerSecond,
			Burst:             cfg.RateLimit.Burst,
		})
	// ── CVE Cache Fetcher ────────────────────────────────────────────────────
	cveFetcher := cvecache.New(st, logger)
	apiServer.SetCVEFetcher(cveFetcher)

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
			// Update Prometheus agent gauges.
			if agents, err := st.ListAgents(context.Background()); err == nil {
				metrics.AgentsTotal.Set(float64(len(agents)))
				online := 0
				for _, a := range agents {
					if a.IsOnline {
						online++
					}
				}
				metrics.AgentsOnline.Set(float64(online))
			}
		}
	}()

	// ── Retention sweep (runs every 1 hour) ─────────────────────────────────
	// Always runs — reads retention policy from DB settings (configurable via
	// the UI at /api/v1/settings/retention). Config file values are just the
	// initial defaults seeded into the DB.
	go func() {
		const sweepInterval = 1 * time.Hour

		runSweep := func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
			defer cancel()

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

		// Log policy at startup.
		evtDays, alrtDays := st.GetRetentionDays(context.Background())
		logger.Info().
			Int("event_days", evtDays).
			Int("alert_days", alrtDays).
			Dur("interval", sweepInterval).
			Msg("retention worker started")

		runSweep() // run once at startup
		ticker := time.NewTicker(sweepInterval)
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

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
	"strings"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/youredr/edr-backend/internal/api"
	"github.com/youredr/edr-backend/internal/connectors"
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
	"github.com/youredr/edr-backend/internal/natsbus"
	"github.com/youredr/edr-backend/internal/store"
	"github.com/youredr/edr-backend/internal/users"
	"github.com/youredr/edr-backend/internal/autocase"
	"github.com/youredr/edr-backend/internal/autoremediate"
	"github.com/youredr/edr-backend/internal/beaconing"
	"github.com/youredr/edr-backend/internal/exfil"
	"github.com/youredr/edr-backend/internal/hostbehavior"
	"github.com/youredr/edr-backend/internal/netthreat"
	"github.com/youredr/edr-backend/internal/dnstunnel"
	"github.com/youredr/edr-backend/internal/enrichment"
	"github.com/youredr/edr-backend/internal/export"
	"github.com/youredr/edr-backend/internal/fim"
	"github.com/youredr/edr-backend/internal/hostrisk"
	"github.com/youredr/edr-backend/internal/lateral"
	"github.com/youredr/edr-backend/internal/logintrack"
	"github.com/youredr/edr-backend/internal/playbook"
	"github.com/youredr/edr-backend/internal/ransomware"
	"github.com/youredr/edr-backend/internal/userrisk"
	"github.com/youredr/edr-backend/internal/workers"

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

	// ── Node identity ─────────────────────────────────────────────────────────
	nodeID := cfg.Server.NodeID
	if nodeID == "" {
		if h, err := os.Hostname(); err == nil {
			nodeID = h
		} else {
			nodeID = "unknown"
		}
	}
	logger.Info().Str("node_id", nodeID).Msg("node identity")

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

	// ── Read replica (optional) ────────────────────────────────────────────────
	if cfg.Database.ReadURL != "" {
		rdb, err := db.OpenReplica(cfg.Database.ReadURL)
		if err != nil {
			logger.Warn().Err(err).Msg("read replica unavailable — all reads use primary")
		} else {
			st.SetReadReplica(rdb)
			defer rdb.Close()
			logger.Info().Msg("read replica connected")
		}
	}

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
	// SSE broker — backed by PostgreSQL LISTEN/NOTIFY for multi-node fan-out.
	sseBroker := sse.New(logger, database, cfg.Database.DSNString())
	brokerCtx, brokerCancel := context.WithCancel(context.Background())
	defer brokerCancel()
	sseBroker.Start(brokerCtx)

	// ── SOAR + Export (created before engine so callbacks can reference them) ──
	// These are late-bound via pointers; the actual Runner/ExportManager are
	// created after lrManager (below) and stored into these vars.
	var (
		pbRunner            *playbook.Runner
		exportMgr           *export.ExportManager
		autoCaseMgr         *autocase.Manager
		enricher            *enrichment.Enricher
		autoRemediateEngine *autoremediate.Engine
	)

	// Incident correlation window — alerts on the same agent within this
	// window are grouped into a single incident.
	const incidentWindow = 30 * time.Minute

	// fireAlert is the shared alert dispatch closure used by the detection engine
	// and the behavioral analyzer.
	var fireAlert func(ctx context.Context, alert *models.Alert)
	fireAlert = func(ctx context.Context, alert *models.Alert) {
		// ── Risk scoring (Feature G) ─────────────────────────────────────
		alert.RiskScore = computeRiskScore(alert)

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

		// ── SOAR: trigger playbooks + export ────────────────────────────
		if pbRunner != nil {
			pbRunner.OnAlert(ctx, alert)
		}
		if exportMgr != nil {
			exportMgr.ExportAlert(ctx, alert)
		}

		// ── Auto-case creation ────────────────────────────────────────
		if autoCaseMgr != nil {
			go autoCaseMgr.Evaluate(ctx, alert)
		}

		// ── Auto-remediation (Feature B) ──────────────────────────────
		if autoRemediateEngine != nil {
			go autoRemediateEngine.Evaluate(context.Background(), alert)
		}

		// ── IOC auto-check (J) ───────────────────────────────────────
		go func(a *models.Alert) {
			iocCtx, iocCancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer iocCancel()
			if a.SrcIP != "" {
				if ioc, err := st.LookupIOC(iocCtx, "ip", a.SrcIP); err == nil && ioc != nil {
					logger.Warn().Str("alert_id", a.ID).Str("ip", a.SrcIP).
						Str("ioc_source", ioc.Source).Msg("IOC MATCH on alert src_ip")
				}
			}
		}(alert)

		// ── Async TI enrichment (Feature A) ──────────────────────────
		if enricher != nil {
			go func(a *models.Alert) {
				enrichCtx, enrichCancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer enrichCancel()
				var ti *enrichment.TIResult
				if a.SrcIP != "" {
					ti, _ = enricher.EnrichIP(enrichCtx, a.SrcIP)
				}
				// Hash enrichment: derive from event IDs or rule metadata
				if ti == nil {
					for _, eid := range a.EventIDs {
						if isFileHash(eid) {
							ti, _ = enricher.EnrichHash(enrichCtx, eid)
							if ti != nil {
								break
							}
						}
					}
				}
				if ti != nil {
					if merged, err := enrichment.MergeIntoEnrichments(a.Enrichments, ti); err == nil {
						_ = st.UpdateAlertEnrichments(enrichCtx, a.ID, a.TenantID, merged)
					}
				}
			}(alert)
		}

		// ── Incident correlation ─────────────────────────────────────────
		// XDR alerts carry user_uid / source_types — correlate cross-source.
		userUID    := alert.UserUID
		srcIPStr   := alert.SrcIP
		sourceType := ""
		if len(alert.SourceTypes) > 0 {
			sourceType = alert.SourceTypes[0]
		}

		var existing *models.Incident
		var err error
		if userUID != "" || srcIPStr != "" {
			existing, err = st.FindOpenIncidentXdr(ctx, alert.AgentID, userUID, srcIPStr, alert.TenantID, incidentWindow)
		} else {
			existing, err = st.FindOpenIncident(ctx, alert.AgentID, alert.TenantID, incidentWindow)
		}
		if err != nil {
			logger.Warn().Err(err).Msg("incident lookup failed — creating new incident")
		}
		if existing != nil {
			// Append alert to existing incident (XDR-aware).
			if err := st.AddAlertToIncidentXdr(ctx, existing.ID, alert, userUID, srcIPStr, sourceType); err != nil {
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
			title := fmt.Sprintf("Incident on %s", alert.Hostname)
			if userUID != "" {
				title = fmt.Sprintf("Incident — %s", userUID)
			}
			inc := &models.Incident{
				ID:          incID,
				TenantID:    alert.TenantID,
				Title:       title,
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
			if userUID != "" {
				inc.UserUIDs = pq.StringArray{userUID}
			}
			if sourceType != "" {
				inc.SourceTypes = pq.StringArray{sourceType}
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
	}
	engine := detection.New(st, logger, fireAlert)
	if err := engine.Reload(context.Background()); err != nil {
		logger.Fatal().Err(err).Msg("load detection rules")
	}

	// ── Live Response Manager ─────────────────────────────────────────────────
	lrManager := liveresponse.NewManager(logger)

	// Wire auto-response: detection engine sends quarantine/block_ip commands
	// to agents via live response when IOC matches are found.
	engine.SetAutoResponder(lrManager)

	// ── SOAR Runner + Export Manager ──────────────────────────────────────────
	pbRunner = playbook.New(st, lrManager, logger)
	exportMgr = export.New(st, logger)
	autoCaseMgr = autocase.New(st, logger)
	enricher = enrichment.New(cfg.Enrichment.VirusTotalAPIKey, cfg.Enrichment.AbuseIPDBAPIKey, logger)
	logger.Info().Msg("SOAR playbook runner, export manager, auto-case, and TI enrichment initialized")

	// ── XDR Feature B: Auto-Remediation Engine ────────────────────────────────
	autoRemediateEngine = autoremediate.New(st, logger)

	// ── XDR Feature D: Host Behavioral Anomaly Detector ──────────────────────
	hostBehaviorDetector := hostbehavior.New(st, fireAlert, logger)

	// ── XDR Feature E: Network Threat Detector ────────────────────────────────
	netThreatDetector := netthreat.New(st, fireAlert, logger)

	// ── XDR Feature E2: Data Exfiltration Detector ────────────────────────────
	exfilDetector := exfil.New(st, logger)

	// ── NATS JetStream (XDR pipeline, optional) ───────────────────────────────
	var ingestSink ingest.EventSink // nil = inline detection (EDR mode)
	var natsBus *natsbus.Bus
	if cfg.NATS.Enabled {
		var err error
		natsBus, err = natsbus.New(cfg.NATS.URL, logger)
		if err != nil {
			logger.Fatal().Err(err).Str("url", cfg.NATS.URL).Msg("NATS connect failed")
		}
		defer natsBus.Close()

		natsCtx, natsCancel := context.WithCancel(context.Background())
		defer natsCancel()

		if err := natsBus.EnsureStream(natsCtx); err != nil {
			logger.Fatal().Err(err).Msg("NATS stream setup failed")
		}

		if err := workers.RunDetectionWorker(natsCtx, natsBus, engine, logger); err != nil {
			logger.Fatal().Err(err).Msg("detection worker startup failed")
		}
		if err := workers.RunStoreWorker(natsCtx, natsBus, st, logger); err != nil {
			logger.Fatal().Err(err).Msg("store worker startup failed")
		}

		ingestSink = natsbus.NewSink(natsBus)
		logger.Info().Str("url", cfg.NATS.URL).Msg("XDR pipeline enabled (NATS JetStream)")
	} else {
		logger.Info().Msg("XDR pipeline disabled — running inline detection (EDR mode)")
	}

	// ── XDR Connector Registry ────────────────────────────────────────────────
	// Connectors only run when the NATS pipeline is active; they publish
	// normalized XdrEvents to the same JetStream subjects as endpoint events.
	if natsBus != nil {
		connReg := connectors.NewRegistry(natsbus.NewSink(natsBus), st, logger)
		connCtx, connCancel := context.WithCancel(context.Background())
		defer connCancel()
		if err := connReg.LoadAndStart(connCtx); err != nil {
			logger.Warn().Err(err).Msg("connector registry load failed — connectors disabled")
		}
	}

	// ── XDR Behavioral Detectors + Decay Worker ──────────────────────────────
	detectorCtx, detectorCancel := context.WithCancel(context.Background())
	defer detectorCancel()

	// Lateral movement runs independently of NATS (sweeps the DB).
	lateralDetector := lateral.New(st, logger)
	go lateralDetector.Run(detectorCtx)

	if natsBus != nil {
		scorer := userrisk.New(st, logger)
		hostScorer := hostrisk.New(st, logger)
		beaconDetector := beaconing.New(st, logger)
		go beaconDetector.Run(detectorCtx)
		loginTracker := logintrack.New(st, logger)
		dnsTunnelDetector := dnstunnel.New(st, logger)
		ransomwareDetector := ransomware.New(st, logger)
		fimMonitor := fim.New(st, logger)

		riskCtx, riskCancel := context.WithCancel(context.Background())
		defer riskCancel()

		_ = natsBus.Subscribe(riskCtx, natsbus.ConsumerConfig{Name: "user-risk-scorer"}, func(ctx context.Context, ev *models.XdrEvent) error {
			scorer.Score(ctx, ev)
			return nil
		})
		_ = natsBus.Subscribe(riskCtx, natsbus.ConsumerConfig{Name: "host-risk-scorer"}, func(ctx context.Context, ev *models.XdrEvent) error {
			hostScorer.Score(ctx, ev)
			return nil
		})
		_ = natsBus.Subscribe(riskCtx, natsbus.ConsumerConfig{Name: "beaconing-detector"}, func(ctx context.Context, ev *models.XdrEvent) error {
			beaconDetector.Observe(ctx, ev)
			return nil
		})
		_ = natsBus.Subscribe(riskCtx, natsbus.ConsumerConfig{Name: "login-tracker"}, func(ctx context.Context, ev *models.XdrEvent) error {
			loginTracker.Track(ctx, ev)
			return nil
		})
		_ = natsBus.Subscribe(riskCtx, natsbus.ConsumerConfig{Name: "dns-tunnel-detector"}, func(ctx context.Context, ev *models.XdrEvent) error {
			dnsTunnelDetector.Observe(ctx, ev)
			return nil
		})
		_ = natsBus.Subscribe(riskCtx, natsbus.ConsumerConfig{Name: "ransomware-detector"}, func(ctx context.Context, ev *models.XdrEvent) error {
			ransomwareDetector.Observe(ctx, ev)
			return nil
		})
		_ = natsBus.Subscribe(riskCtx, natsbus.ConsumerConfig{Name: "fim-monitor"}, func(ctx context.Context, ev *models.XdrEvent) error {
			fimMonitor.Observe(ctx, ev)
			return nil
		})
		_ = natsBus.Subscribe(riskCtx, natsbus.ConsumerConfig{Name: "host-behavior-detector"}, func(ctx context.Context, ev *models.XdrEvent) error {
			hostBehaviorDetector.Observe(ctx, ev)
			return nil
		})
		_ = natsBus.Subscribe(riskCtx, natsbus.ConsumerConfig{Name: "net-threat-detector"}, func(ctx context.Context, ev *models.XdrEvent) error {
			netThreatDetector.Observe(ctx, ev)
			return nil
		})
		_ = natsBus.Subscribe(riskCtx, natsbus.ConsumerConfig{Name: "exfil-detector"}, func(ctx context.Context, ev *models.XdrEvent) error {
			exfilDetector.Observe(ctx, ev)
			return nil
		})

		decayWorker := workers.NewRiskDecayWorker(st, 24*time.Hour, 10, logger)
		go decayWorker.Run(riskCtx)
	}

	// ── gRPC Ingest Server ────────────────────────────────────────────────────
	grpcServer := ingest.New(st, engine, sseBroker, lrManager, ingestSink, logger, ingest.TLSConfig{
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
			APIKey:   st.GetSecretSetting(context.Background(), "llm_api_key", ""),
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

	apiServer := api.New(st, engine, km, um, al, llmClient, lrManager, iocSyncer, sseBroker, logger, nodeID, cfg.Auth.APIKey,
		api.RateLimitConfig{
			Enabled:           cfg.RateLimit.Enabled,
			RequestsPerSecond: cfg.RateLimit.RequestsPerSecond,
			Burst:             cfg.RateLimit.Burst,
		})
	// ── CVE Cache Fetcher ────────────────────────────────────────────────────
	cveFetcher := cvecache.New(st, logger)
	apiServer.SetCVEFetcher(cveFetcher)

	// Wire XDR sink for REST webhook ingest (only when NATS is enabled).
	if natsBus != nil {
		apiServer.SetXdrSink(natsbus.NewSink(natsBus))
	}
	apiServer.SetPlaybookRunner(pbRunner)
	apiServer.SetExportManager(exportMgr)

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

	// ── XDR Phase 4: Flow retention worker ────────────────────────────────────
	flowRetention := workers.NewFlowRetentionWorker(st.DB(), cfg.Retention.FlowDays, logger)
	go flowRetention.Start(context.Background())

	// ── XDR Phase 4: Behavioral analytics ─────────────────────────────────────
	behavioralAnalyzer := detection.NewBehavioralAnalyzer(st.DB(), st, fireAlert, logger)
	go behavioralAnalyzer.Start(context.Background())

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

// ── Risk scoring helpers (Feature G) ─────────────────────────────────────────

// tacticWeights maps MITRE technique prefixes to a bonus risk score.
var tacticWeights = map[string]int16{
	"T1059": 20, // Execution
	"T1003": 25, // Credential Dumping
	"T1078": 20, // Valid Accounts
	"T1021": 20, // Remote Services / Lateral Movement
	"T1550": 25, // Pass-the-Hash
	"T1486": 30, // Data Encrypted for Impact (ransomware)
	"T1048": 20, // Exfiltration
	"T1566": 15, // Phishing
	"T1190": 25, // Exploit Public-Facing Application
	"T1046": 10, // Port Scan
}

// highValueRules get a flat bonus.
var highValueRules = map[string]int16{
	"rule-lateral-movement":     25,
	"rule-data-exfil":           20,
	"rule-host-process-anomaly": 15,
	"rule-ransomware":           30,
	"rule-port-scan":            10,
	"rule-dns-tunnel":           20,
}

func computeRiskScore(a *models.Alert) int16 {
	// Base: severity 1→20, 2→40, 3→60, 4→80, 5→100
	base := int16(a.Severity) * 20
	if base > 100 {
		base = 100
	}

	bonus := int16(0)

	// MITRE tactic bonus
	for _, mid := range a.MitreIDs {
		prefix := strings.ToUpper(mid)
		if idx := strings.IndexByte(prefix, '.'); idx != -1 {
			prefix = prefix[:idx]
		}
		if w, ok := tacticWeights[prefix]; ok && w > bonus {
			bonus = w
		}
	}

	// Rule-specific bonus
	if rb, ok := highValueRules[a.RuleID]; ok && rb > bonus {
		bonus = rb
	}

	score := base + bonus
	if score > 100 {
		score = 100
	}
	return score
}

// isFileHash returns true if s looks like an MD5/SHA1/SHA256 hex string.
func isFileHash(s string) bool {
	if len(s) != 32 && len(s) != 40 && len(s) != 64 {
		return false
	}
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

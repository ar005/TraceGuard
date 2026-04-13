// Package auth monitors /var/log/auth.log (or /var/log/secure on RHEL)
// for login successes, failures, and sudo executions.
// Emits LOGIN_SUCCESS, LOGIN_FAILED, and SUDO_EXEC events.

package auth

import (
	"bufio"
	"context"
	"io"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/youredr/edr-agent/internal/events"
	"github.com/youredr/edr-agent/pkg/types"
)

// Config for the auth monitor.
type Config struct {
	Enabled  bool
	LogPaths []string // defaults to ["/var/log/auth.log", "/var/log/secure"]
}

// Monitor tails auth logs and emits authentication events.
type Monitor struct {
	cfg    Config
	bus    events.Bus
	log    zerolog.Logger
	stopCh chan struct{}
	wg     sync.WaitGroup
}

// Compiled regexes for parsing common auth log patterns.
var (
	// sshd: Accepted publickey for alice from 10.0.0.1 port 22 ssh2
	reSSHAccepted = regexp.MustCompile(
		`sshd\[\d+\]: Accepted (\S+) for (\S+) from (\S+) port (\d+)`)
	// sshd: Failed password for bob from 10.0.0.2 port 22 ssh2
	reSSHFailed = regexp.MustCompile(
		`sshd\[\d+\]: Failed (\S+) for (?:invalid user )?(\S+) from (\S+) port (\d+)`)
	// sudo: alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/ls
	reSudo = regexp.MustCompile(
		`sudo:\s+(\S+)\s+:.*TTY=(\S+)\s*;.*USER=(\S+)\s*;\s*COMMAND=(.+)`)
	// su: pam_unix(su:session): session opened for user root by alice
	reSuSuccess = regexp.MustCompile(
		`su.*session opened for user (\S+)`)
	// login: Login failure on tty
	reLoginFailed = regexp.MustCompile(
		`login.*FAILED LOGIN.*\((\S+)\)`)
)

func New(cfg Config, bus events.Bus, log zerolog.Logger) *Monitor {
	if len(cfg.LogPaths) == 0 {
		cfg.LogPaths = []string{"/var/log/auth.log", "/var/log/secure"}
	}
	return &Monitor{
		cfg:    cfg,
		bus:    bus,
		log:    log.With().Str("monitor", "auth").Logger(),
		stopCh: make(chan struct{}),
	}
}

func (m *Monitor) Start(ctx context.Context) error {
	// Find the first readable auth log.
	var logPath string
	for _, p := range m.cfg.LogPaths {
		if _, err := os.Stat(p); err == nil {
			logPath = p
			break
		}
	}
	if logPath == "" {
		m.log.Warn().Strs("paths", m.cfg.LogPaths).Msg("no auth log found — auth monitor disabled")
		return nil
	}

	m.log.Info().Str("path", logPath).Msg("auth monitor started")
	m.wg.Add(1)
	go m.tailLoop(ctx, logPath)
	return nil
}

func (m *Monitor) Stop() {
	close(m.stopCh)
	m.wg.Wait()
}

func (m *Monitor) tailLoop(ctx context.Context, path string) {
	defer m.wg.Done()

	f, err := os.Open(path)
	if err != nil {
		m.log.Error().Err(err).Str("path", path).Msg("open auth log failed")
		return
	}
	defer f.Close()

	// Seek to end — only process new entries.
	if _, err := f.Seek(0, io.SeekEnd); err != nil {
		m.log.Warn().Err(err).Msg("seek to end failed, reading from current position")
	}

	scanner := bufio.NewScanner(f)
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-m.stopCh:
			return
		case <-ticker.C:
			for scanner.Scan() {
				line := scanner.Text()
				m.parseLine(line)
			}
			if scanner.Err() != nil {
				// Reopen file (log rotation).
				f.Close()
				f, err = os.Open(path)
				if err != nil {
					m.log.Warn().Err(err).Msg("reopen auth log failed")
					time.Sleep(5 * time.Second)
					continue
				}
				scanner = bufio.NewScanner(f)
			}
		}
	}
}

func (m *Monitor) parseLine(line string) {
	// SSH accepted login.
	if match := reSSHAccepted.FindStringSubmatch(line); match != nil {
		m.emit(types.EventLoginSuccess, &types.AuthEvent{
			Method:   match[1],
			Username: match[2],
			SourceIP: match[3],
			Service:  "sshd",
			RawLog:   line,
		})
		return
	}

	// SSH failed login.
	if match := reSSHFailed.FindStringSubmatch(line); match != nil {
		m.emit(types.EventLoginFailed, &types.AuthEvent{
			Method:   match[1],
			Username: match[2],
			SourceIP: match[3],
			Service:  "sshd",
			RawLog:   line,
		})
		return
	}

	// Sudo execution.
	if match := reSudo.FindStringSubmatch(line); match != nil {
		m.emit(types.EventSudoExec, &types.AuthEvent{
			Username:   match[1],
			TTY:        match[2],
			TargetUser: match[3],
			Command:    strings.TrimSpace(match[4]),
			Service:    "sudo",
			RawLog:     line,
		})
		return
	}

	// su session opened.
	if match := reSuSuccess.FindStringSubmatch(line); match != nil {
		m.emit(types.EventLoginSuccess, &types.AuthEvent{
			TargetUser: match[1],
			Service:    "su",
			RawLog:     line,
		})
		return
	}

	// Generic login failure.
	if match := reLoginFailed.FindStringSubmatch(line); match != nil {
		m.emit(types.EventLoginFailed, &types.AuthEvent{
			Username: match[1],
			Service:  "login",
			RawLog:   line,
		})
		return
	}
}

func (m *Monitor) emit(evType types.EventType, ev *types.AuthEvent) {
	ev.BaseEvent = types.BaseEvent{
		ID:        uuid.New().String(),
		Type:      evType,
		Timestamp: time.Now(),
		AgentID:   m.bus.AgentID(),
		Hostname:  m.bus.Hostname(),
	}

	// Set severity based on type.
	switch evType {
	case types.EventLoginFailed:
		ev.Severity = types.SeverityLow
	case types.EventSudoExec:
		ev.Severity = types.SeverityMedium
	default:
		ev.Severity = types.SeverityInfo
	}

	m.log.Debug().
		Str("type", string(evType)).
		Str("user", ev.Username).
		Str("service", ev.Service).
		Str("source_ip", ev.SourceIP).
		Msg("auth event")

	m.bus.Publish(ev)
}

// cmd/agent/main.go
// EDR Agent entrypoint.

package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/youredr/edr-agent/internal/agent"
	"github.com/youredr/edr-agent/internal/config"
	"github.com/youredr/edr-agent/internal/selfprotect"
	"github.com/youredr/edr-agent/internal/version"
)

var (
	flagConfig   = flag.String("config", "/etc/edr/agent.yaml", "path to config file")
	flagWatchdog = flag.Bool("watchdog", false, "run as watchdog parent process")
	flagVersion  = flag.Bool("version", false, "print version and exit")
)

func main() {
	flag.Parse()

	if *flagVersion {
		info := version.Get()
		fmt.Printf("edr-agent %s\n", info.String())
		os.Exit(0)
	}

	// Watchdog mode: this process monitors the child agent and restarts it.
	// Invoked automatically by systemd or manually with --watchdog.
	if *flagWatchdog {
		exe, _ := os.Executable()
		fmt.Fprintln(os.Stderr, "[watchdog] starting watchdog for", exe)
		selfprotect.RunWatchdog(exe, []string{"--config", *flagConfig})
		os.Exit(0)
	}

	// Check we're running as root (required for eBPF).
	if os.Getuid() != 0 {
		fmt.Fprintln(os.Stderr,
			"error: edr-agent must run as root or with CAP_BPF+CAP_SYS_ADMIN")
		os.Exit(1)
	}

	// Load configuration.
	cfg, err := config.Load(*flagConfig)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error loading config: %v\n", err)
		os.Exit(1)
	}

	// Create agent.
	a, err := agent.New(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error creating agent: %v\n", err)
		os.Exit(1)
	}

	// Run with cancellable context.
	ctx, cancel := context.WithCancel(context.Background())

	// Trap signals for clean shutdown.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)
	go func() {
		for sig := range sigCh {
			if sig == syscall.SIGHUP {
				fmt.Fprintln(os.Stderr, "SIGHUP: config reload not yet implemented")
				continue
			}
			fmt.Fprintf(os.Stderr, "received %s, shutting down\n", sig)
			cancel()
			return
		}
	}()

	if err := a.Start(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "agent error: %v\n", err)
		os.Exit(1)
	}
}

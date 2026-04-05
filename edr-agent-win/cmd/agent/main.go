// cmd/agent/main.go
// EDR Agent for Windows — entry point.
// Runs as a Windows Service or interactively (for debugging).

package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"golang.org/x/sys/windows/svc"

	"github.com/youredr/edr-agent-win/internal/agent"
	"github.com/youredr/edr-agent-win/internal/config"
	"github.com/youredr/edr-agent-win/internal/version"
)

const serviceName = "TraceGuardAgent"

var (
	flagConfig  = flag.String("config", `C:\ProgramData\TraceGuard\agent.yaml`, "path to config file")
	flagVersion = flag.Bool("version", false, "print version and exit")
	flagInstall = flag.Bool("install", false, "install as Windows service")
	flagRemove  = flag.Bool("remove", false, "remove Windows service")
	flagRun     = flag.Bool("run", false, "run interactively (not as service)")
)

func main() {
	flag.Parse()

	if *flagVersion {
		info := version.Get()
		fmt.Printf("edr-agent-win %s\n", info.String())
		os.Exit(0)
	}

	if *flagInstall {
		installService()
		return
	}
	if *flagRemove {
		removeService()
		return
	}

	// Detect if running as service or interactive.
	isService, err := svc.IsWindowsService()
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to detect service mode: %v\n", err)
		os.Exit(1)
	}

	if isService && !*flagRun {
		// Running as Windows Service.
		if err := svc.Run(serviceName, &TraceGuardService{}); err != nil {
			fmt.Fprintf(os.Stderr, "service run error: %v\n", err)
			os.Exit(1)
		}
		return
	}

	// Interactive mode.
	runInteractive()
}

func runInteractive() {
	cfg, err := config.Load(*flagConfig)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error loading config: %v\n", err)
		os.Exit(1)
	}

	a, err := agent.New(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error creating agent: %v\n", err)
		os.Exit(1)
	}

	ctx, cancel := context.WithCancel(context.Background())

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		sig := <-sigCh
		fmt.Fprintf(os.Stderr, "received %s, shutting down\n", sig)
		cancel()
	}()

	if err := a.Start(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "agent error: %v\n", err)
		os.Exit(1)
	}
}

// ─── Windows Service Handler ─────────────────────────────────────────────────

type TraceGuardService struct{}

func (s *TraceGuardService) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (ssec bool, errno uint32) {
	changes <- svc.Status{State: svc.StartPending}

	cfg, err := config.Load(*flagConfig)
	if err != nil {
		return true, 1
	}

	a, err := agent.New(cfg)
	if err != nil {
		return true, 1
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start agent in background.
	agentDone := make(chan error, 1)
	go func() {
		agentDone <- a.Start(ctx)
	}()

	changes <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}

	for {
		select {
		case c := <-r:
			switch c.Cmd {
			case svc.Interrogate:
				changes <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				changes <- svc.Status{State: svc.StopPending}
				cancel()
				<-agentDone
				return false, 0
			}
		case err := <-agentDone:
			if err != nil {
				return true, 1
			}
			return false, 0
		}
	}
}

// ─── Service Install / Remove ────────────────────────────────────────────────

func installService() {
	exe, err := os.Executable()
	if err != nil {
		fmt.Fprintf(os.Stderr, "cannot determine executable path: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("To install the TraceGuard Agent service, run:\n\n")
	fmt.Printf("  sc.exe create %s binpath= \"%s --config %s\" start= auto DisplayName= \"TraceGuard Endpoint Agent\"\n", serviceName, exe, *flagConfig)
	fmt.Printf("  sc.exe failure %s reset= 60 actions= restart/5000/restart/10000/restart/30000\n", serviceName)
	fmt.Printf("  sc.exe start %s\n\n", serviceName)
}

func removeService() {
	fmt.Printf("To remove the TraceGuard Agent service, run:\n\n")
	fmt.Printf("  sc.exe stop %s\n", serviceName)
	fmt.Printf("  sc.exe delete %s\n\n", serviceName)
}

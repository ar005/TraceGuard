// internal/monitor/usb/monitor.go
// USB device monitor for Windows — polls Win32_PnPEntity for USB storage devices.
//
// Tracks connected USB storage devices by device instance ID and emits
// USB_CONNECT / USB_DISCONNECT events when changes are detected.

package usb

import (
	"bufio"
	"bytes"
	"context"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/youredr/edr-agent-win/internal/events"
	"github.com/youredr/edr-agent-win/pkg/types"
)

// Config for the USB monitor.
type Config struct {
	PollIntervalS int
}

// Monitor polls for USB storage device changes.
type Monitor struct {
	cfg    Config
	bus    events.Bus
	log    zerolog.Logger
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// New creates a USB monitor.
func New(cfg Config, bus events.Bus, log zerolog.Logger) *Monitor {
	if cfg.PollIntervalS <= 0 {
		cfg.PollIntervalS = 10
	}
	return &Monitor{
		cfg: cfg,
		bus: bus,
		log: log.With().Str("monitor", "usb").Logger(),
	}
}

// usbDevice holds parsed USB device info.
type usbDevice struct {
	DeviceID    string
	Name        string
	Description string
	Manufacturer string
	Status      string
}

// Start begins polling for USB device changes.
func (m *Monitor) Start(ctx context.Context) error {
	ctx, m.cancel = context.WithCancel(ctx)
	m.wg.Add(1)
	go m.pollLoop(ctx)
	m.log.Info().Msg("USB monitor started (polling Win32_PnPEntity)")
	return nil
}

// Stop halts the USB monitor.
func (m *Monitor) Stop() {
	if m.cancel != nil {
		m.cancel()
	}
	m.wg.Wait()
	m.log.Info().Msg("USB monitor stopped")
}

func (m *Monitor) pollLoop(ctx context.Context) {
	defer m.wg.Done()

	known := make(map[string]usbDevice)
	for _, dev := range m.enumUSBDevices(ctx) {
		known[dev.DeviceID] = dev
	}
	m.log.Debug().Int("baseline_usb", len(known)).Msg("USB baseline captured")

	ticker := time.NewTicker(time.Duration(m.cfg.PollIntervalS) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			current := m.enumUSBDevices(ctx)
			currentMap := make(map[string]usbDevice)

			for _, dev := range current {
				currentMap[dev.DeviceID] = dev
				if _, exists := known[dev.DeviceID]; !exists {
					m.emitConnect(dev)
				}
			}

			for id, dev := range known {
				if _, exists := currentMap[id]; !exists {
					m.emitDisconnect(dev)
				}
			}

			known = currentMap
		}
	}
}

func (m *Monitor) enumUSBDevices(ctx context.Context) []usbDevice {
	cmdCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	cmd := exec.CommandContext(cmdCtx, "wmic", "path", "Win32_PnPEntity",
		"where", "Service='USBSTOR'",
		"get", "DeviceID,Name,Description,Manufacturer,Status",
		"/format:csv")
	out, err := cmd.Output()
	if err != nil {
		m.log.Debug().Err(err).Msg("wmic USB query failed")
		return nil
	}

	return parseUSBOutput(out)
}

func parseUSBOutput(data []byte) []usbDevice {
	var devices []usbDevice

	scanner := bufio.NewScanner(bytes.NewReader(data))
	headers := make(map[int]string)
	first := true

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		parts := strings.Split(line, ",")

		if first {
			first = false
			for i, h := range parts {
				headers[i] = strings.TrimSpace(h)
			}
			continue
		}

		dev := usbDevice{}
		for i, val := range parts {
			val = strings.TrimSpace(val)
			switch headers[i] {
			case "DeviceID":
				dev.DeviceID = val
			case "Name":
				dev.Name = val
			case "Description":
				dev.Description = val
			case "Manufacturer":
				dev.Manufacturer = val
			case "Status":
				dev.Status = val
			}
		}

		if dev.DeviceID != "" {
			devices = append(devices, dev)
		}
	}

	return devices
}

// extractVIDPID parses vendor/product IDs from a device instance ID.
// Format: USB\VID_xxxx&PID_yyyy\serial
func extractVIDPID(deviceID string) (vendorID, productID string) {
	upper := strings.ToUpper(deviceID)
	if idx := strings.Index(upper, "VID_"); idx >= 0 && idx+8 <= len(upper) {
		vendorID = upper[idx+4 : idx+8]
	}
	if idx := strings.Index(upper, "PID_"); idx >= 0 && idx+8 <= len(upper) {
		productID = upper[idx+4 : idx+8]
	}
	return
}

func (m *Monitor) emitConnect(dev usbDevice) {
	vid, pid := extractVIDPID(dev.DeviceID)

	ev := &types.USBDeviceEvent{
		BaseEvent: types.BaseEvent{
			ID:        uuid.New().String(),
			Type:      types.EventUSBConnect,
			Timestamp: time.Now(),
			AgentID:   m.bus.AgentID(),
			Hostname:  m.bus.Hostname(),
			Severity:  types.SeverityMedium,
			Tags:      []string{"usb", "storage"},
		},
		DeviceName: dev.Name,
		VendorID:   vid,
		ProductID:  pid,
		Vendor:     dev.Manufacturer,
		Product:    dev.Description,
		DevType:    "mass-storage",
	}

	m.bus.Publish(ev)
	m.log.Info().Str("device", dev.Name).Str("id", dev.DeviceID).Msg("USB device connected")
}

func (m *Monitor) emitDisconnect(dev usbDevice) {
	vid, pid := extractVIDPID(dev.DeviceID)

	ev := &types.USBDeviceEvent{
		BaseEvent: types.BaseEvent{
			ID:        uuid.New().String(),
			Type:      types.EventUSBDisconnect,
			Timestamp: time.Now(),
			AgentID:   m.bus.AgentID(),
			Hostname:  m.bus.Hostname(),
			Severity:  types.SeverityInfo,
			Tags:      []string{"usb", "storage"},
		},
		DeviceName: dev.Name,
		VendorID:   vid,
		ProductID:  pid,
		Vendor:     dev.Manufacturer,
		Product:    dev.Description,
		DevType:    "mass-storage",
	}

	m.bus.Publish(ev)
	m.log.Info().Str("device", dev.Name).Str("id", dev.DeviceID).Msg("USB device disconnected")
}

var _ interface {
	Start(context.Context) error
	Stop()
} = (*Monitor)(nil)

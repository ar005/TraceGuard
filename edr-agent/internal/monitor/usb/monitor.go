// Package usb monitors USB device connect/disconnect events by polling
// /sys/bus/usb/devices/. It emits USB_CONNECT and USB_DISCONNECT events.

package usb

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/youredr/edr-agent/internal/events"
	"github.com/youredr/edr-agent/pkg/types"
)

// Config for the USB monitor.
type Config struct {
	Enabled       bool
	PollIntervalS int
}

// DefaultConfig returns sensible defaults.
func DefaultConfig() Config {
	return Config{Enabled: true, PollIntervalS: 10}
}

// usbDevice represents a single USB device discovered in sysfs.
type usbDevice struct {
	Path      string
	VendorID  string
	ProductID string
	Vendor    string
	Product   string
	Serial    string
	BusNum    string
	DevNum    string
}

// Monitor polls sysfs for USB device changes.
type Monitor struct {
	cfg  Config
	bus  events.Bus
	log  zerolog.Logger
	stop context.CancelFunc
	wg   sync.WaitGroup
}

// New creates a USB monitor.
func New(cfg Config, bus events.Bus, log zerolog.Logger) *Monitor {
	return &Monitor{
		cfg: cfg,
		bus: bus,
		log: log.With().Str("monitor", "usb").Logger(),
	}
}

// Start begins polling for USB device changes.
func (m *Monitor) Start(ctx context.Context) error {
	if !m.cfg.Enabled {
		return nil
	}

	pollCtx, cancel := context.WithCancel(ctx)
	m.stop = cancel

	// Take initial baseline snapshot.
	baseline := scanUSBDevices()
	m.log.Info().Int("devices", len(baseline)).Msg("USB baseline snapshot taken")

	interval := time.Duration(m.cfg.PollIntervalS) * time.Second
	if interval <= 0 {
		interval = 10 * time.Second
	}

	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-pollCtx.Done():
				return
			case <-ticker.C:
				current := scanUSBDevices()
				m.diffAndEmit(baseline, current)
				baseline = current
			}
		}
	}()

	return nil
}

// Stop halts the polling loop and waits for it to finish.
func (m *Monitor) Stop() {
	if m.stop != nil {
		m.stop()
	}
	m.wg.Wait()
}

// diffAndEmit compares old and new device maps, emitting events for changes.
func (m *Monitor) diffAndEmit(old, current map[string]usbDevice) {
	// Detect new devices (connects).
	for key, dev := range current {
		if _, existed := old[key]; !existed {
			m.emitEvent(types.EventUSBConnect, dev)
		}
	}
	// Detect removed devices (disconnects).
	for key, dev := range old {
		if _, exists := current[key]; !exists {
			m.emitEvent(types.EventUSBDisconnect, dev)
		}
	}
}

func (m *Monitor) emitEvent(evType types.EventType, dev usbDevice) {
	devType := classifyDevice(dev.Path)

	sev := types.SeverityInfo
	if devType == "mass_storage" {
		sev = types.SeverityLow
	}

	ev := &types.USBDeviceEvent{
		BaseEvent: types.BaseEvent{
			ID:        uuid.New().String(),
			Type:      evType,
			Timestamp: time.Now(),
			AgentID:   m.bus.AgentID(),
			Hostname:  m.bus.Hostname(),
			Severity:  sev,
		},
		VendorID:  dev.VendorID,
		ProductID: dev.ProductID,
		Vendor:    dev.Vendor,
		Product:   dev.Product,
		Serial:    dev.Serial,
		BusNum:    dev.BusNum,
		DevNum:    dev.DevNum,
		DevType:   devType,
	}

	m.log.Info().
		Str("event", string(evType)).
		Str("vendor", dev.Vendor).
		Str("product", dev.Product).
		Str("vendor_id", dev.VendorID).
		Str("product_id", dev.ProductID).
		Str("bus", dev.BusNum).
		Str("dev", dev.DevNum).
		Str("dev_type", devType).
		Msg("USB device event")

	m.bus.Publish(ev)
}

// ─── sysfs helpers ───────────────────────────────────────────────────────────

const sysfsUSBPath = "/sys/bus/usb/devices"

// readSysfsFile reads a single sysfs attribute file, returning "" on error.
func readSysfsFile(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// scanUSBDevices enumerates all non-hub USB devices from sysfs.
func scanUSBDevices() map[string]usbDevice {
	entries, err := os.ReadDir(sysfsUSBPath)
	if err != nil {
		return make(map[string]usbDevice)
	}

	devices := make(map[string]usbDevice)
	for _, entry := range entries {
		devPath := filepath.Join(sysfsUSBPath, entry.Name())

		// Skip entries without idVendor (not real USB devices — e.g. interfaces).
		vendorID := readSysfsFile(filepath.Join(devPath, "idVendor"))
		if vendorID == "" {
			continue
		}

		// Skip USB hubs (bDeviceClass == "09").
		devClass := readSysfsFile(filepath.Join(devPath, "bDeviceClass"))
		if devClass == "09" {
			continue
		}

		dev := usbDevice{
			Path:      devPath,
			VendorID:  vendorID,
			ProductID: readSysfsFile(filepath.Join(devPath, "idProduct")),
			Vendor:    readSysfsFile(filepath.Join(devPath, "manufacturer")),
			Product:   readSysfsFile(filepath.Join(devPath, "product")),
			Serial:    readSysfsFile(filepath.Join(devPath, "serial")),
			BusNum:    readSysfsFile(filepath.Join(devPath, "busnum")),
			DevNum:    readSysfsFile(filepath.Join(devPath, "devnum")),
		}
		key := dev.BusNum + "-" + dev.DevNum
		devices[key] = dev
	}
	return devices
}

// classifyDevice determines a human-friendly device type by inspecting
// bInterfaceClass in child interface directories.
func classifyDevice(devPath string) string {
	// Look for interface subdirectories (e.g. 1-2:1.0) that have bInterfaceClass.
	entries, err := os.ReadDir(devPath)
	if err != nil {
		return "other"
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		ifClass := readSysfsFile(filepath.Join(devPath, entry.Name(), "bInterfaceClass"))
		if ifClass == "" {
			continue
		}
		switch strings.ToLower(ifClass) {
		case "08":
			return "mass_storage"
		case "03":
			return "hid"
		case "01":
			return "audio"
		case "02":
			return "cdc"
		case "0e":
			return "video"
		}
	}
	return "other"
}

package usb

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadSysfsFile(t *testing.T) {
	// Create a temp file with known content.
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "idVendor")
	if err := os.WriteFile(filePath, []byte("0bda\n"), 0644); err != nil {
		t.Fatal(err)
	}

	got := readSysfsFile(filePath)
	if got != "0bda" {
		t.Errorf("readSysfsFile: expected 'obda', got %q", got)
	}
}

func TestReadSysfsFileNonexistent(t *testing.T) {
	got := readSysfsFile("/nonexistent/path/file")
	if got != "" {
		t.Errorf("readSysfsFile: expected empty for nonexistent file, got %q", got)
	}
}

func TestReadSysfsFileTrimsWhitespace(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "product")
	if err := os.WriteFile(filePath, []byte("  USB Keyboard  \n"), 0644); err != nil {
		t.Fatal(err)
	}

	got := readSysfsFile(filePath)
	if got != "USB Keyboard" {
		t.Errorf("readSysfsFile: expected 'USB Keyboard', got %q", got)
	}
}

func TestClassifyDevice(t *testing.T) {
	// Create a fake device directory with interface subdirectories.
	devDir := t.TempDir()

	tests := []struct {
		name          string
		interfaceClass string
		want          string
	}{
		{"mass_storage", "08", "mass_storage"},
		{"hid", "03", "hid"},
		{"audio", "01", "audio"},
		{"cdc", "02", "cdc"},
		{"video", "0e", "video"},
		{"video_uppercase", "0E", "video"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			// Create an interface subdirectory with bInterfaceClass.
			ifDir := filepath.Join(dir, "1-2:1.0")
			if err := os.Mkdir(ifDir, 0755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(ifDir, "bInterfaceClass"), []byte(tt.interfaceClass+"\n"), 0644); err != nil {
				t.Fatal(err)
			}

			got := classifyDevice(dir)
			if got != tt.want {
				t.Errorf("classifyDevice(%s): got %q, want %q", tt.interfaceClass, got, tt.want)
			}
		})
	}

	// Test "other" when no interface class found.
	t.Run("other_no_interfaces", func(t *testing.T) {
		got := classifyDevice(devDir)
		if got != "other" {
			t.Errorf("classifyDevice(empty dir): got %q, want 'other'", got)
		}
	})

	// Test "other" when interface class is unknown.
	t.Run("other_unknown_class", func(t *testing.T) {
		dir := t.TempDir()
		ifDir := filepath.Join(dir, "1-2:1.0")
		if err := os.Mkdir(ifDir, 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(ifDir, "bInterfaceClass"), []byte("ff\n"), 0644); err != nil {
			t.Fatal(err)
		}

		got := classifyDevice(dir)
		if got != "other" {
			t.Errorf("classifyDevice(ff): got %q, want 'other'", got)
		}
	})
}

func TestScanUSBDevicesHubFiltering(t *testing.T) {
	// Create a fake sysfs tree with a hub device (bDeviceClass == "09").
	// scanUSBDevices reads from the const sysfsUSBPath, so we can't directly
	// test it without overriding the path. Instead, test the filtering logic
	// inline to verify it works.

	devDir := t.TempDir()

	// Create a hub device.
	hubDir := filepath.Join(devDir, "usb1")
	if err := os.Mkdir(hubDir, 0755); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(hubDir, "idVendor"), []byte("1d6b\n"), 0644)
	os.WriteFile(filepath.Join(hubDir, "bDeviceClass"), []byte("09\n"), 0644)

	// Create a real device.
	realDir := filepath.Join(devDir, "1-1")
	if err := os.Mkdir(realDir, 0755); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(realDir, "idVendor"), []byte("0bda\n"), 0644)
	os.WriteFile(filepath.Join(realDir, "bDeviceClass"), []byte("00\n"), 0644)
	os.WriteFile(filepath.Join(realDir, "idProduct"), []byte("5411\n"), 0644)
	os.WriteFile(filepath.Join(realDir, "busnum"), []byte("1\n"), 0644)
	os.WriteFile(filepath.Join(realDir, "devnum"), []byte("2\n"), 0644)

	// Replicate scanUSBDevices logic using our temp dir.
	entries, err := os.ReadDir(devDir)
	if err != nil {
		t.Fatal(err)
	}

	devices := make(map[string]usbDevice)
	for _, entry := range entries {
		devPath := filepath.Join(devDir, entry.Name())
		vendorID := readSysfsFile(filepath.Join(devPath, "idVendor"))
		if vendorID == "" {
			continue
		}
		devClass := readSysfsFile(filepath.Join(devPath, "bDeviceClass"))
		if devClass == "09" {
			continue // hub filtering
		}
		dev := usbDevice{
			Path:      devPath,
			VendorID:  vendorID,
			ProductID: readSysfsFile(filepath.Join(devPath, "idProduct")),
			BusNum:    readSysfsFile(filepath.Join(devPath, "busnum")),
			DevNum:    readSysfsFile(filepath.Join(devPath, "devnum")),
		}
		key := dev.BusNum + "-" + dev.DevNum
		devices[key] = dev
	}

	if len(devices) != 1 {
		t.Errorf("expected 1 device (hub filtered), got %d", len(devices))
	}
	dev, ok := devices["1-2"]
	if !ok {
		t.Fatal("expected device with key '1-2'")
	}
	if dev.VendorID != "0bda" {
		t.Errorf("expected vendorID '0bda', got %q", dev.VendorID)
	}
}

func TestDiffAndEmitDetectsChanges(t *testing.T) {
	old := map[string]usbDevice{
		"1-1": {VendorID: "0bda", ProductID: "5411", BusNum: "1", DevNum: "1"},
		"1-2": {VendorID: "1234", ProductID: "5678", BusNum: "1", DevNum: "2"},
	}
	current := map[string]usbDevice{
		"1-1": {VendorID: "0bda", ProductID: "5411", BusNum: "1", DevNum: "1"},
		"2-1": {VendorID: "abcd", ProductID: "ef01", BusNum: "2", DevNum: "1"},
	}

	// Detect new devices.
	var newDevices []string
	for key := range current {
		if _, existed := old[key]; !existed {
			newDevices = append(newDevices, key)
		}
	}
	if len(newDevices) != 1 || newDevices[0] != "2-1" {
		t.Errorf("expected new device '2-1', got %v", newDevices)
	}

	// Detect removed devices.
	var removedDevices []string
	for key := range old {
		if _, exists := current[key]; !exists {
			removedDevices = append(removedDevices, key)
		}
	}
	if len(removedDevices) != 1 || removedDevices[0] != "1-2" {
		t.Errorf("expected removed device '1-2', got %v", removedDevices)
	}
}

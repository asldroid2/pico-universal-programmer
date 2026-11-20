package usbprobe

import (
	"sort"
	"strings"
)

const (
	// DefaultVID is the official Raspberry Pi USB Vendor ID.
	DefaultVID uint16 = 0x2E8A
	// DefaultPID (0x0000) selects wildcard matching for any "Pico Universal*" product on DefaultVID.
	DefaultPID uint16 = 0x0000
	// ProductPrefix is the canonical USB iProduct prefix for Pico Universal firmware.
	ProductPrefix = "Pico Universal"
)

// RawInterfaceNode represents a single discovered OS USB interface before composite correlation.
type RawInterfaceNode struct {
	VID          uint16
	PID          uint16
	Serial       string
	Product      string
	InterfaceNum int
	DevPath      string // e.g. /dev/ttyACM0, COM7, or USB bus path
}

// ProbeDevice represents a correlated composite Pico Universal hardware probe.
type ProbeDevice struct {
	Serial   string
	VID      uint16
	PID      uint16
	Product  string
	DAPPath  string // IF 0 CMSIS-DAP v2
	GDBPort  string // IF 1..2 CH32 SWIO CDC
	UARTPort string // IF 3..4 Target UART CDC
	CtrlPath string // IF 5 Control/Telemetry
}

// CorrelateNodes deterministically groups raw USB interfaces by Serial (sorted by Serial
// ascending), maps IF 0 -> DAPPath, IF 1..2 -> GDBPort, IF 3..4 -> UARTPort, IF 5 -> CtrlPath,
// and applies either wildcard product matching (pid == 0: Product starting with "Pico Universal"
// on VID 0x2E8A) or strict exact VID+PID matching (pid != 0).
func CorrelateNodes(nodes []RawInterfaceNode, vid, pid uint16) []ProbeDevice {
	effectiveVID := vid
	if effectiveVID == 0 {
		effectiveVID = DefaultVID
	}

	bySerial := make(map[string]*ProbeDevice)
	hasPicoProduct := make(map[string]bool)

	for _, n := range nodes {
		if n.VID != effectiveVID {
			continue
		}
		if pid != 0 && n.PID != pid {
			continue
		}
		serial := strings.TrimSpace(n.Serial)
		if serial == "" {
			continue
		}
		prod := strings.TrimSpace(n.Product)
		if strings.HasPrefix(prod, ProductPrefix) {
			hasPicoProduct[serial] = true
		}

		p, exists := bySerial[serial]
		if !exists {
			p = &ProbeDevice{
				Serial:  serial,
				VID:     n.VID,
				PID:     n.PID,
				Product: prod,
			}
			bySerial[serial] = p
		} else if p.Product == "" && prod != "" {
			p.Product = prod
		}

		if n.DevPath == "" {
			continue
		}
		switch n.InterfaceNum {
		case 0:
			p.DAPPath = n.DevPath
			if prod != "" {
				p.Product = prod
			}
		case 1:
			p.GDBPort = n.DevPath
		case 2:
			if p.GDBPort == "" {
				p.GDBPort = n.DevPath
			}
		case 3:
			p.UARTPort = n.DevPath
		case 4:
			if p.UARTPort == "" {
				p.UARTPort = n.DevPath
			}
		case 5:
			p.CtrlPath = n.DevPath
		}
	}

	out := make([]ProbeDevice, 0, len(bySerial))
	for serial, p := range bySerial {
		if pid == 0 && !hasPicoProduct[serial] {
			continue
		}
		out = append(out, *p)
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].Serial != out[j].Serial {
			return out[i].Serial < out[j].Serial
		}
		if out[i].VID != out[j].VID {
			return out[i].VID < out[j].VID
		}
		return out[i].PID < out[j].PID
	})
	return out
}

// DiscoverProbes enumerates composite Pico Universal probes on the current OS,
// optionally filtering by hardware serial number (case-insensitive).
func DiscoverProbes(filterSerial string, vid, pid uint16) ([]ProbeDevice, error) {
	effectiveVID := vid
	if effectiveVID == 0 {
		effectiveVID = DefaultVID
	}
	nodes, err := collectOSInterfaceNodes(effectiveVID, pid)
	if err != nil {
		return nil, err
	}
	probes := CorrelateNodes(nodes, effectiveVID, pid)
	wantSerial := strings.TrimSpace(filterSerial)
	if wantSerial == "" {
		return probes, nil
	}

	filtered := make([]ProbeDevice, 0, 1)
	for _, p := range probes {
		if strings.EqualFold(p.Serial, wantSerial) {
			filtered = append(filtered, p)
		}
	}
	return filtered, nil
}

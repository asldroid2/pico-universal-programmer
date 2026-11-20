package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"strings"

	"github.com/nfsahsn/pico-universal-programmer/host/internal/usbprobe"
)

// IF 5 Vendor Control framing constants matching firmware/control_telemetry.h.
const (
	ctrlCmdCH32Unbrick byte = 0x05

	ctrlStatusOK           byte = 0x00
	ctrlStatusUnsupported  byte = 0x02
	ctrlStatusBusy         byte = 0x03
	ctrlStatusFaultLatched byte = 0x04
)

func runRecover(ctx cliContext, args []string) int {
	fs := flag.NewFlagSet("pu recover", flag.ContinueOnError)
	fs.SetOutput(ctx.stderr)

	familyFlag := fs.String("family", "", "Target MCU family to recover (ch32v003|stm32f1|stm32f4)")
	serialFlag := fs.String("serial", "", "Select specific Pico Universal probe hardware serial number")
	pidFlag := fs.String("pid", "", "Approved USB PID in hex (overrides PU_USB_PID)")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}

	family := strings.ToLower(strings.TrimSpace(*familyFlag))
	if family == "ch32v" {
		family = "ch32v003"
	}
	switch family {
	case "ch32v003", "stm32f1", "stm32f4":
	case "":
		fmt.Fprintln(ctx.stderr, "pu recover: --family is required (ch32v003|stm32f1|stm32f4)")
		return 2
	default:
		fmt.Fprintf(ctx.stderr, "pu recover: unsupported recovery family %q (expected ch32v003, stm32f1, or stm32f4)\n", *familyFlag)
		return 2
	}

	probe, err := resolveSingleProbe(ctx, *serialFlag, *pidFlag)
	if err != nil {
		fmt.Fprintf(ctx.stderr, "pu recover: %v\n", err)
		return 1
	}

	lk, err := usbprobe.AcquireSessionLock(probe.Serial)
	if err != nil {
		fmt.Fprintf(ctx.stderr, "pu recover: %v\n", err)
		return 1
	}
	defer lk.Close()

	if family == "ch32v003" {
		return recoverCH32V003(ctx, probe)
	}
	return recoverSTM32(ctx, probe, family)
}

func recoverCH32V003(ctx cliContext, probe usbprobe.ProbeDevice) int {
	if ctx.ctrlTransceiver != nil {
		resp, err := ctx.ctrlTransceiver(probe, []byte{ctrlCmdCH32Unbrick})
		if err != nil {
			fmt.Fprintf(ctx.stderr, "pu recover: IF 5 CH32 unbrick control request failed: %v\n", err)
			return 1
		}
		if len(resp) >= 2 && resp[0] == ctrlCmdCH32Unbrick {
			switch resp[1] {
			case ctrlStatusOK:
				fmt.Fprintf(ctx.stdout, "CH32V003 hardware VTARG power-cycle + SWIO hold unbrick succeeded on probe %s.\n", probe.Serial)
				fmt.Fprintln(ctx.stdout, "Next step: run 'pu check --family ch32v003' or 'pu upload --family ch32v003 --file <fw.elf>'.")
				return 0
			case ctrlStatusBusy:
				fmt.Fprintln(ctx.stderr, "pu recover: probe debug engine is busy; close active GDB/OpenOCD sessions and retry")
				return 1
			case ctrlStatusFaultLatched:
				fmt.Fprintln(ctx.stderr, "pu recover: probe VTARG overcurrent fault is latched; inspect target wiring for shorts")
				return 1
			case ctrlStatusUnsupported:
				// Fall through to guided manual power-cycle procedure for PU_BOARD_PICO dev hardware.
			default:
				fmt.Fprintf(ctx.stderr, "pu recover: probe reported CH32 unbrick error status 0x%02x\n", resp[1])
				return 1
			}
		}
	}

	fmt.Fprintf(ctx.stdout, "CH32V003 Guided Power-Cycle Unbrick (Probe %s):\n", probe.Serial)
	fmt.Fprintln(ctx.stdout, "  1. Verify GND is shared and a 1 kΩ pull-up resistor connects SWIO (PD1) to 3.3 V (required on Pico dev board).")
	fmt.Fprintln(ctx.stdout, "  2. Disconnect CH32V003 VDD (3.3 V) for 2 seconds to clear any PD1 GPIO sketch remap or brownout latch.")
	fmt.Fprintln(ctx.stdout, "  3. Reconnect CH32V003 VDD while immediately running 'pu upload --family ch32v003 --file <clean.elf>' to halt before user code executes.")
	fmt.Fprintln(ctx.stdout, "  4. Verify recovery with 'pu check --family ch32v003'.")
	return 0
}

func recoverSTM32(ctx cliContext, probe usbprobe.ProbeDevice, family string) int {
	ocdBin, err := ctx.cmdRunner.LookPath("openocd")
	if err != nil {
		fmt.Fprintf(ctx.stderr, "pu recover: openocd not found in PATH: %v\n", err)
		return 1
	}

	var args []string
	switch family {
	case "stm32f1":
		args = []string{
			"-f", "interface/cmsis-dap.cfg",
			"-c", "adapter serial " + probe.Serial,
			"-c", "transport select swd",
			"-c", "set CPUTAPID 0",
			"-f", "target/stm32f1x.cfg",
			"-c", "adapter speed 100; reset_config srst_only srst_nogate connect_assert_srst; init; reset halt; stm32f1x unlock 0; stm32f1x mass_erase 0; reset halt; exit",
		}
	case "stm32f4":
		args = []string{
			"-f", "interface/cmsis-dap.cfg",
			"-c", "adapter serial " + probe.Serial,
			"-c", "transport select swd",
			"-f", "target/stm32f4x.cfg",
			"-c", "adapter speed 100; reset_config srst_only srst_nogate connect_assert_srst; init; reset halt; stm32f2x unlock 0; stm32f2x mass_erase 0; reset halt; exit",
		}
	}

	var outBuf, errBuf bytes.Buffer
	if err := ctx.cmdRunner.Run(commandSpec{Name: ocdBin, Args: args}, &outBuf, &errBuf); err != nil {
		fmt.Fprintf(ctx.stderr, "pu recover: %s mass erase failed: %v (%s)\n", family, err, strings.TrimSpace(errBuf.String()))
		return 1
	}

	fmt.Fprintf(ctx.stdout, "Recovered %s target via connect_assert_srst unlock + mass_erase on probe %s.\n", family, probe.Serial)
	fmt.Fprintln(ctx.stdout, "Note: power-cycle target VDD if flash Option Bytes (RDP) were previously locked.")
	return 0
}

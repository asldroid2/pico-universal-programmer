package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nfsahsn/pico-universal-programmer/host/internal/puid"
	"github.com/nfsahsn/pico-universal-programmer/host/internal/usbprobe"
)

func singleFakeProbe() func(vid, pid uint16) ([]usbprobe.ProbeDevice, error) {
	return func(vid, pid uint16) ([]usbprobe.ProbeDevice, error) {
		return []usbprobe.ProbeDevice{
			{
				Serial:   "E660583883278628",
				VID:      0x2E8A,
				PID:      0x1050,
				Product:  "Pico Universal",
				DAPPath:  "/dev/bus/usb/001/010",
				GDBPort:  "/dev/ttyACM0",
				UARTPort: "/dev/ttyACM1",
				CtrlPath: "/dev/bus/usb/001/010:1.5",
			},
		}, nil
	}
}

func TestPUCheckSubcommandJSONHumanAndMultiProbeDisambiguation(t *testing.T) {
	t.Setenv("PU_LOCK_DIR", filepath.Join(t.TempDir(), "locks"))

	runner := &fakeCommandRunner{
		bins: map[string]string{
			"openocd":            "/usr/bin/openocd",
			"riscv-none-elf-gdb": "/usr/bin/riscv-none-elf-gdb",
		},
		onRun: func(cmd commandSpec, stdout, stderr io.Writer) error {
			fmt.Fprintln(stderr, "Info : SWD DPIDR 0x1ba01477")
			fmt.Fprintln(stdout, "0xe0042000: 20036410")
			fmt.Fprintln(stdout, "0x1ffff7e0: 0040")
			return nil
		},
	}

	// 1. Genuine STM32F1 JSON output -> exit 0, Ready=true
	var out, errBuf bytes.Buffer
	code := runWithEnv([]string{"check", "--family", "stm32f1", "--json"}, cliEnv{
		stdout:         &out,
		stderr:         &errBuf,
		cmdRunner:      runner,
		discoverProbes: singleFakeProbe(),
	})
	if code != 0 {
		t.Fatalf("pu check stm32f1 --json failed: code=%d stderr=%s", code, errBuf.String())
	}
	var rep puid.CheckReport
	if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
		t.Fatalf("invalid JSON from pu check: %v\n%s", err, out.String())
	}
	if !rep.Ready || rep.IsClone || rep.FlashKB != 64 || rep.ProbeSerial != "E660583883278628" {
		t.Fatalf("unexpected CheckReport: %+v", rep)
	}

	// 2. CH32V003 ERR_NO_REPLY human output -> exit 1, prints all 5 causes
	runner.onRun = func(cmd commandSpec, stdout, stderr io.Writer) error {
		fmt.Fprintln(stdout, "PUID1:ERR_NO_REPLY")
		return nil
	}
	out.Reset()
	errBuf.Reset()
	code = runWithEnv([]string{"check", "--family", "ch32v003"}, cliEnv{
		stdout:         &out,
		stderr:         &errBuf,
		cmdRunner:      runner,
		discoverProbes: singleFakeProbe(),
	})
	if code == 0 {
		t.Fatalf("expected non-zero exit code for PUID1:ERR_NO_REPLY, got 0")
	}
	lowerOut := strings.ToLower(out.String())
	for _, want := range []string{"power", "ground", "1 k", "pd1", "read protection"} {
		if !strings.Contains(lowerOut, want) {
			t.Fatalf("missing %q in pu check human output:\n%s", want, out.String())
		}
	}

	// 3. Multiple probes without --serial must fail with clear disambiguation guidance
	twoProbes := func(vid, pid uint16) ([]usbprobe.ProbeDevice, error) {
		return []usbprobe.ProbeDevice{
			{Serial: "E660AAAA00000001", VID: 0x2E8A, PID: 0x1050, GDBPort: "/dev/ttyACM0"},
			{Serial: "E660BBBB00000002", VID: 0x2E8A, PID: 0x1050, GDBPort: "/dev/ttyACM2"},
		}, nil
	}
	out.Reset()
	errBuf.Reset()
	code = runWithEnv([]string{"check", "--family", "ch32v003"}, cliEnv{
		stdout:         &out,
		stderr:         &errBuf,
		cmdRunner:      runner,
		discoverProbes: twoProbes,
	})
	if code == 0 || !strings.Contains(errBuf.String(), "--serial") {
		t.Fatalf("expected --serial disambiguation error, got code=%d stderr=%s", code, errBuf.String())
	}
}

func TestPUUploadDirectCLIAndArduinoRecipeIntegration(t *testing.T) {
	t.Setenv("PU_LOCK_DIR", filepath.Join(t.TempDir(), "locks"))

	dir := t.TempDir()
	elf := filepath.Join(dir, "sketch.elf")
	boot := filepath.Join(dir, "sketch.bootloader.bin")
	part := filepath.Join(dir, "sketch.partitions.bin")
	app := filepath.Join(dir, "sketch.bin")
	_ = os.WriteFile(elf, []byte("\x7fELF-test"), 0o600)
	_ = os.WriteFile(boot, bytes.Repeat([]byte{0xAA}, 4096), 0o600)
	_ = os.WriteFile(part, bytes.Repeat([]byte{0xBB}, 2048), 0o600)
	_ = os.WriteFile(app, bytes.Repeat([]byte{0xCC}, 8192), 0o600)

	runner := &fakeCommandRunner{
		bins: map[string]string{
			"openocd":            "/usr/bin/openocd",
			"riscv-none-elf-gdb": "/usr/bin/riscv-none-elf-gdb",
		},
	}

	// 1. Direct CLI: pu upload --family stm32f4 --file <elf> --serial E660583883278628
	var out, errBuf bytes.Buffer
	code := runWithEnv([]string{
		"upload",
		"--family", "stm32f4",
		"--file", elf,
		"--serial", "E660583883278628",
	}, cliEnv{
		stdout:         &out,
		stderr:         &errBuf,
		cmdRunner:      runner,
		discoverProbes: singleFakeProbe(),
	})
	if code != 0 {
		t.Fatalf("pu upload stm32f4 failed: code=%d stderr=%s", code, errBuf.String())
	}
	if len(runner.ran) != 1 || !strings.Contains(strings.Join(runner.ran[0].args, " "), "target/stm32f4x.cfg") {
		t.Fatalf("unexpected stm32f4 OpenOCD invocation: %+v", runner.ran)
	}

	// 2. Arduino IDE 2 platform.local.txt recipe invocation (--core esp32 --fqbn ... --elf ... --segment ... -v)
	runner.ran = nil
	out.Reset()
	errBuf.Reset()
	code = runWithEnv([]string{
		"upload",
		"--core", "esp32",
		"--fqbn", "esp32:esp32:esp32:UploadSpeed=921600",
		"--board", "ESP32_DEV",
		"--elf", elf,
		"--segment", "0x1000:" + boot,
		"--segment", "0x8000:" + part,
		"--segment", "0x10000:" + app,
		"-v",
	}, cliEnv{
		stdout:         &out,
		stderr:         &errBuf,
		cmdRunner:      runner,
		discoverProbes: singleFakeProbe(),
	})
	if code != 0 {
		t.Fatalf("Arduino recipe esp32 upload failed: code=%d stderr=%s", code, errBuf.String())
	}
	if len(runner.ran) != 1 || !strings.Contains(strings.Join(runner.ran[0].args, " "), "program_esp") {
		t.Fatalf("unexpected esp32 OpenOCD invocation: %+v", runner.ran)
	}

	// 3. Sector overlap via CLI --segment must return non-zero and never invoke OpenOCD!
	runner.ran = nil
	out.Reset()
	errBuf.Reset()
	code = runWithEnv([]string{
		"upload",
		"--family", "esp32",
		"--segment", "0x1000:" + boot,
		"--segment", "0x1800:" + part,
	}, cliEnv{
		stdout:         &out,
		stderr:         &errBuf,
		cmdRunner:      runner,
		discoverProbes: singleFakeProbe(),
	})
	if code == 0 || len(runner.ran) != 0 {
		t.Fatalf("expected CLI upload sector overlap failure with 0 OpenOCD runs, got code=%d runs=%d", code, len(runner.ran))
	}
}

func TestPUGDBPipeStdioAndListenModes(t *testing.T) {
	t.Setenv("PU_LOCK_DIR", filepath.Join(t.TempDir(), "locks"))

	// 1. Stdio mode (with --family ch32v flag used by Arduino debug_custom.json)
	probeServer, probePort := net.Pipe()
	go func() {
		defer probeServer.Close()
		buf := make([]byte, 5)
		if _, err := io.ReadFull(probeServer, buf); err == nil && string(buf) == "$g#67" {
			_, _ = probeServer.Write([]byte("+$00000000#80"))
		}
	}()

	inBuf := bytes.NewBufferString("$g#67")
	var out, errBuf bytes.Buffer
	code := runWithEnv([]string{"gdb-pipe", "--family", "ch32v", "--serial", "E660583883278628"}, cliEnv{
		stdin:          inBuf,
		stdout:         &out,
		stderr:         &errBuf,
		discoverProbes: singleFakeProbe(),
		portOpener: func(string) (io.ReadWriteCloser, error) {
			return probePort, nil
		},
	})
	if code != 0 {
		t.Fatalf("pu gdb-pipe stdio failed: code=%d stderr=%s", code, errBuf.String())
	}
	if out.String() != "+$00000000#80" {
		t.Fatalf("stdio stdout must contain pure RSP bytes only, got %q", out.String())
	}

	// 2. TCP --listen mode for VS Code cortex-debug
	probeServer2, probePort2 := net.Pipe()
	go func() {
		defer probeServer2.Close()
		buf := make([]byte, 5)
		if _, err := io.ReadFull(probeServer2, buf); err == nil && string(buf) == "$D#44" {
			_, _ = probeServer2.Write([]byte("+$OK#9a"))
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	addrCh := make(chan net.Addr, 1)
	doneCh := make(chan int, 1)

	var tcpOut, tcpErr bytes.Buffer
	go func() {
		doneCh <- runWithEnv([]string{"gdb-pipe", "--listen", "127.0.0.1:0"}, cliEnv{
			ctx:            ctx,
			stdout:         &tcpOut,
			stderr:         &tcpErr,
			discoverProbes: singleFakeProbe(),
			portOpener: func(string) (io.ReadWriteCloser, error) {
				return probePort2, nil
			},
			onGDBListen: func(a net.Addr) {
				addrCh <- a
			},
		})
	}()

	bound := <-addrCh
	conn, err := net.DialTimeout("tcp", bound.String(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial %s: %v", bound, err)
	}
	_, _ = conn.Write([]byte("$D#44"))
	resp := make([]byte, 7)
	if _, err := io.ReadFull(conn, resp); err != nil || string(resp) != "+$OK#9a" {
		_ = conn.Close()
		t.Fatalf("unexpected TCP response %q err=%v", string(resp), err)
	}
	_ = conn.Close()

	select {
	case exitCode := <-doneCh:
		if exitCode != 0 {
			t.Fatalf("pu gdb-pipe --listen failed: code=%d stderr=%s", exitCode, tcpErr.String())
		}
	case <-time.After(2 * time.Second):
		cancel()
		t.Fatal("pu gdb-pipe --listen hung after client disconnect")
	}
}

func TestPURecoverCH32AndSTM32MassErase(t *testing.T) {
	t.Setenv("PU_LOCK_DIR", filepath.Join(t.TempDir(), "locks"))

	// 1. CH32V003 IF 5 hardware VTARG power-cycle unbrick (PU_CTRL_CMD_CH32_UNBRICK = 0x05)
	var out, errBuf bytes.Buffer
	var sentCtrl []byte
	code := runWithEnv([]string{"recover", "--family", "ch32v003"}, cliEnv{
		stdout:         &out,
		stderr:         &errBuf,
		discoverProbes: singleFakeProbe(),
		ctrlTransceiver: func(_ usbprobe.ProbeDevice, req []byte) ([]byte, error) {
			sentCtrl = append([]byte(nil), req...)
			return []byte{0x05, 0x00}, nil
		},
	})
	if code != 0 || len(sentCtrl) != 1 || sentCtrl[0] != 0x05 {
		t.Fatalf("CH32 IF5 recover failed: code=%d sent=%x stderr=%s", code, sentCtrl, errBuf.String())
	}

	// 2. CH32V003 guided fallback when probe is PU_BOARD_PICO (UNSUPPORTED = 0x02 / no VTARG switch)
	out.Reset()
	errBuf.Reset()
	code = runWithEnv([]string{"recover", "--family", "ch32v003"}, cliEnv{
		stdout:         &out,
		stderr:         &errBuf,
		discoverProbes: singleFakeProbe(),
		ctrlTransceiver: func(_ usbprobe.ProbeDevice, _ []byte) ([]byte, error) {
			return []byte{0x05, 0x02}, nil
		},
	})
	if code != 0 || !strings.Contains(strings.ToLower(out.String()), "power-cycle") {
		t.Fatalf("expected guided power-cycle unbrick instructions on Pico dev profile, got code=%d out=%s", code, out.String())
	}

	// 3. STM32F1 connect_assert_srst mass erase
	runner := &fakeCommandRunner{
		bins: map[string]string{"openocd": "/usr/bin/openocd"},
	}
	out.Reset()
	errBuf.Reset()
	code = runWithEnv([]string{"recover", "--family", "stm32f1", "--serial", "E660583883278628"}, cliEnv{
		stdout:         &out,
		stderr:         &errBuf,
		cmdRunner:      runner,
		discoverProbes: singleFakeProbe(),
	})
	if code != 0 {
		t.Fatalf("STM32F1 recover failed: code=%d stderr=%s", code, errBuf.String())
	}
	joined := strings.Join(runner.ran[0].args, " ")
	if !strings.Contains(joined, "connect_assert_srst") || !strings.Contains(joined, "mass_erase") {
		t.Fatalf("missing connect_assert_srst or mass_erase in STM32 recover args: %s", joined)
	}
}

func TestPUExportVSCodeGeneratesLaunchJSONAndOpenOCDCfg(t *testing.T) {
	for _, family := range []string{"stm32f1", "rp2040", "esp32", "ch32v003"} {
		t.Run(family, func(t *testing.T) {
			projDir := t.TempDir()
			var out, errBuf bytes.Buffer
			code := runWithEnv([]string{
				"export-vscode",
				"--family", family,
				"--out-dir", projDir,
				"--serial", "E660583883278628",
			}, cliEnv{
				stdout: &out,
				stderr: &errBuf,
			})
			if code != 0 {
				t.Fatalf("export-vscode %s failed: code=%d stderr=%s", family, code, errBuf.String())
			}

			launchPath := filepath.Join(projDir, ".vscode", "launch.json")
			ocdPath := filepath.Join(projDir, ".vscode", "pico-universal-openocd.cfg")

			launchRaw, err := os.ReadFile(launchPath)
			if err != nil {
				t.Fatalf("missing %s: %v", launchPath, err)
			}
			ocdRaw, err := os.ReadFile(ocdPath)
			if err != nil {
				t.Fatalf("missing %s: %v", ocdPath, err)
			}
			if _, statErr := os.Stat(ocdPath); errors.Is(statErr, os.ErrNotExist) {
				t.Fatalf("expected %s to exist", ocdPath)
			}

			var parsed struct {
				Version        string           `json:"version"`
				Configurations []map[string]any `json:"configurations"`
			}
			if err := json.Unmarshal(launchRaw, &parsed); err != nil {
				t.Fatalf("invalid launch.json for %s: %v\n%s", family, err, string(launchRaw))
			}
			if parsed.Version != "0.2.0" || len(parsed.Configurations) == 0 {
				t.Fatalf("unexpected launch.json content for %s: %+v", family, parsed)
			}

			if family == "esp32" && !strings.Contains(string(ocdRaw), "ESP32_FLASH_VOLTAGE 3.3") {
				t.Fatalf("expected embedded Zbit/ESP32 OpenOCD config in %s:\n%s", ocdPath, string(ocdRaw))
			}
			if family == "ch32v003" && !strings.Contains(string(launchRaw), "set breakpoint auto-hw off") {
				t.Fatalf("expected 'set breakpoint auto-hw off' in CH32 launch.json:\n%s", string(launchRaw))
			}
		})
	}
}

package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/nfsahsn/pico-universal-programmer/host/internal/catalog"
)

const (
	// MarkerBegin marks the start of a Pico Universal managed Arduino config block.
	MarkerBegin = "# >>> PICO-UNIVERSAL-BEGIN"
	// MarkerEnd marks the end of a Pico Universal managed Arduino config block.
	MarkerEnd = "# <<< PICO-UNIVERSAL-END"

	udevRulesFilename = "60-pico-universal.rules"
)

// ErrMalformedMarkerBlock indicates an unbalanced or duplicated Pico Universal marker section.
var ErrMalformedMarkerBlock = errors.New("setup: malformed or duplicate Pico Universal marker block")

// defaultUdevRulesTemplate mirrors linux/60-pico-universal.rules so standalone static
// binaries can render deterministic udev rules even outside a git checkout.
const defaultUdevRulesTemplate = `# Pico Universal USB Programmer & Debugger — Linux udev access & ModemManager rules
#
# Official Raspberry Pi Vendor ID: 0x2E8A.

ACTION=="remove", GOTO="pico_universal_end"

# Production builds inject the approved PU_USB_PID at configure/setup time;
# replace <pu_usb_pid> (4 lowercase hex digits) or let ` + "`pu setup`" + ` render it:
# SUBSYSTEM=="usb", ATTRS{idVendor}=="2e8a", ATTRS{idProduct}=="<pu_usb_pid>", TAG+="uaccess", ENV{ID_MM_DEVICE_IGNORE}="1"
# SUBSYSTEM=="tty", ATTRS{idVendor}=="2e8a", ATTRS{idProduct}=="<pu_usb_pid>", TAG+="uaccess", ENV{ID_MM_DEVICE_IGNORE}="1"

# Pico Universal composite USB & CDC-ACM interfaces (VID 0x2E8A)
SUBSYSTEM=="usb", ATTRS{idVendor}=="2e8a", ATTRS{product}=="Pico Universal*", TAG+="uaccess", ENV{ID_MM_DEVICE_IGNORE}="1"
SUBSYSTEM=="tty", ATTRS{idVendor}=="2e8a", ATTRS{product}=="Pico Universal*", TAG+="uaccess", ENV{ID_MM_DEVICE_IGNORE}="1"

# Development CMSIS-DAP probe (000c) and RP2040 BOOTSEL recovery (0003) identities
SUBSYSTEM=="usb", ATTRS{idVendor}=="2e8a", ATTRS{idProduct}=="000c", TAG+="uaccess", ENV{ID_MM_DEVICE_IGNORE}="1"
SUBSYSTEM=="tty", ATTRS{idVendor}=="2e8a", ATTRS{idProduct}=="000c", TAG+="uaccess", ENV{ID_MM_DEVICE_IGNORE}="1"
SUBSYSTEM=="usb", ATTRS{idVendor}=="2e8a", ATTRS{idProduct}=="0003", TAG+="uaccess", ENV{ID_MM_DEVICE_IGNORE}="1"

LABEL="pico_universal_end"
`

var canonicalFamilies = []string{"stm32", "rp2040", "esp32", "ch32v"}

func runSetup(ctx cliContext, args []string) int {
	fs := flag.NewFlagSet("pu setup", flag.ContinueOnError)
	fs.SetOutput(ctx.stderr)

	offline := fs.Bool("offline", false, "Operate strictly offline without network requests")
	verifyOnly := fs.Bool("verify", false, "Verify catalog hashes, installed marker blocks, and USB readiness")
	uninstall := fs.Bool("uninstall", false, "Remove only Pico Universal managed blocks and leave all other profiles intact")
	arduinoDirFlag := fs.String("arduino-dir", "", "Arduino IDE 2 data directory (default: ~/.arduino15 or %LOCALAPPDATA%\\Arduino15)")
	catalogDirFlag := fs.String("catalog-dir", "", "Directory containing targets.json and dependencies.lock.json (or repo root)")
	udevDirFlag := fs.String("udev-dir", "", "Directory for 60-pico-universal.rules (default on Linux: /etc/udev/rules.d)")
	pidFlag := fs.String("pid", "", "Approved USB PID in hex (overrides PU_USB_PID)")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if *verifyOnly && *uninstall {
		fmt.Fprintln(ctx.stderr, "pu setup: --verify and --uninstall are mutually exclusive")
		return 2
	}
	_ = *offline // Host setup operates from locked local catalog without unsolicited downloads.

	effectivePIDFlag := *pidFlag
	if effectivePIDFlag == "" {
		effectivePIDFlag = ctx.globalPID
	}
	pid, err := ResolveUSBPID(effectivePIDFlag, ctx.getenv)
	if err != nil {
		fmt.Fprintf(ctx.stderr, "pu setup: invalid --pid: %v\n", err)
		return 2
	}

	arduinoDir, err := resolveArduinoDir(*arduinoDirFlag, ctx.getenv)
	if err != nil {
		fmt.Fprintf(ctx.stderr, "pu setup: %v\n", err)
		return 1
	}

	udevDir := strings.TrimSpace(*udevDirFlag)
	if udevDir == "" && runtime.GOOS == "linux" {
		udevDir = "/etc/udev/rules.d"
	}

	tc, lock, err := catalog.Load(*catalogDirFlag)
	if err != nil {
		fmt.Fprintf(ctx.stderr, "pu setup: %v\n", err)
		return 1
	}
	catDir, err := catalog.ResolveCatalogDir(*catalogDirFlag)
	if err != nil {
		fmt.Fprintf(ctx.stderr, "pu setup: %v\n", err)
		return 1
	}

	if *uninstall {
		if err := uninstallSetup(ctx.stdout, tc, arduinoDir, udevDir); err != nil {
			fmt.Fprintf(ctx.stderr, "pu setup --uninstall: %v\n", err)
			return 1
		}
		return 0
	}

	if *verifyOnly {
		if err := verifySetup(ctx.stdout, tc, lock, arduinoDir, udevDir, pid); err != nil {
			fmt.Fprintf(ctx.stderr, "pu setup --verify: %v\n", err)
			return 1
		}
		return 0
	}

	if err := installSetup(ctx.stdout, tc, lock, catDir, arduinoDir, udevDir, pid); err != nil {
		fmt.Fprintf(ctx.stderr, "pu setup: %v\n", err)
		return 1
	}
	return 0
}

func resolveArduinoDir(explicit string, getenv func(string) string) (string, error) {
	if strings.TrimSpace(explicit) != "" {
		return filepath.Abs(explicit)
	}
	if runtime.GOOS == "windows" {
		if localAppData := strings.TrimSpace(getenv("LOCALAPPDATA")); localAppData != "" {
			return filepath.Join(localAppData, "Arduino15"), nil
		}
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return "", errors.New("unable to determine user home directory; pass --arduino-dir")
	}
	if runtime.GOOS == "darwin" {
		return filepath.Join(home, "Library", "Arduino15"), nil
	}
	return filepath.Join(home, ".arduino15"), nil
}

func coreHardwareDir(tc *catalog.TargetsCatalog, arduinoDir, family string) (string, error) {
	core, ok := tc.FindCore(family)
	if !ok {
		return "", fmt.Errorf("missing core %q in catalog", family)
	}
	parts := strings.SplitN(core.Package, ":", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", fmt.Errorf("invalid core package %q for %s", core.Package, family)
	}
	return filepath.Join(arduinoDir, "packages", parts[0], "hardware", parts[1], core.Version), nil
}

func installSetup(stdout io.Writer, tc *catalog.TargetsCatalog, lock *catalog.DependenciesLock, catDir, arduinoDir, udevDir string, pid uint16) error {
	if err := verifyCachedArchivesIfPresent(arduinoDir, lock); err != nil {
		return err
	}

	puExe, err := resolveSafeExecutablePath()
	if err != nil {
		return err
	}

	for _, family := range canonicalFamilies {
		hwDir, err := coreHardwareDir(tc, arduinoDir, family)
		if err != nil {
			return err
		}
		if err := os.MkdirAll(hwDir, 0o755); err != nil {
			return fmt.Errorf("create core dir %s: %w", hwDir, err)
		}

		progPath := filepath.Join(hwDir, "programmers.local.txt")
		oldProg, err := readOptionalNonSymlink(progPath)
		if err != nil {
			return err
		}
		newProg, err := MergeManagedBlock(oldProg, renderProgrammersBody(family))
		if err != nil {
			return fmt.Errorf("%s: %w", progPath, err)
		}
		if err := atomicWriteFile(progPath, []byte(newProg), 0o644); err != nil {
			return err
		}

		platPath := filepath.Join(hwDir, "platform.local.txt")
		oldPlat, err := readOptionalNonSymlink(platPath)
		if err != nil {
			return err
		}
		newPlat, err := MergeManagedBlock(oldPlat, renderPlatformBody(family, puExe, pid))
		if err != nil {
			return fmt.Errorf("%s: %w", platPath, err)
		}
		if err := atomicWriteFile(platPath, []byte(newPlat), 0o644); err != nil {
			return err
		}

		dbgPath := filepath.Join(hwDir, "debug_custom.json")
		oldDbg, err := readOptionalNonSymlink(dbgPath)
		if err != nil {
			return err
		}
		newDbg, err := mergeDebugCustomJSON(oldDbg, family, buildDebugCustomEntry(family, puExe, catDir, pid))
		if err != nil {
			return fmt.Errorf("%s: %w", dbgPath, err)
		}
		if err := atomicWriteFile(dbgPath, newDbg, 0o644); err != nil {
			return err
		}
	}

	if udevDir != "" {
		tmpl := loadUdevTemplate(catDir)
		rendered := RenderUdevRules(tmpl, pid)
		targetPath := filepath.Join(udevDir, udevRulesFilename)
		if err := installUdevRuleOrPrintSudo(stdout, arduinoDir, targetPath, []byte(rendered)); err != nil {
			return err
		}
	} else if runtime.GOOS == "windows" {
		fmt.Fprintln(stdout, "Windows USB readiness: MS OS 2.0 WCID WinUSB descriptors active (zero external driver install required).")
	}

	fmt.Fprintf(stdout, "Pico Universal Arduino IDE 2 profiles installed under %s\n", arduinoDir)
	return nil
}

func uninstallSetup(stdout io.Writer, tc *catalog.TargetsCatalog, arduinoDir, udevDir string) error {
	for _, family := range canonicalFamilies {
		hwDir, err := coreHardwareDir(tc, arduinoDir, family)
		if err != nil {
			return err
		}

		for _, fn := range []string{"programmers.local.txt", "platform.local.txt"} {
			p := filepath.Join(hwDir, fn)
			if _, statErr := os.Lstat(p); errors.Is(statErr, os.ErrNotExist) {
				continue
			}
			oldContent, err := readOptionalNonSymlink(p)
			if err != nil {
				return err
			}
			cleaned, err := RemoveManagedBlock(oldContent)
			if err != nil {
				return fmt.Errorf("%s: %w", p, err)
			}
			if cleaned != oldContent {
				if err := atomicWriteFile(p, []byte(cleaned), 0o644); err != nil {
					return err
				}
			}
		}

		dbgPath := filepath.Join(hwDir, "debug_custom.json")
		if _, statErr := os.Lstat(dbgPath); !errors.Is(statErr, os.ErrNotExist) {
			oldDbg, err := readOptionalNonSymlink(dbgPath)
			if err != nil {
				return err
			}
			cleanedDbg, changed, err := removeDebugCustomJSON(oldDbg, family)
			if err != nil {
				return fmt.Errorf("%s: %w", dbgPath, err)
			}
			if changed {
				if err := atomicWriteFile(dbgPath, cleanedDbg, 0o644); err != nil {
					return err
				}
			}
		}
	}

	stagedRule := filepath.Join(arduinoDir, "udev", udevRulesFilename)
	_ = os.Remove(stagedRule)

	if udevDir != "" {
		targetRule := filepath.Join(udevDir, udevRulesFilename)
		if _, err := os.Lstat(targetRule); err == nil {
			if rmErr := os.Remove(targetRule); rmErr != nil {
				if errors.Is(rmErr, os.ErrPermission) {
					fmt.Fprintf(stdout, "Run as administrator to remove system udev rule:\n  sudo rm -f %q && sudo udevadm control --reload-rules\n", targetRule)
				} else {
					return fmt.Errorf("remove udev rule %s: %w", targetRule, rmErr)
				}
			}
		}
	}

	fmt.Fprintf(stdout, "Pico Universal profiles cleanly uninstalled from %s\n", arduinoDir)
	return nil
}

func verifySetup(stdout io.Writer, tc *catalog.TargetsCatalog, lock *catalog.DependenciesLock, arduinoDir, udevDir string, pid uint16) error {
	if err := verifyCachedArchivesIfPresent(arduinoDir, lock); err != nil {
		return err
	}

	for _, family := range canonicalFamilies {
		hwDir, err := coreHardwareDir(tc, arduinoDir, family)
		if err != nil {
			return err
		}

		progPath := filepath.Join(hwDir, "programmers.local.txt")
		progBody, ok, err := ExtractManagedBlock(progPath)
		if err != nil {
			return err
		}
		if !ok || !strings.Contains(progBody, "pico_universal.name=") {
			return fmt.Errorf("missing Pico Universal managed block in %s", progPath)
		}

		platPath := filepath.Join(hwDir, "platform.local.txt")
		platBody, ok, err := ExtractManagedBlock(platPath)
		if err != nil {
			return err
		}
		if !ok || !strings.Contains(platBody, "tools.pico_universal.program.pattern=") {
			return fmt.Errorf("missing Pico Universal upload recipe in %s", platPath)
		}

		dbgPath := filepath.Join(hwDir, "debug_custom.json")
		dbgRaw, err := os.ReadFile(dbgPath)
		if err != nil {
			return fmt.Errorf("missing %s: %w", dbgPath, err)
		}
		var entries []map[string]any
		if err := json.Unmarshal(dbgRaw, &entries); err != nil {
			return fmt.Errorf("invalid JSON in %s: %w", dbgPath, err)
		}
		wantID := "pico-universal-" + family
		found := false
		for _, e := range entries {
			if e["configId"] == wantID {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("missing %q debug profile in %s", wantID, dbgPath)
		}
	}

	if udevDir != "" {
		rulePath := filepath.Join(udevDir, udevRulesFilename)
		raw, err := os.ReadFile(rulePath)
		if err != nil {
			return fmt.Errorf("udev rules not installed at %s: %w", rulePath, err)
		}
		text := string(raw)
		if !strings.Contains(text, `ATTRS{idVendor}=="2e8a"`) || !strings.Contains(text, `ENV{ID_MM_DEVICE_IGNORE}="1"`) {
			return fmt.Errorf("incomplete udev rules in %s", rulePath)
		}
		if pid != 0 {
			wantAttr := fmt.Sprintf(`ATTRS{idProduct}=="%04x"`, pid)
			if !strings.Contains(text, wantAttr) {
				return fmt.Errorf("udev rules in %s missing configured PID match %s", rulePath, wantAttr)
			}
		}
	}

	fmt.Fprintln(stdout, "Pico Universal setup verification passed.")
	return nil
}

func verifyCachedArchivesIfPresent(arduinoDir string, lock *catalog.DependenciesLock) error {
	for _, sub := range []string{
		filepath.Join(arduinoDir, "staging", "packages"),
		filepath.Join(arduinoDir, "downloads", "packages"),
		filepath.Join(arduinoDir, "staging", "libraries"),
		filepath.Join(arduinoDir, "downloads", "libraries"),
	} {
		entries, err := os.ReadDir(sub)
		if err != nil {
			continue
		}
		byFilename := make(map[string]string)
		for _, art := range lock.Artifacts {
			if prev, exists := byFilename[art.Filename]; exists && prev != art.SHA256 {
				continue
			}
			byFilename[art.Filename] = art.SHA256
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			if expectedSHA, locked := byFilename[e.Name()]; locked {
				if err := catalog.VerifyFileSHA256(filepath.Join(sub, e.Name()), expectedSHA); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func resolveSafeExecutablePath() (string, error) {
	exe, err := os.Executable()
	if err != nil || exe == "" {
		exe = "pu"
	}
	clean := filepath.ToSlash(exe)
	if strings.ContainsAny(clean, "\r\n\"{}") {
		return "", fmt.Errorf("executable path %q contains characters unsafe for Arduino recipes", exe)
	}
	return clean, nil
}

func renderProgrammersBody(family string) string {
	protocol := "cmsis-dap"
	if family == "ch32v" {
		protocol = "swio-gdb"
	}
	return strings.Join([]string{
		"pico_universal.name=Pico Universal",
		"pico_universal.communication=usb",
		"pico_universal.protocol=" + protocol,
		"pico_universal.program.tool=pico_universal",
		"pico_universal.program.tool.default=pico_universal",
	}, "\n")
}

func renderPlatformBody(family, puExeSlash string, pid uint16) string {
	pidArg := ""
	if pid != 0 {
		pidArg = fmt.Sprintf(" --pid 0x%04x", pid)
	}
	args := fmt.Sprintf(`upload%s --core %s --fqbn "{build.fqbn}" --board "{build.board}" --elf "{build.path}/{build.project_name}.elf"`, pidArg, family)
	if family == "esp32" {
		args += ` --segment "{build.bootloader_addr}:{build.path}/{build.project_name}.bootloader.bin" --segment "0x8000:{build.path}/{build.project_name}.partitions.bin" --segment "0xe000:{runtime.platform.path}/tools/partitions/boot_app0.bin" --segment "0x10000:{build.path}/{build.project_name}.bin"`
	}
	return strings.Join([]string{
		"tools.pico_universal.cmd=" + puExeSlash,
		"tools.pico_universal.program.params.verbose=-v",
		"tools.pico_universal.program.params.quiet=",
		fmt.Sprintf(`tools.pico_universal.program.pattern="{tools.pico_universal.cmd}" %s {program.verbose}`, args),
	}, "\n")
}

func buildDebugCustomEntry(family, puExeSlash, catDir string, pid uint16) map[string]any {
	entry := map[string]any{
		"configId":  "pico-universal-" + family,
		"managedBy": "pico-universal",
		"name":      "Pico Universal (" + family + ")",
		"request":   "launch",
		"type":      "cortex-debug",
	}
	switch family {
	case "stm32":
		entry["servertype"] = "openocd"
		entry["interface"] = "swd"
		entry["configFiles"] = []string{"interface/cmsis-dap.cfg", "target/stm32f1x.cfg"}
	case "rp2040":
		entry["servertype"] = "openocd"
		entry["interface"] = "swd"
		entry["configFiles"] = []string{"interface/cmsis-dap.cfg", "target/rp2040.cfg"}
	case "esp32":
		entry["servertype"] = "openocd"
		entry["interface"] = "jtag"
		espCfg := filepath.ToSlash(filepath.Join(catDir, "openocd", "pu-esp32.cfg"))
		entry["configFiles"] = []string{espCfg}
	case "ch32v":
		pidFlag := ""
		if pid != 0 {
			pidFlag = fmt.Sprintf(" --pid 0x%04x", pid)
		}
		entry["servertype"] = "external"
		entry["gdbTarget"] = fmt.Sprintf(`| "%s" gdb-pipe --family ch32v%s`, puExeSlash, pidFlag)
		entry["postLaunchCommands"] = []string{"set breakpoint auto-hw off"}
	}
	return entry
}

func mergeDebugCustomJSON(existing string, family string, managedEntry map[string]any) ([]byte, error) {
	var list []map[string]any
	trimmed := strings.TrimSpace(existing)
	if trimmed != "" {
		if err := json.Unmarshal([]byte(trimmed), &list); err != nil {
			return nil, fmt.Errorf("parse debug_custom.json: %w", err)
		}
	}

	targetID := "pico-universal-" + family
	replaced := false
	out := make([]map[string]any, 0, len(list)+1)
	for _, item := range list {
		if isManagedDebugEntry(item, targetID) {
			if !replaced {
				out = append(out, managedEntry)
				replaced = true
			}
			continue
		}
		out = append(out, item)
	}
	if !replaced {
		out = append(out, managedEntry)
	}

	encoded, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(encoded, '\n'), nil
}

func removeDebugCustomJSON(existing string, family string) ([]byte, bool, error) {
	trimmed := strings.TrimSpace(existing)
	if trimmed == "" {
		return []byte(existing), false, nil
	}
	var list []map[string]any
	if err := json.Unmarshal([]byte(trimmed), &list); err != nil {
		return nil, false, fmt.Errorf("parse debug_custom.json: %w", err)
	}

	targetID := "pico-universal-" + family
	changed := false
	kept := make([]map[string]any, 0, len(list))
	for _, item := range list {
		if isManagedDebugEntry(item, targetID) {
			changed = true
			continue
		}
		kept = append(kept, item)
	}
	if !changed {
		return []byte(existing), false, nil
	}
	encoded, err := json.MarshalIndent(kept, "", "  ")
	if err != nil {
		return nil, false, err
	}
	return append(encoded, '\n'), true, nil
}

func isManagedDebugEntry(item map[string]any, exactConfigID string) bool {
	if id, _ := item["configId"].(string); id == exactConfigID {
		return true
	}
	return false
}

func loadUdevTemplate(catDir string) string {
	candidate := filepath.Join(filepath.Dir(catDir), "linux", udevRulesFilename)
	if raw, err := os.ReadFile(candidate); err == nil && len(raw) > 0 {
		return string(raw)
	}
	return defaultUdevRulesTemplate
}

// RenderUdevRules renders 60-pico-universal.rules, activating the exact ATTRS{idProduct}
// rules when pid is non-zero.
func RenderUdevRules(template string, pid uint16) string {
	if pid == 0 {
		return template
	}
	hexPID := fmt.Sprintf("%04x", pid)
	out := strings.ReplaceAll(template,
		`# SUBSYSTEM=="usb", ATTRS{idVendor}=="2e8a", ATTRS{idProduct}=="<pu_usb_pid>"`,
		fmt.Sprintf(`SUBSYSTEM=="usb", ATTRS{idVendor}=="2e8a", ATTRS{idProduct}=="%s"`, hexPID),
	)
	out = strings.ReplaceAll(out,
		`# SUBSYSTEM=="tty", ATTRS{idVendor}=="2e8a", ATTRS{idProduct}=="<pu_usb_pid>"`,
		fmt.Sprintf(`SUBSYSTEM=="tty", ATTRS{idVendor}=="2e8a", ATTRS{idProduct}=="%s"`, hexPID),
	)
	return out
}

func installUdevRuleOrPrintSudo(stdout io.Writer, arduinoDir, targetPath string, content []byte) error {
	dir := filepath.Dir(targetPath)
	if mkErr := os.MkdirAll(dir, 0o755); mkErr != nil {
		if errors.Is(mkErr, os.ErrPermission) {
			return stageUdevAndPrintSudo(stdout, arduinoDir, targetPath, content)
		}
		return fmt.Errorf("create udev dir %s: %w", dir, mkErr)
	}
	if err := atomicWriteFile(targetPath, content, 0o644); err != nil {
		if errors.Is(err, os.ErrPermission) {
			return stageUdevAndPrintSudo(stdout, arduinoDir, targetPath, content)
		}
		return err
	}
	return nil
}

func stageUdevAndPrintSudo(stdout io.Writer, arduinoDir, targetPath string, content []byte) error {
	stagedDir := filepath.Join(arduinoDir, "udev")
	if err := os.MkdirAll(stagedDir, 0o755); err != nil {
		return fmt.Errorf("create staged udev dir %s: %w", stagedDir, err)
	}
	stagedPath := filepath.Join(stagedDir, udevRulesFilename)
	if err := atomicWriteFile(stagedPath, content, 0o644); err != nil {
		return err
	}
	fmt.Fprintf(stdout,
		"Insufficient privileges to write %s directly. Install udev rules with:\n  sudo install -m 0644 %q %q && sudo udevadm control --reload-rules && sudo udevadm trigger --subsystem-match=usb --subsystem-match=tty\n",
		targetPath, stagedPath, targetPath)
	return nil
}

type lineSpan struct {
	rawStart int
	rawEnd   int
	trimmed  string
}

func scanLines(s string) []lineSpan {
	if s == "" {
		return nil
	}
	var spans []lineSpan
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			line := s[start:i]
			line = strings.TrimSuffix(line, "\r")
			spans = append(spans, lineSpan{rawStart: start, rawEnd: i + 1, trimmed: line})
			start = i + 1
		}
	}
	if start < len(s) {
		line := strings.TrimSuffix(s[start:], "\r")
		spans = append(spans, lineSpan{rawStart: start, rawEnd: len(s), trimmed: line})
	}
	return spans
}

func locateManagedBlock(existing string) (spans []lineSpan, beginIdx, endIdx int, present bool, err error) {
	spans = scanLines(existing)
	var begins, ends []int
	for idx, sp := range spans {
		if sp.trimmed == MarkerBegin {
			begins = append(begins, idx)
		} else if sp.trimmed == MarkerEnd {
			ends = append(ends, idx)
		}
	}
	if len(begins) == 0 && len(ends) == 0 {
		return spans, -1, -1, false, nil
	}
	if len(begins) != 1 || len(ends) != 1 || begins[0] >= ends[0] {
		return nil, -1, -1, false, ErrMalformedMarkerBlock
	}
	return spans, begins[0], ends[0], true, nil
}

// MergeManagedBlock idempotently inserts or updates the exact `# >>> PICO-UNIVERSAL-BEGIN` ..
// `# <<< PICO-UNIVERSAL-END` section while preserving all surrounding content and sibling markers.
func MergeManagedBlock(existing, body string) (string, error) {
	spans, bIdx, eIdx, present, err := locateManagedBlock(existing)
	if err != nil {
		return "", err
	}
	cleanBody := strings.TrimRight(body, "\r\n")
	block := MarkerBegin + "\n" + cleanBody + "\n" + MarkerEnd + "\n"

	if !present {
		if existing == "" {
			return block, nil
		}
		if strings.HasSuffix(existing, "\n") {
			return existing + block, nil
		}
		return existing + "\n" + block, nil
	}

	prefix := existing[:spans[bIdx].rawStart]
	suffix := existing[spans[eIdx].rawEnd:]
	return prefix + block + suffix, nil
}

// RemoveManagedBlock removes ONLY the exact `# >>> PICO-UNIVERSAL-BEGIN` .. `# <<< PICO-UNIVERSAL-END`
// block (whether or not the file ends with a trailing newline) and leaves all other lines untouched.
func RemoveManagedBlock(existing string) (string, error) {
	spans, bIdx, eIdx, present, err := locateManagedBlock(existing)
	if err != nil {
		return "", err
	}
	if !present {
		return existing, nil
	}
	return existing[:spans[bIdx].rawStart] + existing[spans[eIdx].rawEnd:], nil
}

// ExtractManagedBlock reads path and returns the inner lines of the Pico Universal marker block.
func ExtractManagedBlock(path string) (string, bool, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", false, err
	}
	s := string(raw)
	spans, bIdx, eIdx, present, err := locateManagedBlock(s)
	if err != nil {
		return "", false, fmt.Errorf("%s: %w", path, err)
	}
	if !present {
		return "", false, nil
	}
	innerStart := spans[bIdx].rawEnd
	innerEnd := spans[eIdx].rawStart
	if innerStart > innerEnd {
		return "", true, nil
	}
	return strings.TrimRight(s[innerStart:innerEnd], "\r\n"), true, nil
}

func readOptionalNonSymlink(path string) (string, error) {
	info, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", nil
		}
		return "", err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("refusing to modify symlink %s", path)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

func atomicWriteFile(path string, content []byte, perm os.FileMode) error {
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing to overwrite symlink %s", path)
		}
		perm = info.Mode().Perm()
	}

	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".pu-setup-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpName)
		}
	}()

	if _, err := tmp.Write(content); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpName, perm); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	cleanup = false
	return nil
}

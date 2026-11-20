package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func testRepoRoot(t *testing.T) string {
	t.Helper()
	abs, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatalf("resolve repo root: %v", err)
	}
	return abs
}

func TestResolveUSBPIDPrecedenceAndValidation(t *testing.T) {
	env := map[string]string{}
	getenv := func(k string) string { return env[k] }

	// Default when neither flag nor env is provided -> 0x0000
	pid, err := ResolveUSBPID("", getenv)
	if err != nil || pid != 0x0000 {
		t.Fatalf("expected default PID 0x0000, got 0x%04x err=%v", pid, err)
	}

	// Environment variable PU_USB_PID
	env["PU_USB_PID"] = "0x1050"
	pid, err = ResolveUSBPID("", getenv)
	if err != nil || pid != 0x1050 {
		t.Fatalf("expected env PID 0x1050, got 0x%04x err=%v", pid, err)
	}

	// Explicit -pid flag overrides PU_USB_PID env
	pid, err = ResolveUSBPID("1a2b", getenv)
	if err != nil || pid != 0x1A2B {
		t.Fatalf("expected flag PID 0x1a2b, got 0x%04x err=%v", pid, err)
	}

	// Invalid hex PID must fail
	if _, err := ResolveUSBPID("0xZZZZ", getenv); err == nil {
		t.Fatal("expected invalid hex PID to return error")
	}
}

func TestManagedBlockEdgeCasesTrailingNewlinesAndSiblingPrefixes(t *testing.T) {
	// Existing content WITHOUT trailing newline + sibling longer-prefix markers that must never match!
	existingNoNL := strings.Join([]string{
		"user_prog.name=User Custom Programmer",
		"# >>> PICO-UNIVERSAL-BEGIN-THIRDPARTY",
		"thirdparty.name=Do Not Touch",
		"# <<< PICO-UNIVERSAL-END-THIRDPARTY",
		"trailing.line=preserve_no_nl",
	}, "\n")

	merged, err := MergeManagedBlock(existingNoNL, "pico_universal.name=Pico Universal")
	if err != nil {
		t.Fatalf("MergeManagedBlock failed: %v", err)
	}
	if !strings.Contains(merged, "# >>> PICO-UNIVERSAL-BEGIN-THIRDPARTY\nthirdparty.name=Do Not Touch\n# <<< PICO-UNIVERSAL-END-THIRDPARTY") {
		t.Fatalf("sibling longer-prefix block corrupted:\n%s", merged)
	}
	if !strings.Contains(merged, "trailing.line=preserve_no_nl\n# >>> PICO-UNIVERSAL-BEGIN\npico_universal.name=Pico Universal\n# <<< PICO-UNIVERSAL-END\n") {
		t.Fatalf("unexpected merged output:\n%s", merged)
	}

	// Idempotent re-merge
	merged2, err := MergeManagedBlock(merged, "pico_universal.name=Pico Universal")
	if err != nil {
		t.Fatalf("second MergeManagedBlock failed: %v", err)
	}
	if merged2 != merged {
		t.Fatalf("MergeManagedBlock is not idempotent:\ngot:\n%s\nwant:\n%s", merged2, merged)
	}

	// Strip trailing newline off the managed block itself and verify RemoveManagedBlock still works cleanly!
	mergedWithoutTrailingNL := strings.TrimSuffix(merged, "\n")
	removed, err := RemoveManagedBlock(mergedWithoutTrailingNL)
	if err != nil {
		t.Fatalf("RemoveManagedBlock without trailing newline failed: %v", err)
	}
	if strings.Contains(removed, "# >>> PICO-UNIVERSAL-BEGIN\n") || strings.Contains(removed, "pico_universal.name=") {
		t.Fatalf("Pico Universal block was not removed:\n%s", removed)
	}
	if !strings.Contains(removed, "# >>> PICO-UNIVERSAL-BEGIN-THIRDPARTY") || !strings.Contains(removed, "trailing.line=preserve_no_nl") {
		t.Fatalf("third-party content lost during RemoveManagedBlock:\n%s", removed)
	}

	// Middle-of-file removal where final line has no trailing newline
	midFile := "before=1\n# >>> PICO-UNIVERSAL-BEGIN\npico=1\n# <<< PICO-UNIVERSAL-END\nafter_no_nl=2"
	midRemoved, err := RemoveManagedBlock(midFile)
	if err != nil {
		t.Fatalf("middle RemoveManagedBlock failed: %v", err)
	}
	if midRemoved != "before=1\nafter_no_nl=2" {
		t.Fatalf("unexpected middle removal result: %q", midRemoved)
	}

	// Unbalanced marker block must be rejected without corrupting user data
	if _, err := MergeManagedBlock("# >>> PICO-UNIVERSAL-BEGIN\norphan=1\n", "x=1"); err == nil {
		t.Fatal("expected unbalanced BEGIN marker to return error")
	}
	if _, err := RemoveManagedBlock("# <<< PICO-UNIVERSAL-END\n"); err == nil {
		t.Fatal("expected orphan END marker to return error")
	}
}

func TestSetupVerifyRejectsCorruptedStagingArchiveAndTamperedCatalog(t *testing.T) {
	root := testRepoRoot(t)
	catCopy := t.TempDir()
	for _, fn := range []string{"targets.json", "dependencies.lock.json"} {
		raw, err := os.ReadFile(filepath.Join(root, "catalog", fn))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(catCopy, fn), raw, 0o644); err != nil {
			t.Fatal(err)
		}
	}

	arduinoDir := filepath.Join(t.TempDir(), "Arduino15")
	udevDir := filepath.Join(t.TempDir(), "udev")

	var out, errBuf bytes.Buffer
	if code := run([]string{"setup", "--offline", "--arduino-dir", arduinoDir, "--catalog-dir", catCopy, "--udev-dir", udevDir}, &out, &errBuf, nil); code != 0 {
		t.Fatalf("initial setup failed: %s", errBuf.String())
	}

	// Place a corrupted cached archive matching a locked filename in staging/packages.
	stagingDir := filepath.Join(arduinoDir, "staging", "packages")
	if err := os.MkdirAll(stagingDir, 0o755); err != nil {
		t.Fatal(err)
	}
	badArchive := filepath.Join(stagingDir, "CMSIS-6.2.0.tar.bz2")
	if err := os.WriteFile(badArchive, []byte("corrupted-bytes"), 0o644); err != nil {
		t.Fatal(err)
	}
	errBuf.Reset()
	if code := run([]string{"setup", "--verify", "--arduino-dir", arduinoDir, "--catalog-dir", catCopy, "--udev-dir", udevDir}, &out, &errBuf, nil); code == 0 {
		t.Fatal("expected --verify to fail on corrupted cached archive SHA-256")
	}
	_ = os.Remove(badArchive)

	// Tamper with targets.json and confirm --verify rejects catalog_sha256 mismatch.
	if err := os.WriteFile(filepath.Join(catCopy, "targets.json"), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	errBuf.Reset()
	if code := run([]string{"setup", "--verify", "--arduino-dir", arduinoDir, "--catalog-dir", catCopy, "--udev-dir", udevDir}, &out, &errBuf, nil); code == 0 {
		t.Fatal("expected --verify to fail on tampered targets.json")
	}
}

func TestSetupInstallVerifyIdempotencyAndUninstall(t *testing.T) {
	root := testRepoRoot(t)
	catDir := filepath.Join(root, "catalog")
	arduinoDir := filepath.Join(t.TempDir(), "Arduino15")
	udevDir := filepath.Join(t.TempDir(), "udev-rules")

	// Pre-populate STM32 core files with third-party content (no trailing newline on programmers.local.txt!)
	// and a third-party entry in debug_custom.json.
	stmDir := filepath.Join(arduinoDir, "packages", "STMicroelectronics", "hardware", "stm32", "2.12.0")
	if err := os.MkdirAll(stmDir, 0o755); err != nil {
		t.Fatal(err)
	}
	thirdPartyProg := "# >>> PICO-UNIVERSAL-BEGIN-CUSTOM\ncustom_stlink.name=Custom STLink\n# <<< PICO-UNIVERSAL-END-CUSTOM"
	if err := os.WriteFile(filepath.Join(stmDir, "programmers.local.txt"), []byte(thirdPartyProg), 0o644); err != nil {
		t.Fatal(err)
	}
	thirdPartyDebug := `[{"configId":"custom-jlink","name":"Custom J-Link","servertype":"jlink"}]`
	if err := os.WriteFile(filepath.Join(stmDir, "debug_custom.json"), []byte(thirdPartyDebug), 0o644); err != nil {
		t.Fatal(err)
	}

	runCLI := func(args ...string) (int, string, string) {
		var out, errBuf bytes.Buffer
		code := run(args, &out, &errBuf, func(string) string { return "" })
		return code, out.String(), errBuf.String()
	}

	// Verify BEFORE install must fail cleanly.
	if code, _, _ := runCLI("setup", "--verify", "--arduino-dir", arduinoDir, "--catalog-dir", catDir, "--udev-dir", udevDir, "--pid", "0x1050"); code == 0 {
		t.Fatal("expected --verify before install to fail")
	}

	// 1. Run `pu setup --offline`
	code, stdout, stderr := runCLI("setup", "--offline", "--arduino-dir", arduinoDir, "--catalog-dir", catDir, "--udev-dir", udevDir, "--pid", "0x1050")
	if code != 0 {
		t.Fatalf("pu setup failed (code=%d): stdout=%s stderr=%s", code, stdout, stderr)
	}

	// Check all 4 core families exist and contain valid files
	expectedFamilies := []struct {
		family string
		relDir string
	}{
		{"stm32", filepath.Join("packages", "STMicroelectronics", "hardware", "stm32", "2.12.0")},
		{"rp2040", filepath.Join("packages", "rp2040", "hardware", "rp2040", "6.1.1")},
		{"esp32", filepath.Join("packages", "esp32", "hardware", "esp32", "3.3.11")},
		{"ch32v", filepath.Join("packages", "WCH", "hardware", "ch32v", "1.0.4")},
	}

	snapshotFirst := make(map[string]string)
	for _, fam := range expectedFamilies {
		coreDir := filepath.Join(arduinoDir, fam.relDir)
		for _, fn := range []string{"programmers.local.txt", "platform.local.txt", "debug_custom.json"} {
			full := filepath.Join(coreDir, fn)
			raw, err := os.ReadFile(full)
			if err != nil {
				t.Fatalf("missing %s for %s: %v", fn, fam.family, err)
			}
			snapshotFirst[full] = string(raw)
		}

		// Validate debug_custom.json is valid JSON containing pico-universal-<family>
		var dbgEntries []map[string]any
		if err := json.Unmarshal([]byte(snapshotFirst[filepath.Join(coreDir, "debug_custom.json")]), &dbgEntries); err != nil {
			t.Fatalf("invalid JSON in %s debug_custom.json: %v", fam.family, err)
		}
		foundPU := false
		for _, e := range dbgEntries {
			if e["configId"] == "pico-universal-"+fam.family {
				foundPU = true
			}
		}
		if !foundPU {
			t.Fatalf("missing pico-universal-%s in debug_custom.json: %+v", fam.family, dbgEntries)
		}
	}

	// Confirm third-party STM32 entries were preserved alongside Pico Universal!
	stmProgAfter := snapshotFirst[filepath.Join(stmDir, "programmers.local.txt")]
	if !strings.Contains(stmProgAfter, "custom_stlink.name=Custom STLink") || !strings.Contains(stmProgAfter, "# >>> PICO-UNIVERSAL-BEGIN-CUSTOM") {
		t.Fatalf("STM32 third-party programmers.local.txt lost:\n%s", stmProgAfter)
	}
	if !strings.Contains(snapshotFirst[filepath.Join(stmDir, "debug_custom.json")], `"custom-jlink"`) {
		t.Fatalf("STM32 third-party debug_custom.json entry lost:\n%s", snapshotFirst[filepath.Join(stmDir, "debug_custom.json")])
	}

	// Confirm udev rule rendered with PID 1050
	udevBytes, err := os.ReadFile(filepath.Join(udevDir, "60-pico-universal.rules"))
	if err != nil {
		t.Fatalf("read rendered udev rules: %v", err)
	}
	udevStr := string(udevBytes)
	if !strings.Contains(udevStr, `SUBSYSTEM=="usb", ATTRS{idVendor}=="2e8a", ATTRS{idProduct}=="1050", TAG+="uaccess", ENV{ID_MM_DEVICE_IGNORE}="1"`) {
		t.Fatalf("rendered udev rules missing uncommented PID 1050 rule:\n%s", udevStr)
	}

	// 2. Re-run `pu setup` to prove byte-for-byte idempotency
	code, _, stderr = runCLI("setup", "--offline", "--arduino-dir", arduinoDir, "--catalog-dir", catDir, "--udev-dir", udevDir, "--pid", "0x1050")
	if code != 0 {
		t.Fatalf("second idempotent pu setup failed: %s", stderr)
	}
	for full, want := range snapshotFirst {
		got, err := os.ReadFile(full)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != want {
			t.Fatalf("non-idempotent output in %s:\ngot:\n%s\nwant:\n%s", full, string(got), want)
		}
	}

	// 3. Run `pu setup --verify` -> must PASS
	code, _, stderr = runCLI("setup", "--verify", "--arduino-dir", arduinoDir, "--catalog-dir", catDir, "--udev-dir", udevDir, "--pid", "0x1050")
	if code != 0 {
		t.Fatalf("pu setup --verify failed: %s", stderr)
	}

	// 4. Run `pu setup --uninstall` -> removes ONLY Pico Universal entries, preserving third-party!
	code, _, stderr = runCLI("setup", "--uninstall", "--arduino-dir", arduinoDir, "--catalog-dir", catDir, "--udev-dir", udevDir)
	if code != 0 {
		t.Fatalf("pu setup --uninstall failed: %s", stderr)
	}

	stmProgFinal, err := os.ReadFile(filepath.Join(stmDir, "programmers.local.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(stmProgFinal), "pico_universal.name=") {
		t.Fatalf("Pico Universal block remained after uninstall:\n%s", string(stmProgFinal))
	}
	if !strings.Contains(string(stmProgFinal), "custom_stlink.name=Custom STLink") || !strings.Contains(string(stmProgFinal), "# >>> PICO-UNIVERSAL-BEGIN-CUSTOM") {
		t.Fatalf("third-party block damaged by uninstall:\n%s", string(stmProgFinal))
	}

	stmDbgFinal, err := os.ReadFile(filepath.Join(stmDir, "debug_custom.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(stmDbgFinal), "pico-universal-stm32") || !strings.Contains(string(stmDbgFinal), `"custom-jlink"`) {
		t.Fatalf("unexpected debug_custom.json after uninstall:\n%s", string(stmDbgFinal))
	}

	// Verify AFTER uninstall must fail cleanly.
	if code, _, _ := runCLI("setup", "--verify", "--arduino-dir", arduinoDir, "--catalog-dir", catDir, "--udev-dir", udevDir, "--pid", "0x1050"); code == 0 {
		t.Fatal("expected --verify after uninstall to fail")
	}
}

func TestSetupUnprivilegedUdevPrintsSudoCommand(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("permission test applies to unprivileged Unix user")
	}
	root := testRepoRoot(t)
	catDir := filepath.Join(root, "catalog")
	arduinoDir := filepath.Join(t.TempDir(), "Arduino15")
	roUdevDir := filepath.Join(t.TempDir(), "readonly-udev")
	if err := os.MkdirAll(roUdevDir, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(roUdevDir, 0o755) })

	var out, errBuf bytes.Buffer
	code := run([]string{
		"setup", "--offline",
		"--arduino-dir", arduinoDir,
		"--catalog-dir", catDir,
		"--udev-dir", roUdevDir,
		"--pid", "0x1050",
	}, &out, &errBuf, func(string) string { return "" })

	if code != 0 {
		t.Fatalf("expected unprivileged setup to succeed with sudo instructions, got code=%d stderr=%s", code, errBuf.String())
	}
	if !strings.Contains(out.String(), "sudo install -m 0644") {
		t.Fatalf("expected sudo install command in stdout, got:\n%s", out.String())
	}
}

func TestEmbeddedUdevTemplateMatchesRepoRuleFile(t *testing.T) {
	root := testRepoRoot(t)
	committed, err := os.ReadFile(filepath.Join(root, "linux", "60-pico-universal.rules"))
	if err != nil {
		t.Fatalf("read linux/60-pico-universal.rules: %v", err)
	}
	if string(committed) != defaultUdevRulesTemplate {
		t.Fatal("defaultUdevRulesTemplate in setup.go drifted from linux/60-pico-universal.rules")
	}
}

func TestCLISubcommandRouterVersionListAndDispatchHooks(t *testing.T) {
	var out, errBuf bytes.Buffer
	if code := run([]string{"version"}, &out, &errBuf, func(string) string { return "" }); code != 0 || !strings.Contains(out.String(), "pu ") {
		t.Fatalf("version failed: code=%d out=%q err=%q", code, out.String(), errBuf.String())
	}

	out.Reset()
	errBuf.Reset()
	if code := run([]string{"-pid", "0x1050", "list", "--json"}, &out, &errBuf, func(string) string { return "" }); code != 0 {
		t.Fatalf("list --json failed: code=%d err=%q", code, errBuf.String())
	}

	// Verify Task 8 / 11 / 12 dispatch hooks exist and are routed cleanly (not "unknown command").
	for _, sub := range []string{"check", "upload", "gdb-pipe", "recover", "export-vscode", "factory-qc", "bench"} {
		out.Reset()
		errBuf.Reset()
		code := run([]string{sub}, &out, &errBuf, func(string) string { return "" })
		if code == 0 {
			t.Fatalf("expected stub subcommand %q to return non-zero until implemented", sub)
		}
		if strings.Contains(strings.ToLower(errBuf.String()), "unknown subcommand") {
			t.Fatalf("subcommand %q was not registered in router: %s", sub, errBuf.String())
		}
	}
}

import json
import re
import shutil
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def _eval_c_int(token: str, defines: dict[str, int]) -> int:
    expr = token.strip()
    if not expr:
        return 1

    def repl_ident(match: re.Match[str]) -> str:
        ident = match.group(0)
        if ident.startswith(("0x", "0X")) or ident[0].isdigit():
            return re.sub(r"[uUlL]+$", "", ident)
        return str(defines.get(ident, 0))

    expr = re.sub(r"\b(?:0[xX][0-9a-fA-F]+|\d+)[uUlL]*\b|\b[A-Za-z_][A-Za-z0-9_]*\b", repl_ident, expr)
    if not re.fullmatch(r"[0-9xXa-fA-F+\-*/%<>!=&|^~()\s]+", expr):
        raise ValueError(f"Unsupported macro expression: {token!r}")
    return int(eval(expr, {"__builtins__": {}}, {}))


def _eval_c_cond(expr: str, defines: dict[str, int]) -> bool:
    s = re.sub(
        r"\bdefined\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)|\bdefined\s+([A-Za-z_][A-Za-z0-9_]*)\b",
        lambda m: "1" if (m.group(1) or m.group(2)) in defines else "0",
        expr,
    )

    def repl_token(match: re.Match[str]) -> str:
        tok = match.group(0)
        if tok.startswith(("0x", "0X")) or tok[0].isdigit():
            return re.sub(r"[uUlL]+$", "", tok)
        return str(defines.get(tok, 0))

    s = re.sub(r"\b(?:0[xX][0-9a-fA-F]+|\d+)[uUlL]*\b|\b[A-Za-z_][A-Za-z0-9_]*\b", repl_token, s)
    s = s.replace("&&", " and ").replace("||", " or ")
    s = re.sub(r"!(?!=)", " not ", s)
    return bool(eval(s, {"__builtins__": {}}, {}))


def evaluate_c_header_defines(header_path: Path, initial_defines: dict[str, int] | None = None) -> dict[str, int]:
    text = header_path.read_text(encoding="utf-8")
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)
    text = re.sub(r"//[^\n]*", "", text)

    defines: dict[str, int] = dict(initial_defines or {})
    # Each frame is (parent_active, current_branch_active, any_branch_taken)
    stack: list[tuple[bool, bool, bool]] = []

    def is_active() -> bool:
        return all(frame[1] for frame in stack)

    logical_lines: list[str] = []
    buf = ""
    for raw_line in text.splitlines():
        if raw_line.endswith("\\"):
            buf += raw_line[:-1] + " "
        else:
            logical_lines.append(buf + raw_line)
            buf = ""
    if buf:
        logical_lines.append(buf)

    for line in logical_lines:
        stripped = line.strip()
        if not stripped.startswith("#"):
            continue
        directive = stripped[1:].strip()
        parts = directive.split(None, 1)
        if not parts:
            continue
        kw = parts[0]
        rest = parts[1].strip() if len(parts) > 1 else ""

        if kw == "ifdef":
            parent = is_active()
            cond = parent and (rest in defines)
            stack.append((parent, cond, cond))
        elif kw == "ifndef":
            parent = is_active()
            cond = parent and (rest not in defines)
            stack.append((parent, cond, cond))
        elif kw == "if":
            parent = is_active()
            cond = parent and _eval_c_cond(rest, defines)
            stack.append((parent, cond, cond))
        elif kw == "elif":
            parent, _, taken = stack.pop()
            cond = parent and (not taken) and _eval_c_cond(rest, defines)
            stack.append((parent, cond, taken or cond))
        elif kw == "else":
            parent, _, taken = stack.pop()
            cond = parent and (not taken)
            stack.append((parent, cond, True))
        elif kw == "endif":
            stack.pop()
        elif is_active():
            if kw == "error":
                raise RuntimeError(f"Preprocessor #error: {rest}")
            if kw == "define":
                m = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)(?:\s+(.*))?$", rest)
                if m and "(" not in rest.split()[0]:
                    name = m.group(1)
                    val_str = (m.group(2) or "").strip()
                    defines[name] = _eval_c_int(val_str, defines)
            elif kw == "undef":
                defines.pop(rest, None)

    if stack:
        raise AssertionError("Unterminated preprocessor conditional block")
    return defines


class FoundationBaselineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.build_root = ROOT / "build"
        self.build_existed = self.build_root.exists()
        self.scratch_dir = self.build_root / "test_flash_layout_scratch"
        if self.scratch_dir.exists():
            shutil.rmtree(self.scratch_dir)
        self.scratch_dir.mkdir(parents=True, exist_ok=True)

    def tearDown(self) -> None:
        if self.scratch_dir.exists():
            shutil.rmtree(self.scratch_dir)
        if not self.build_existed and self.build_root.exists() and not any(self.build_root.iterdir()):
            self.build_root.rmdir()

    def test_flash_layout_geometry_and_partitions(self) -> None:
        layout_path = ROOT / "config" / "flash_layout.json"
        self.assertTrue(layout_path.is_file(), "config/flash_layout.json must exist")

        layout = json.loads(layout_path.read_text(encoding="utf-8"))
        self.assertEqual(layout["flash_base"], 0x10000000)
        self.assertEqual(layout["flash_size"], 2097152)
        self.assertEqual(layout["page_size"], 256)
        self.assertEqual(layout["sector_size"], 4096)

        expected_partitions = [
            ("bootloader", "SLOT_BOOTLOADER", 0x000000, 61440, True),
            ("journal_a", "SLOT_JOURNAL_A", 0x00F000, 4096, False),
            ("app_slot_a", "SLOT_APP_A", 0x010000, 983040, True),
            ("app_slot_b", "SLOT_APP_B", 0x100000, 983040, True),
            ("journal_b", "SLOT_JOURNAL_B", 0x1F0000, 4096, False),
            ("factory_meta", "SLOT_FACTORY_META", 0x1FF000, 4096, False),
        ]

        parts = layout["partitions"]
        self.assertEqual(len(parts), 6)
        self.assertEqual([p["name"] for p in parts], [e[0] for e in expected_partitions])

        sector = layout["sector_size"]
        cursor = 0
        for part, (exp_name, exp_macro, exp_offset, exp_size, exp_exec) in zip(parts, expected_partitions):
            self.assertEqual(part["name"], exp_name)
            self.assertEqual(part["macro"], exp_macro)
            self.assertEqual(part["offset"], exp_offset)
            self.assertEqual(part["size"], exp_size)
            self.assertIs(part["executable"], exp_exec)
            self.assertEqual(part["offset"] % sector, 0, f"{part['name']} offset not 4 KiB aligned")
            self.assertEqual(part["size"] % sector, 0, f"{part['name']} size not 4 KiB aligned")
            self.assertGreaterEqual(part["offset"], cursor, f"{part['name']} overlaps previous partition")
            cursor = part["offset"] + part["size"]

        self.assertLessEqual(cursor, layout["flash_size"])

    def test_gen_flash_layout_matches_committed_header_and_macros(self) -> None:
        script_path = ROOT / "tools" / "gen_flash_layout.py"
        layout_path = ROOT / "config" / "flash_layout.json"
        committed_header = ROOT / "config" / "flash_layout.h"

        self.assertTrue(script_path.is_file(), "tools/gen_flash_layout.py must exist")
        self.assertTrue(committed_header.is_file(), "config/flash_layout.h must exist")

        generated_out = self.scratch_dir / "flash_layout.h"
        subprocess.run(
            [
                sys.executable,
                str(script_path),
                "--in",
                str(layout_path),
                "--out",
                str(generated_out),
            ],
            check=True,
        )
        self.assertEqual(
            generated_out.read_text(encoding="utf-8"),
            committed_header.read_text(encoding="utf-8"),
        )

        subprocess.run(
            [sys.executable, str(script_path), "--check"],
            check=True,
        )

        defines = evaluate_c_header_defines(committed_header)
        self.assertEqual(defines["FLASH_BASE_ADDR"], 0x10000000)
        self.assertEqual(defines["FLASH_TOTAL_SIZE"], 2097152)
        self.assertEqual(defines["FLASH_PAGE_SIZE"], 256)
        self.assertEqual(defines["FLASH_SECTOR_SIZE"], 4096)

        expected_macros = {
            "SLOT_BOOTLOADER": (0x000000, 61440),
            "SLOT_JOURNAL_A": (0x00F000, 4096),
            "SLOT_APP_A": (0x010000, 983040),
            "SLOT_APP_B": (0x100000, 983040),
            "SLOT_JOURNAL_B": (0x1F0000, 4096),
            "SLOT_FACTORY_META": (0x1FF000, 4096),
        }
        for macro, (offset, size) in expected_macros.items():
            self.assertEqual(defines[f"{macro}_OFFSET"], offset)
            self.assertEqual(defines[f"{macro}_ADDR"], 0x10000000 + offset)
            self.assertEqual(defines[f"{macro}_SIZE"], size)

    def test_gen_flash_layout_rejects_invalid_layouts(self) -> None:
        script_path = ROOT / "tools" / "gen_flash_layout.py"
        layout_path = ROOT / "config" / "flash_layout.json"
        self.assertTrue(script_path.is_file(), "tools/gen_flash_layout.py must exist")
        self.assertTrue(layout_path.is_file(), "config/flash_layout.json must exist")

        base_layout = json.loads(layout_path.read_text(encoding="utf-8"))

        overlapping = json.loads(json.dumps(base_layout))
        overlapping["partitions"][2]["offset"] = overlapping["partitions"][1]["offset"]
        bad_overlap_json = self.scratch_dir / "overlap.json"
        bad_overlap_json.write_text(json.dumps(overlapping), encoding="utf-8")
        res_overlap = subprocess.run(
            [
                sys.executable,
                str(script_path),
                "--in",
                str(bad_overlap_json),
                "--out",
                str(self.scratch_dir / "bad1.h"),
            ],
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(res_overlap.returncode, 0)

        unaligned = json.loads(json.dumps(base_layout))
        unaligned["partitions"][1]["offset"] = 61440 + 256
        bad_align_json = self.scratch_dir / "unaligned.json"
        bad_align_json.write_text(json.dumps(unaligned), encoding="utf-8")
        res_align = subprocess.run(
            [
                sys.executable,
                str(script_path),
                "--in",
                str(bad_align_json),
                "--out",
                str(self.scratch_dir / "bad2.h"),
            ],
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(res_align.returncode, 0)

    def test_board_pinout_profiles_and_usb_identity(self) -> None:
        pinout_path = ROOT / "config" / "board_pinout.h"
        self.assertTrue(pinout_path.is_file(), "config/board_pinout.h must exist")

        # 1. Default profile selects PU_BOARD_PICO and default placeholder PU_USB_PID
        pico_defs = evaluate_c_header_defines(pinout_path)
        self.assertEqual(pico_defs.get("PU_BOARD_PICO"), 1)
        self.assertNotIn("PU_BOARD_PRO_PCB", pico_defs)
        self.assertEqual(pico_defs.get("PU_USB_VID"), 0x2E8A)
        self.assertEqual(pico_defs.get("PU_USB_PID"), 0x0000)

        expected_pico = {
            "PU_HAS_LEVEL_SHIFTER": 0,
            "PU_HAS_VTARG_SWITCH": 0,
            "PU_HAS_ADC_TELEMETRY": 0,
            "PU_PIN_UART_TX": 0,
            "PU_PIN_UART_RX": 1,
            "PU_PIN_SWCLK_TCK": 2,
            "PU_PIN_SWDIO_TMS": 3,
            "PU_PIN_JTAG_TDI": 4,
            "PU_PIN_JTAG_TDO": 5,
            "PU_PIN_TARGET_NRST": 6,
            "PU_PIN_RECOVERY_BTN": 15,
            "PU_PIN_LED_STATUS": 25,
            "PU_PIN_SWIO": 28,
        }
        for key, val in expected_pico.items():
            self.assertEqual(pico_defs.get(key), val, f"PU_BOARD_PICO mismatch for {key}")

        pico_pins = [v for k, v in pico_defs.items() if k.startswith("PU_PIN_")]
        self.assertEqual(len(pico_pins), len(set(pico_pins)), "Duplicate GPIO assignment in PU_BOARD_PICO")

        # 2. PU_BOARD_PRO_PCB profile with injected approved PU_USB_PID
        pro_defs = evaluate_c_header_defines(
            pinout_path,
            {"PU_BOARD_PRO_PCB": 1, "PU_USB_PID": 0x1050},
        )
        self.assertEqual(pro_defs.get("PU_BOARD_PRO_PCB"), 1)
        self.assertNotIn("PU_BOARD_PICO", pro_defs)
        self.assertEqual(pro_defs.get("PU_USB_VID"), 0x2E8A)
        self.assertEqual(pro_defs.get("PU_USB_PID"), 0x1050)

        expected_pro = {
            "PU_HAS_LEVEL_SHIFTER": 1,
            "PU_HAS_VTARG_SWITCH": 1,
            "PU_HAS_ADC_TELEMETRY": 1,
            "PU_PIN_UART_TX": 0,
            "PU_PIN_UART_RX": 1,
            "PU_PIN_SWCLK_TCK": 2,
            "PU_PIN_SWDIO_TMS": 3,
            "PU_PIN_JTAG_TDI": 4,
            "PU_PIN_JTAG_TDO": 5,
            "PU_PIN_SWDIO_DIR": 6,
            "PU_PIN_TARGET_NRST": 7,
            "PU_PIN_SWIO": 8,
            "PU_PIN_SWIO_PU_EN": 9,
            "PU_PIN_VTARG_EN": 10,
            "PU_PIN_VTARG_FAULT_N": 11,
            "PU_PIN_LED_R": 12,
            "PU_PIN_LED_G": 13,
            "PU_PIN_LED_B": 14,
            "PU_PIN_RECOVERY_BTN": 15,
            "PU_PIN_ADC_VTREF": 26,
            "PU_PIN_ADC_ITARG": 27,
        }
        for key, val in expected_pro.items():
            self.assertEqual(pro_defs.get(key), val, f"PU_BOARD_PRO_PCB mismatch for {key}")

        pro_pins = [v for k, v in pro_defs.items() if k.startswith("PU_PIN_")]
        self.assertEqual(len(pro_pins), len(set(pro_pins)), "Duplicate GPIO assignment in PU_BOARD_PRO_PCB")

        # 3. Defining both profiles simultaneously must fail compilation
        with self.assertRaises(RuntimeError):
            evaluate_c_header_defines(pinout_path, {"PU_BOARD_PICO": 1, "PU_BOARD_PRO_PCB": 1})

    def test_catalog_targets_json_contains_four_initial_families(self) -> None:
        catalog_path = ROOT / "catalog" / "targets.json"
        self.assertTrue(catalog_path.is_file(), "catalog/targets.json must exist")

        catalog = json.loads(catalog_path.read_text(encoding="utf-8"))
        required_families = {"stm32", "rp2040", "esp32", "ch32v"}
        self.assertTrue(required_families.issubset(set(catalog.get("cores", {}).keys())))

        initial_board_cores = {
            board["core"]
            for board in catalog.get("boards", [])
            if board.get("phase") == "initial"
        }
        self.assertEqual(initial_board_cores, required_families)

    def test_openocd_pu_esp32_cfg_workarounds_present(self) -> None:
        cfg_path = ROOT / "catalog" / "openocd" / "pu-esp32.cfg"
        self.assertTrue(cfg_path.is_file(), "catalog/openocd/pu-esp32.cfg must exist")

        content = cfg_path.read_text(encoding="utf-8")
        for required_token in ("ESP32_FLASH_VOLTAGE", "gdb-attach", "examine-end", "gdb-detach"):
            self.assertIn(required_token, content)

    def test_linux_udev_rules_valid_and_complete(self) -> None:
        rules_path = ROOT / "linux" / "60-pico-universal.rules"
        self.assertTrue(rules_path.is_file(), "linux/60-pico-universal.rules must exist")

        content = rules_path.read_text(encoding="utf-8")
        self.assertIn('ATTRS{idVendor}=="2e8a"', content)
        self.assertIn("2e8a", content)
        self.assertIn('TAG+="uaccess"', content)
        self.assertIn("ID_MM_DEVICE_IGNORE", content)
        self.assertIn('ENV{ID_MM_DEVICE_IGNORE}="1"', content)
        self.assertIn("PU_USB_PID", content)

        active_rules = [
            line.strip()
            for line in content.splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
        self.assertGreaterEqual(len(active_rules), 1)
        for rule in active_rules:
            clauses = [c.strip() for c in rule.split(",")]
            for clause in clauses:
                self.assertRegex(
                    clause,
                    r'^[A-Za-z0-9_{}\[\]\-]+(?:==|!=|\+=|=|:=)"[^"]*"$',
                    f"Malformed udev rule clause: {clause!r}",
                )

        udevadm = shutil.which("udevadm")
        if udevadm:
            res = subprocess.run(
                [udevadm, "verify", "--resolve-names=never", str(rules_path)],
                capture_output=True,
                text=True,
            )
            self.assertEqual(res.returncode, 0, f"udevadm verify failed:\n{res.stderr}\n{res.stdout}")


if __name__ == "__main__":
    unittest.main()

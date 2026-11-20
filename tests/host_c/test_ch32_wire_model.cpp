/*
 * Host unit & wire-model test suite for Task 5:
 *   Hardened CH32V003 PIO1 SWIO Engine, PUID1 Non-Destructive Identity
 *   & Cross-Page SoftBreak (firmware/swio_engine.h)
 */

#ifdef NDEBUG
#error "Assertions must remain enabled in host tests"
#endif

#ifndef PU_HOST_TEST
#define PU_HOST_TEST 1
#endif

#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>

#include "config/board_pinout.h"
#include "firmware/engine_owner.h"
#include "firmware/swio_engine.h"

namespace {

int hex_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

std::string extract_gdb_payload(const uint8_t *buf, size_t n) {
    const std::string wire(reinterpret_cast<const char *>(buf), n);
    size_t dollar = wire.find('$');
    assert(dollar != std::string::npos);
    size_t hash = wire.find('#', dollar + 1u);
    assert(hash != std::string::npos && hash + 2u < wire.size());

    uint8_t csum = 0u;
    std::string unescaped;
    for (size_t i = dollar + 1u; i < hash; ++i) {
        csum = static_cast<uint8_t>(csum + static_cast<uint8_t>(wire[i]));
        if (wire[i] == '}' && i + 1u < hash) {
            ++i;
            csum = static_cast<uint8_t>(csum + static_cast<uint8_t>(wire[i]));
            unescaped.push_back(static_cast<char>(wire[i] ^ 0x20));
        } else {
            unescaped.push_back(wire[i]);
        }
    }
    int hi = hex_nibble(wire[hash + 1u]);
    int lo = hex_nibble(wire[hash + 2u]);
    assert(hi >= 0 && lo >= 0);
    assert(static_cast<uint8_t>((hi << 4) | lo) == csum);
    return unescaped;
}

std::string decode_hex_ascii(const std::string &hex) {
    assert((hex.size() % 2u) == 0u);
    std::string out;
    out.reserve(hex.size() / 2u);
    for (size_t i = 0u; i < hex.size(); i += 2u) {
        int hi = hex_nibble(hex[i]);
        int lo = hex_nibble(hex[i + 1u]);
        assert(hi >= 0 && lo >= 0);
        out.push_back(static_cast<char>((hi << 4) | lo));
    }
    return out;
}

/* Custom wire HAL for testing reserved/contradictory DMSTATUS & wire timeouts */
uint32_t g_custom_dmstatus = 0u;
bool g_custom_wire_timeout = false;

bool custom_read_reg(uint8_t reg_addr, uint32_t *out_val, uint32_t /*timeout_us*/) {
    if (g_custom_wire_timeout) {
        return false;
    }
    if (reg_addr == 0x11u /* DMSTATUS */) {
        *out_val = g_custom_dmstatus;
        return true;
    }
    *out_val = 0u;
    return true;
}

bool custom_write_reg(uint8_t /*reg_addr*/, uint32_t /*val*/, uint32_t /*timeout_us*/) {
    return !g_custom_wire_timeout;
}

void test_ch32_silent_bus_never_misclassified() {
    uint8_t out[256] = {};

    /* 1. Silent-high (0xFFFFFFFF): floating pull-up / unplugged target */
    pu_swio_set_fake_wire_mode(PU_WIRE_SILENT_HIGH_FF);
    pu_ch32_check_result_t r_hi = pu_ch32_non_destructive_check(1000u);
    assert(r_hi.status == PU_CH32_ERR_NO_REPLY);
    assert(r_hi.flash_writes == 0u);
    assert(r_hi.diagnosis_mask == PU_CH32_DIAG_ALL_FIVE_CAUSES);
    assert(r_hi.resumed_running == false);
    assert(r_hi.outen_disabled_verified == false);
    assert(pu_engine_current() == PU_ENGINE_IDLE);

    /* GDB memory read & flash erase on 0xFFFFFFFF bus must NEVER claim blank flash or OK */
    assert(pu_ch32_gdb_send_checked("$m08000000,10#", out, sizeof(out), 1100u) != PU_OK);
    assert(extract_gdb_payload(out, std::strlen(reinterpret_cast<const char *>(out)))[0] == 'E');
    assert(pu_ch32_gdb_send_checked("$vFlashErase:08000000,40#", out, sizeof(out), 1200u) != PU_OK);
    assert(extract_gdb_payload(out, std::strlen(reinterpret_cast<const char *>(out)))[0] == 'E');
    pu_ch32_on_disconnect();
    assert(pu_swio_fake_flash_matches_original() == true);

    /* 2. Silent-low (0x00000000): shorted-to-GND / unpowered clamping */
    pu_swio_set_fake_wire_mode(PU_WIRE_SILENT_LOW_00);
    pu_ch32_check_result_t r_lo = pu_ch32_non_destructive_check(2000u);
    assert(r_lo.status == PU_CH32_ERR_NO_REPLY);
    assert(r_lo.flash_writes == 0u);
    assert(r_lo.diagnosis_mask == PU_CH32_DIAG_ALL_FIVE_CAUSES);
    assert(r_lo.resumed_running == false);
    assert(r_lo.outen_disabled_verified == false);
    assert(pu_engine_current() == PU_ENGINE_IDLE);

    assert(pu_ch32_gdb_send_checked("$m08000000,10#", out, sizeof(out), 2100u) != PU_OK);
    assert(extract_gdb_payload(out, std::strlen(reinterpret_cast<const char *>(out)))[0] == 'E');
    assert(pu_ch32_gdb_send_checked("$vFlashErase:08000000,40#", out, sizeof(out), 2200u) != PU_OK);
    assert(extract_gdb_payload(out, std::strlen(reinterpret_cast<const char *>(out)))[0] == 'E');
    pu_ch32_on_disconnect();
    assert(pu_swio_fake_flash_matches_original() == true);

    /* 3. DMSTATUS with non-zero reserved bits or contradictory ANYHALTED|ALLRUNNING */
    pu_swio_wire_hal_t custom_hal = {};
    custom_hal.sys_clock_hz = 125000000u;
    custom_hal.read_reg = custom_read_reg;
    custom_hal.write_reg = custom_write_reg;
    pu_swio_init(&custom_hal);

    /* Non-zero reserved bit [20] on otherwise halted-looking DMSTATUS */
    g_custom_wire_timeout = false;
    g_custom_dmstatus = (1u << 20) | (1u << 9) | (1u << 8) | (1u << 7) | 0x2u;
    pu_ch32_check_result_t r_resv = pu_ch32_non_destructive_check(2300u);
    assert(r_resv.status == PU_CH32_ERR_NO_REPLY);
    assert(r_resv.diagnosis_mask == PU_CH32_DIAG_ALL_FIVE_CAUSES);
    assert(r_resv.flash_writes == 0u);

    /* Contradictory ANYHALTED && ALLRUNNING */
    g_custom_dmstatus = (1u << 11) | (1u << 10) | (1u << 9) | (1u << 8) | (1u << 7) | 0x2u;
    pu_ch32_check_result_t r_contra = pu_ch32_non_destructive_check(2400u);
    assert(r_contra.status == PU_CH32_ERR_NO_REPLY);
    assert(r_contra.diagnosis_mask == PU_CH32_DIAG_ALL_FIVE_CAUSES);
    assert(r_contra.flash_writes == 0u);

    /* Bounded wire timeout on unresponsive bus */
    g_custom_wire_timeout = true;
    pu_ch32_check_result_t r_tout = pu_ch32_non_destructive_check(2500u);
    assert(r_tout.status == PU_CH32_ERR_NO_REPLY);
    assert(r_tout.diagnosis_mask == PU_CH32_DIAG_ALL_FIVE_CAUSES);
    assert(pu_engine_current() == PU_ENGINE_IDLE);
}

void test_ch32_already_halted_rejected() {
    pu_swio_set_fake_wire_mode(PU_WIRE_ALREADY_HALTED);
    pu_ch32_check_result_t r = pu_ch32_non_destructive_check(2800u);
    assert(r.status == PU_CH32_ERR_ALREADY_HALTED);
    assert(r.flash_writes == 0u);
    assert(r.resumed_running == false);
    assert(pu_engine_current() == PU_ENGINE_IDLE);
    assert(pu_swio_fake_flash_matches_original() == true);
}

void test_ch32_check_preserves_running_sketch_and_resets_outen() {
    pu_swio_set_fake_wire_mode(PU_WIRE_HEALTHY_CH32V003);
    pu_ch32_check_result_t r = pu_ch32_non_destructive_check(3000u);
    assert(r.status == PU_CH32_OK);
    assert(r.chip_id != 0u && r.chip_id != 0xFFFFFFFFu);
    assert(r.flash_kb == 16u);
    assert(r.flash_writes == 0u);
    assert(r.diagnosis_mask == 0u);
    assert(r.resumed_running == true);
    assert(r.outen_disabled_verified == true);
    assert(pu_engine_current() == PU_ENGINE_IDLE);
    assert(pu_swio_fake_flash_matches_original() == true);

    /* Monitor command qRcmd,"puid1" over CDC stream */
    uint8_t out[256] = {};
    assert(pu_ch32_gdb_send_checked("$qRcmd,7075696431#", out, sizeof(out), 3200u) == PU_OK);
    std::string hex_reply = extract_gdb_payload(out, std::strlen(reinterpret_cast<const char *>(out)));
    std::string text = decode_hex_ascii(hex_reply);
    assert(text.find("PUID1:OK") == 0u);
    assert(text.find("FLASH_KB=16") != std::string::npos);
    assert(text.find("FLASH_WRITES=0") != std::string::npos);
    assert(pu_engine_current() == PU_ENGINE_IDLE);
}

void test_ch32_outen_reset_and_resume_failures() {
    /* Failed WCH_DM_SHDWCFGR.OUTEN == 0 verification MUST return PU_CH32_ERR_DETACH_FAILED */
    pu_swio_set_fake_wire_mode(PU_WIRE_OUTEN_RESET_FAIL);
    pu_ch32_check_result_t r_outen = pu_ch32_non_destructive_check(3500u);
    assert(r_outen.status == PU_CH32_ERR_DETACH_FAILED);
    assert(r_outen.flash_writes == 0u);
    assert(r_outen.outen_disabled_verified == false);
    assert(pu_engine_current() == PU_ENGINE_IDLE);

    /* Failed post-resume running verification MUST fail */
    pu_swio_set_fake_wire_mode(PU_WIRE_RESUME_FAIL);
    pu_ch32_check_result_t r_res = pu_ch32_non_destructive_check(3700u);
    assert(r_res.status == PU_CH32_ERR_DETACH_FAILED);
    assert(r_res.flash_writes == 0u);
    assert(r_res.resumed_running == false);
    assert(pu_engine_current() == PU_ENGINE_IDLE);
}

void test_ch32_softbreak_cross_page_and_disconnect_restore() {
    pu_swio_set_fake_wire_mode(PU_WIRE_HEALTHY_CH32V003);
    uint8_t out[256] = {};

    /* 1. Cross-page 4-byte software breakpoint at 0x0800003E (bytes 62..65 -> Pages 0 & 1) */
    const char *ins = "$Z0,0800003e,4#";
    assert(pu_ch32_gdb_send_checked(ins, out, sizeof(out), 4000u) == PU_OK);
    assert(extract_gdb_payload(out, std::strlen(reinterpret_cast<const char *>(out))) == "OK");
    assert(pu_swio_fake_flash_matches_original() == false);

    /* Duplicate insert is idempotent */
    assert(pu_ch32_gdb_send_checked(ins, out, sizeof(out), 4050u) == PU_OK);
    assert(extract_gdb_payload(out, std::strlen(reinterpret_cast<const char *>(out))) == "OK");

    /* Overlapping breakpoints (second halfword in next page, preceding word, mismatched size) rejected */
    assert(pu_ch32_gdb_send_checked("$Z0,08000040,2#", out, sizeof(out), 4100u) != PU_OK);
    assert(pu_ch32_gdb_send_checked("$Z0,0800003c,4#", out, sizeof(out), 4110u) != PU_OK);
    assert(pu_ch32_gdb_send_checked("$Z0,0800003e,2#", out, sizeof(out), 4120u) != PU_OK);

    /* 2. Final 2-byte compressed instruction at 0x08003FFE valid; 4-byte at 0x08003FFE & past-end rejected */
    assert(pu_ch32_gdb_send_checked("$Z0,08003ffe,2#", out, sizeof(out), 4200u) == PU_OK);
    assert(pu_ch32_gdb_send_checked("$Z0,08003ffe,4#", out, sizeof(out), 4210u) != PU_OK);
    assert(pu_ch32_gdb_send_checked("$Z0,08004000,2#", out, sizeof(out), 4220u) != PU_OK);
    assert(pu_ch32_gdb_send_checked("$Z0,07fffffe,2#", out, sizeof(out), 4230u) != PU_OK);

    /* Duplicate remove is idempotent */
    assert(pu_ch32_gdb_send_checked("$z0,08003ffe,2#", out, sizeof(out), 4240u) == PU_OK);
    assert(pu_ch32_gdb_send_checked("$z0,08003ffe,2#", out, sizeof(out), 4250u) == PU_OK);

    /* 3. Z1 / z1 hardware breakpoints return empty unsupported reply ($#00) */
    assert(pu_ch32_gdb_send_checked("$Z1,08000000,2#", out, sizeof(out), 4300u) == PU_OK);
    assert(extract_gdb_payload(out, std::strlen(reinterpret_cast<const char *>(out))).empty());
    assert(pu_ch32_gdb_send_checked("$z1,08000000,2#", out, sizeof(out), 4310u) == PU_OK);
    assert(extract_gdb_payload(out, std::strlen(reinterpret_cast<const char *>(out))).empty());

    /* Stage partial vFlashWrite data before disconnect to confirm cache cleanup */
    assert(pu_ch32_gdb_send_checked("$vFlashWrite:08000100:\xAA\xBB#", out, sizeof(out), 4350u) == PU_OK);

    /* 4. Disconnect restores ALL original flash bytes across both pages & drops stale vFlash cache */
    pu_ch32_on_disconnect();
    assert(pu_swio_fake_flash_matches_original() == true);
    assert(pu_engine_current() == PU_ENGINE_IDLE);

    /* Subsequent vFlashDone in a fresh session must not flush the discarded partial write */
    assert(pu_ch32_gdb_send_checked("$vFlashDone#", out, sizeof(out), 4400u) == PU_OK);
    pu_ch32_on_disconnect();
    assert(pu_swio_fake_flash_matches_original() == true);

    /* 5. Flash write failure on second page of cross-page SoftBreak propagates failure & rolls back */
    pu_swio_inject_fake_flash_write_fail(1);
    assert(pu_ch32_gdb_send_checked("$Z0,0800003e,4#", out, sizeof(out), 4500u) != PU_OK);
    assert(extract_gdb_payload(out, std::strlen(reinterpret_cast<const char *>(out)))[0] == 'E');
    pu_swio_inject_fake_flash_write_fail(-1);
    pu_ch32_on_disconnect();
    assert(pu_swio_fake_flash_matches_original() == true);
}

void test_ch32_gdb_parser_hardening() {
    pu_swio_set_fake_wire_mode(PU_WIRE_HEALTHY_CH32V003);
    uint8_t out[256] = {};

    /* 1. Malformed checksum & non-hex checksum digits -> NACK '-', no engine acquisition */
    const char *bad_csum = "$m08000000,4#00";
    size_t n = pu_ch32_gdb_feed(reinterpret_cast<const uint8_t *>(bad_csum),
                                std::strlen(bad_csum), out, sizeof(out), 5000u);
    assert(n == 1u && out[0] == '-');
    assert(pu_engine_current() == PU_ENGINE_IDLE);

    const char *non_hex_csum = "$?#zz";
    n = pu_ch32_gdb_feed(reinterpret_cast<const uint8_t *>(non_hex_csum),
                         std::strlen(non_hex_csum), out, sizeof(out), 5010u);
    assert(n == 1u && out[0] == '-');
    assert(pu_engine_current() == PU_ENGINE_IDLE);

    /* 2. Interrupted '$' framing resynchronizes cleanly onto the second '$' */
    const char *resync = "$truncated_partial$?#3f";
    n = pu_ch32_gdb_feed(reinterpret_cast<const uint8_t *>(resync),
                         std::strlen(resync), out, sizeof(out), 5020u);
    assert(n > 0u && out[0] == '+');
    assert(extract_gdb_payload(out, n) == "T05");

    /* 3. Wrapped uint32 ranges (0xFFFFFFF0,20) and trailing garbage rejected */
    assert(pu_ch32_gdb_send_checked("$mfffffff0,20#", out, sizeof(out), 5100u) != PU_OK);
    assert(extract_gdb_payload(out, std::strlen(reinterpret_cast<const char *>(out))) == "E01");

    assert(pu_ch32_gdb_send_checked(
               "$Mfffffff0,20:00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff#",
               out, sizeof(out), 5110u) != PU_OK);
    assert(extract_gdb_payload(out, std::strlen(reinterpret_cast<const char *>(out))) == "E01");

    assert(pu_ch32_gdb_send_checked("$qCRC:fffffff0,20#", out, sizeof(out), 5120u) != PU_OK);
    assert(pu_ch32_gdb_send_checked("$vFlashErase:fffffff0,40#", out, sizeof(out), 5130u) != PU_OK);
    assert(pu_ch32_gdb_send_checked("$m08000000,4trailing#", out, sizeof(out), 5140u) != PU_OK);
    assert(pu_ch32_gdb_send_checked("$vFlashErase:08000000,40garbage#", out, sizeof(out), 5150u) != PU_OK);

    pu_ch32_on_disconnect();
    assert(pu_swio_fake_flash_matches_original() == true);
}

void test_ch32_contention_fault_and_unbrick() {
    pu_swio_set_fake_wire_mode(PU_WIRE_HEALTHY_CH32V003);
    uint8_t out[256] = {};

    /* Cross-interface contention: CMSIS-DAP SWD owns debug pins */
    assert(pu_engine_acquire(PU_ENGINE_SWD, 6000u, 500000u) == PU_OK);

    pu_ch32_check_result_t r_busy = pu_ch32_non_destructive_check(6100u);
    assert(r_busy.status == PU_CH32_ERR_BUSY);
    assert(r_busy.flash_writes == 0u);
    assert(pu_engine_current() == PU_ENGINE_SWD);

    assert(pu_ch32_gdb_send_checked("$?#", out, sizeof(out), 6200u) == PU_ERR_ENGINE_BUSY);
    assert(pu_engine_current() == PU_ENGINE_SWD);

    assert(pu_ch32_power_cycle_unbrick(6300u) == PU_ERR_ENGINE_BUSY);
    assert(pu_engine_current() == PU_ENGINE_SWD);

    assert(pu_engine_release(PU_ENGINE_SWD) == PU_OK);

    /* Latched hardware overcurrent fault blocks SWIO & recovery */
    pu_engine_latch_fault(PU_FAULT_OVERCURRENT);
    pu_ch32_check_result_t r_fault = pu_ch32_non_destructive_check(6400u);
    assert(r_fault.status == PU_CH32_ERR_FAULT);
    assert(pu_ch32_power_cycle_unbrick(6500u) == PU_ERR_FAULT_LATCHED);
    assert(pu_engine_clear_fault() == PU_OK);

    /* Power-cycle unbrick acquires & cleanly releases PU_ENGINE_RECOVERY */
    assert(pu_ch32_power_cycle_unbrick(7000u) == PU_OK);
    assert(pu_engine_current() == PU_ENGINE_IDLE);

    /* Review Focus #3: After deadline expiry revokes a crashed GDB session,
     * the very next GDB session must seamlessly re-acquire PU_ENGINE_SWIO without replugging. */
    assert(pu_ch32_gdb_send_checked("$?#", out, sizeof(out), 8000u) == PU_OK);
    assert(pu_engine_current() == PU_ENGINE_SWIO);
    pu_engine_tick(8000u + PU_SWIO_SESSION_TIMEOUT_US + 10u);
    assert(pu_engine_current() == PU_ENGINE_IDLE);

    assert(pu_ch32_gdb_send_checked("$?#", out, sizeof(out), 9000000u) == PU_OK);
    assert(extract_gdb_payload(out, std::strlen(reinterpret_cast<const char *>(out))) == "T05");
    assert(pu_engine_current() == PU_ENGINE_SWIO);
    pu_ch32_on_disconnect();
    assert(pu_engine_current() == PU_ENGINE_IDLE);
}

void test_ch32_register_preservation_step_and_vflash_roundtrip() {
    pu_swio_set_fake_wire_mode(PU_WIRE_HEALTHY_CH32V003);
    uint8_t out[512] = {};

    /* 1. PUID1 check + GDB memory/SoftBreak must preserve scratch GPRs x8 (s0/fp) & x9 (s1) */
    pu_ch32_check_result_t r = pu_ch32_non_destructive_check(10000u);
    assert(r.status == PU_CH32_OK);

    assert(pu_ch32_gdb_send_checked("$p8#", out, sizeof(out), 10100u) == PU_OK);
    const std::string x8_before = extract_gdb_payload(out, std::strlen(reinterpret_cast<const char *>(out)));
    assert(pu_ch32_gdb_send_checked("$p9#", out, sizeof(out), 10110u) == PU_OK);
    const std::string x9_before = extract_gdb_payload(out, std::strlen(reinterpret_cast<const char *>(out)));

    /* Cross-page SoftBreak at 0x0800003E + memory read across boundary returns clean bytes */
    assert(pu_ch32_gdb_send_checked("$m0800003e,4#", out, sizeof(out), 10200u) == PU_OK);
    const std::string orig_insn_hex = extract_gdb_payload(out, std::strlen(reinterpret_cast<const char *>(out)));
    assert(pu_ch32_gdb_send_checked("$Z0,0800003e,4#", out, sizeof(out), 10210u) == PU_OK);
    assert(pu_ch32_gdb_send_checked("$m0800003e,4#", out, sizeof(out), 10220u) == PU_OK);
    assert(extract_gdb_payload(out, std::strlen(reinterpret_cast<const char *>(out))) == orig_insn_hex);

    /* Single-stepping directly from 0x0800003E while Z0 is active steps the real instruction */
    assert(pu_ch32_gdb_send_checked("$s0800003e#", out, sizeof(out), 10230u) == PU_OK);
    assert(extract_gdb_payload(out, std::strlen(reinterpret_cast<const char *>(out))) == "T05");
    assert(pu_ch32_gdb_send_checked("$p10#", out, sizeof(out), 10240u) == PU_OK);
    /* PC (reg 0x10 = 16) must have advanced past 0x0800003E (not trapped in-place on ebreak!) */
    assert(extract_gdb_payload(out, std::strlen(reinterpret_cast<const char *>(out))) != "3e000008");

    /* Verify x8 & x9 were completely preserved */
    assert(pu_ch32_gdb_send_checked("$p8#", out, sizeof(out), 10250u) == PU_OK);
    assert(extract_gdb_payload(out, std::strlen(reinterpret_cast<const char *>(out))) == x8_before);
    assert(pu_ch32_gdb_send_checked("$p9#", out, sizeof(out), 10260u) == PU_OK);
    assert(extract_gdb_payload(out, std::strlen(reinterpret_cast<const char *>(out))) == x9_before);

    pu_ch32_on_disconnect();
    assert(pu_swio_fake_flash_matches_original() == true);
}

} // namespace

int main() {
    test_ch32_silent_bus_never_misclassified();
    test_ch32_already_halted_rejected();
    test_ch32_check_preserves_running_sketch_and_resets_outen();
    test_ch32_outen_reset_and_resume_failures();
    test_ch32_softbreak_cross_page_and_disconnect_restore();
    test_ch32_gdb_parser_hardening();
    test_ch32_contention_fault_and_unbrick();
    test_ch32_register_preservation_step_and_vflash_roundtrip();
    std::puts("test_ch32_wire_model: all checks passed");
    return 0;
}

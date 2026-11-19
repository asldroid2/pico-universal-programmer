/*
 * Host unit & 50,000-packet deterministic fuzz tests for Pico Universal's
 * hardened CMSIS-DAP v2 engine (dap_engine + dap_guard + engine_owner).
 */

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "firmware/dap_engine.h"
#include "firmware/engine_owner.h"

static uint32_t xorshift32(uint32_t *s) {
    uint32_t x = *s;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    *s = x;
    return x;
}

static void test_dap_info_and_basic_commands(void) {
    pu_dap_init_for_test();
    uint8_t resp[64];

    /* Product string must be "Pico Universal CMSIS-DAP" */
    const uint8_t req_prod[2] = {ID_DAP_Info, DAP_ID_PRODUCT};
    size_t n = pu_dap_process_packet(req_prod, sizeof(req_prod), resp, sizeof(resp), 100u);
    const char *expected_prod = "Pico Universal CMSIS-DAP";
    assert(n == 2u + strlen(expected_prod) + 1u);
    assert(resp[0] == ID_DAP_Info);
    assert(resp[1] == strlen(expected_prod) + 1u);
    assert(memcmp(&resp[2], expected_prod, strlen(expected_prod) + 1u) == 0);

    /* Serial string must be 16 hex chars + NUL = 17 bytes */
    const uint8_t req_ser[2] = {ID_DAP_Info, DAP_ID_SER_NUM};
    n = pu_dap_process_packet(req_ser, sizeof(req_ser), resp, sizeof(resp), 200u);
    assert(n == 19u && resp[0] == ID_DAP_Info && resp[1] == 17u && resp[18] == '\0');

    /* Capabilities must include both SWD (bit 0) and JTAG (bit 1) */
    const uint8_t req_cap[2] = {ID_DAP_Info, DAP_ID_CAPABILITIES};
    n = pu_dap_process_packet(req_cap, sizeof(req_cap), resp, sizeof(resp), 300u);
    assert(n == 3u && resp[0] == ID_DAP_Info && resp[1] == 1u);
    assert((resp[2] & 0x03u) == 0x03u);

    /* Packet Size must be 64 (0x0040 LE) */
    const uint8_t req_psize[2] = {ID_DAP_Info, DAP_ID_PACKET_SIZE};
    n = pu_dap_process_packet(req_psize, sizeof(req_psize), resp, sizeof(resp), 400u);
    assert(n == 4u && resp[0] == ID_DAP_Info && resp[1] == 2u);
    assert(resp[2] == 64u && resp[3] == 0u);

    /* Packet Count >= 1 */
    const uint8_t req_pcnt[2] = {ID_DAP_Info, DAP_ID_PACKET_COUNT};
    n = pu_dap_process_packet(req_pcnt, sizeof(req_pcnt), resp, sizeof(resp), 500u);
    assert(n == 3u && resp[0] == ID_DAP_Info && resp[1] == 1u && resp[2] >= 1u);
}

/* Spy state for verifying buffer-snapshot isolation, pin handoff, and zero-touch contention */
typedef struct {
    unsigned port_setup_calls;
    unsigned port_off_calls;
    unsigned swd_transfer_calls;
    unsigned pio_drain_calls;
    unsigned sio_override_calls;
    unsigned pin_io_calls;
    unsigned sio_release_calls;
    uint32_t last_pin_wait_us;
    uint8_t step_log[8];
    unsigned step_count;
    uint8_t *mutated_caller_buf;
    size_t mutated_caller_len;
    uint32_t dp_ctrl_stat;
} spy_wire_state_t;

static spy_wire_state_t g_spy;

static void spy_port_setup(uint8_t port) {
    (void)port;
    g_spy.port_setup_calls++;
}

static void spy_port_off(void) {
    g_spy.port_off_calls++;
}

static uint8_t spy_swd_transfer(uint8_t req_hdr,
                                uint32_t *data,
                                uint8_t turnaround_cycles,
                                bool force_data_phase) {
    (void)turnaround_cycles;
    (void)force_data_phase;
    g_spy.swd_transfer_calls++;
    /* Simulate USB reset / ring reuse corrupting caller's request buffer mid-batch! */
    if (g_spy.mutated_caller_buf != NULL) {
        memset(g_spy.mutated_caller_buf, 0xFF, g_spy.mutated_caller_len);
        g_spy.mutated_caller_buf = NULL;
    }
    if ((req_hdr & DAP_TRANSFER_RnW) != 0u) {
        *data = g_spy.dp_ctrl_stat;
    } else {
        g_spy.dp_ctrl_stat = *data;
    }
    return DAP_TRANSFER_OK;
}

static void spy_pio_drain(void) {
    g_spy.pio_drain_calls++;
    if (g_spy.step_count < sizeof(g_spy.step_log)) {
        g_spy.step_log[g_spy.step_count++] = 1u;
    }
}

static void spy_sio_override_begin(void) {
    g_spy.sio_override_calls++;
    if (g_spy.step_count < sizeof(g_spy.step_log)) {
        g_spy.step_log[g_spy.step_count++] = 2u;
    }
}

static uint8_t spy_swj_pins_io(uint8_t pin_output, uint8_t pin_select, uint32_t wait_us) {
    g_spy.pin_io_calls++;
    g_spy.last_pin_wait_us = wait_us;
    if (g_spy.step_count < sizeof(g_spy.step_log)) {
        g_spy.step_log[g_spy.step_count++] = 3u;
    }
    return (uint8_t)((pin_output & pin_select) | (~pin_select & PU_DAP_PIN_nRESET));
}

static void spy_sio_override_end(void) {
    g_spy.sio_release_calls++;
    if (g_spy.step_count < sizeof(g_spy.step_log)) {
        g_spy.step_log[g_spy.step_count++] = 4u;
    }
}

static void init_spy_dap(void) {
    memset(&g_spy, 0, sizeof(g_spy));
    pu_dap_init_for_test();
    pu_dap_wire_hal_t hal;
    memset(&hal, 0, sizeof(hal));
    hal.sys_clock_hz = 125000000u;
    hal.port_setup = spy_port_setup;
    hal.port_off = spy_port_off;
    hal.swd_transfer = spy_swd_transfer;
    hal.pio_drain = spy_pio_drain;
    hal.sio_override_begin = spy_sio_override_begin;
    hal.swj_pins_io = spy_swj_pins_io;
    hal.sio_override_end = spy_sio_override_end;
    pu_dap_init(&hal);
}

static void test_dap_guard_snapshot_survives_buffer_reuse(void) {
    /*
     * 4-command batch:
     *   1. DAP_Connect(SWD)              -> [0x02, 0x01] (2B)
     *   2. DAP_Transfer(write 0xA55A1234)-> [0x05, 0x01, 0x01] (3B)
     *   3. DAP_Transfer(read)            -> [0x05, 0x01, 0x01, 0x34, 0x12, 0x5A, 0xA5] (7B)
     *   4. DAP_Disconnect                -> [0x03, 0x00] (2B)
     * Total response = 2 (batch hdr) + 2 + 3 + 7 + 2 = 16 bytes.
     */
    const uint8_t kBatch[] = {
        ID_DAP_ExecuteCommands, 4u,
        ID_DAP_Connect, DAP_PORT_SWD,
        ID_DAP_Transfer, 0u, 1u, 0x04u /* DP Write */, 0x34u, 0x12u, 0x5Au, 0xA5u,
        ID_DAP_Transfer, 0u, 1u, 0x06u /* DP Read */,
        ID_DAP_Disconnect
    };

    /* Run 1: Clean separate buffers */
    init_spy_dap();
    uint8_t clean_resp[64] = {0};
    size_t clean_len = pu_dap_process_packet(kBatch, sizeof(kBatch), clean_resp, sizeof(clean_resp), 1000u);
    assert(clean_len == 16u);
    assert(clean_resp[0] == ID_DAP_ExecuteCommands && clean_resp[1] == 4u);
    assert(clean_resp[2] == ID_DAP_Connect && clean_resp[3] == DAP_PORT_SWD);
    assert(clean_resp[4] == ID_DAP_Transfer && clean_resp[5] == 1u && clean_resp[6] == DAP_TRANSFER_OK);
    assert(clean_resp[7] == ID_DAP_Transfer && clean_resp[8] == 1u && clean_resp[9] == DAP_TRANSFER_OK);
    assert(clean_resp[10] == 0x34u && clean_resp[11] == 0x12u &&
           clean_resp[12] == 0x5Au && clean_resp[13] == 0xA5u);
    assert(clean_resp[14] == ID_DAP_Disconnect && clean_resp[15] == DAP_OK);

    /* Run 2: Aliased in-place buffer (req == resp) */
    init_spy_dap();
    uint8_t shared_buf[64] = {0};
    memcpy(shared_buf, kBatch, sizeof(kBatch));
    size_t aliased_len = pu_dap_process_packet(shared_buf, sizeof(kBatch), shared_buf, sizeof(shared_buf), 2000u);
    assert(aliased_len == clean_len);
    assert(memcmp(shared_buf, clean_resp, clean_len) == 0);

    /* Run 3: Mid-batch caller buffer overwrite (simulating USB reset clearing RX ring) */
    init_spy_dap();
    uint8_t volatile_req[64];
    memcpy(volatile_req, kBatch, sizeof(kBatch));
    g_spy.mutated_caller_buf = volatile_req;
    g_spy.mutated_caller_len = sizeof(volatile_req);
    uint8_t mutated_resp[64] = {0};
    size_t mutated_len = pu_dap_process_packet(volatile_req, sizeof(kBatch), mutated_resp, sizeof(mutated_resp), 3000u);
    assert(volatile_req[0] == 0xFFu); /* Confirm callback really wiped caller's buffer */
    assert(mutated_len == clean_len);
    assert(memcmp(mutated_resp, clean_resp, clean_len) == 0);
}

static void test_dap_cross_interface_contention_and_deadline_renewal(void) {
    init_spy_dap();
    uint8_t resp[64];

    /* Simulate IF 1-2 CH32 SWIO owning engine_owner */
    assert(pu_engine_acquire(PU_ENGINE_SWIO, 1000u, 500000u) == PU_OK);

    const uint8_t conn_swd[2] = {ID_DAP_Connect, DAP_PORT_SWD};
    size_t n = pu_dap_process_packet(conn_swd, sizeof(conn_swd), resp, sizeof(resp), 1100u);
    assert(n == 2u && resp[0] == ID_DAP_Connect && resp[1] == 0x00u);
    assert(pu_engine_current() == PU_ENGINE_SWIO);
    assert(g_spy.port_setup_calls == 0u && g_spy.swd_transfer_calls == 0u);

    const uint8_t conn_jtag[2] = {ID_DAP_Connect, DAP_PORT_JTAG};
    n = pu_dap_process_packet(conn_jtag, sizeof(conn_jtag), resp, sizeof(resp), 1200u);
    assert(n == 2u && resp[0] == ID_DAP_Connect && resp[1] == 0x00u);
    assert(pu_engine_current() == PU_ENGINE_SWIO);
    assert(g_spy.port_setup_calls == 0u);

    /* DAP_Disconnect while SWIO owns bus must NOT release SWIO! */
    const uint8_t disc[1] = {ID_DAP_Disconnect};
    n = pu_dap_process_packet(disc, sizeof(disc), resp, sizeof(resp), 1300u);
    assert(n == 2u && resp[0] == ID_DAP_Disconnect);
    assert(pu_engine_current() == PU_ENGINE_SWIO);

    /* Release SWIO, latch hardware FAULT -> DAP_Connect must fail cleanly */
    assert(pu_engine_release(PU_ENGINE_SWIO) == PU_OK);
    pu_engine_latch_fault(PU_FAULT_OVERCURRENT);
    n = pu_dap_process_packet(conn_swd, sizeof(conn_swd), resp, sizeof(resp), 1400u);
    assert(n == 2u && resp[0] == ID_DAP_Connect && resp[1] == 0x00u);
    assert(pu_engine_current() == PU_ENGINE_FAULT);
    assert(g_spy.port_setup_calls == 0u);

    /* Clear fault -> DAP_Connect(SWD) succeeds and renews deadline on traffic */
    assert(pu_engine_clear_fault() == PU_OK);
    n = pu_dap_process_packet(conn_swd, sizeof(conn_swd), resp, sizeof(resp), 2000u);
    assert(n == 2u && resp[0] == ID_DAP_Connect && resp[1] == DAP_PORT_SWD);
    assert(pu_engine_current() == PU_ENGINE_SWD);
    assert(g_spy.port_setup_calls == 1u);

    /* Renew deadline with an active transfer near session expiry */
    const uint8_t xfer[8] = {ID_DAP_Transfer, 0u, 1u, 0x00u, 0x01u, 0x00u, 0x00u, 0x00u};
    n = pu_dap_process_packet(xfer, sizeof(xfer), resp, sizeof(resp), 2000u + PU_DAP_SESSION_TIMEOUT_US - 10u);
    assert(n == 3u && resp[2] == DAP_TRANSFER_OK);
    /* Tick past original connect deadline -> still alive because transfer renewed deadline! */
    pu_engine_tick(2000u + PU_DAP_SESSION_TIMEOUT_US + 100u);
    assert(pu_engine_current() == PU_ENGINE_SWD);

    /* Now let renewed deadline expire via pu_engine_tick and let SWIO take over */
    pu_engine_tick(2000u + 2u * PU_DAP_SESSION_TIMEOUT_US + 100u);
    assert(pu_engine_current() == PU_ENGINE_IDLE);
    assert(pu_engine_acquire(PU_ENGINE_SWIO, 20000000u, 500000u) == PU_OK);

    /* Stale DAP session must detect lost ownership and refuse wire access */
    uint32_t prev_swd_calls = g_spy.swd_transfer_calls;
    n = pu_dap_process_packet(xfer, sizeof(xfer), resp, sizeof(resp), 20000100u);
    assert(n == 3u && resp[1] == 0u && resp[2] == DAP_TRANSFER_ERROR);
    assert(g_spy.swd_transfer_calls == prev_swd_calls);
    assert(pu_engine_current() == PU_ENGINE_SWIO);

    /* Once SWIO releases, DAP_Connect(SWD) cleanly re-acquires */
    assert(pu_engine_release(PU_ENGINE_SWIO) == PU_OK);
    n = pu_dap_process_packet(conn_swd, sizeof(conn_swd), resp, sizeof(resp), 20000200u);
    assert(n == 2u && resp[1] == DAP_PORT_SWD);
    assert(pu_engine_current() == PU_ENGINE_SWD);

    /* USB disconnect tears down SWD ownership cleanly */
    pu_dap_on_usb_disconnect();
    assert(pu_engine_current() == PU_ENGINE_IDLE);
    assert(g_spy.port_off_calls == 1u);
}

static void test_dap_swj_pins_handoff_and_bounded_wait(void) {
    init_spy_dap();
    uint8_t resp[64];
    const uint8_t conn_swd[2] = {ID_DAP_Connect, DAP_PORT_SWD};
    assert(pu_dap_process_packet(conn_swd, 2u, resp, sizeof(resp), 100u) == 2u);
    assert(resp[1] == DAP_PORT_SWD);

    /* Request SWCLK/SWDIO/nRESET override with huge 0xFFFFFFFF wait -> must bound wait and enforce order */
    const uint8_t pins_req[7] = {
        ID_DAP_SWJ_Pins,
        PU_DAP_PIN_SWDIO_TMS,
        (uint8_t)(PU_DAP_PIN_SWCLK_TCK | PU_DAP_PIN_SWDIO_TMS | PU_DAP_PIN_nRESET),
        0xFFu, 0xFFu, 0xFFu, 0xFFu
    };
    size_t n = pu_dap_process_packet(pins_req, sizeof(pins_req), resp, sizeof(resp), 200u);
    assert(n == 2u && resp[0] == ID_DAP_SWJ_Pins);
    assert(g_spy.step_count == 4u);
    assert(g_spy.step_log[0] == 1u); /* 1. PIO drain */
    assert(g_spy.step_log[1] == 2u); /* 2. SIO override begin */
    assert(g_spy.step_log[2] == 3u); /* 3. Pin write/wait/read */
    assert(g_spy.step_log[3] == 4u); /* 4. Release overrides */
    assert(g_spy.last_pin_wait_us <= PU_DAP_MAX_PIN_WAIT_US);
}

static void test_dap_clock_64bit_math(void) {
    pu_dap_init_for_test();
    uint8_t resp[64];

    /* 0 Hz must be rejected cleanly */
    const uint8_t clk_zero[5] = {ID_DAP_SWJ_Clock, 0u, 0u, 0u, 0u};
    size_t n = pu_dap_process_packet(clk_zero, sizeof(clk_zero), resp, sizeof(resp), 100u);
    assert(n == 2u && resp[0] == ID_DAP_SWJ_Clock && resp[1] == DAP_ERROR);
    uint32_t eff_khz = 999u;
    assert(pu_dap_compute_pio_clkdiv_q16_8(125000000u, 0u, &eff_khz) == 0u);

    /* 1 Hz and 500 Hz clamp to 1 kHz floor */
    const uint8_t clk_1hz[5] = {ID_DAP_SWJ_Clock, 1u, 0u, 0u, 0u};
    n = pu_dap_process_packet(clk_1hz, sizeof(clk_1hz), resp, sizeof(resp), 200u);
    assert(n == 2u && resp[0] == ID_DAP_SWJ_Clock && resp[1] == DAP_OK);
    uint32_t div_1hz = pu_dap_compute_pio_clkdiv_q16_8(125000000u, 1u, &eff_khz);
    assert(div_1hz >= 256u && div_1hz <= 0xFFFFFFu);
    assert(eff_khz == 1u);

    uint32_t div_500hz = pu_dap_compute_pio_clkdiv_q16_8(125000000u, 500u, &eff_khz);
    assert(div_500hz == div_1hz && eff_khz == 1u);

    /* High MHz (UINT32_MAX) clamps cleanly without 32-bit overflow */
    const uint8_t clk_max[5] = {ID_DAP_SWJ_Clock, 0xFFu, 0xFFu, 0xFFu, 0xFFu};
    n = pu_dap_process_packet(clk_max, sizeof(clk_max), resp, sizeof(resp), 300u);
    assert(n == 2u && resp[0] == ID_DAP_SWJ_Clock && resp[1] == DAP_OK);
    uint32_t div_max = pu_dap_compute_pio_clkdiv_q16_8(125000000u, UINT32_MAX, &eff_khz);
    assert(div_max >= 256u);
    assert(eff_khz <= (PU_DAP_MAX_CLOCK_HZ / 1000u));

    /* Legacy delay-to-kHz helper parity with origin/linux-focused clock_math.h */
    assert(pu_dap_delay_to_khz(125000000u, 624u) == 100u);
    assert(pu_dap_delay_to_khz(125000000u, UINT32_MAX) == 1u);
    assert(pu_dap_delay_to_khz(125000000u, 62500000u) == 1u);
}

static void test_dap_bounds_jtag_and_batch_guards(void) {
    init_spy_dap();
    uint8_t resp[64];

    /* JTAG chain > 8 devices, 0 devices, 0 IR length, >32 IR length all rejected */
    uint8_t jtag_9[11] = {ID_DAP_JTAG_Configure, 9u, 4, 4, 4, 4, 4, 4, 4, 4, 4};
    assert(pu_dap_process_packet(jtag_9, sizeof(jtag_9), resp, sizeof(resp), 100u) == 1u && resp[0] == ID_DAP_Invalid);
    uint8_t jtag_0[2] = {ID_DAP_JTAG_Configure, 0u};
    assert(pu_dap_process_packet(jtag_0, sizeof(jtag_0), resp, sizeof(resp), 100u) == 1u && resp[0] == ID_DAP_Invalid);
    uint8_t jtag_ir0[3] = {ID_DAP_JTAG_Configure, 1u, 0u};
    assert(pu_dap_process_packet(jtag_ir0, sizeof(jtag_ir0), resp, sizeof(resp), 100u) == 1u && resp[0] == ID_DAP_Invalid);
    uint8_t jtag_ir33[3] = {ID_DAP_JTAG_Configure, 1u, 33u};
    assert(pu_dap_process_packet(jtag_ir33, sizeof(jtag_ir33), resp, sizeof(resp), 100u) == 1u && resp[0] == ID_DAP_Invalid);

    /* Valid JTAG session: Connect(JTAG) -> JTAG_Configure(2 TAPs: IR 4, 5) -> JTAG_IDCODE(0) -> JTAG_Sequence -> Disconnect */
    pu_dap_init_for_test();
    const uint8_t conn_jtag[2] = {ID_DAP_Connect, DAP_PORT_JTAG};
    assert(pu_dap_process_packet(conn_jtag, 2u, resp, sizeof(resp), 200u) == 2u && resp[1] == DAP_PORT_JTAG);
    const uint8_t jtag_ok[4] = {ID_DAP_JTAG_Configure, 2u, 4u, 5u};
    assert(pu_dap_process_packet(jtag_ok, sizeof(jtag_ok), resp, sizeof(resp), 210u) == 2u && resp[1] == DAP_OK);
    const uint8_t jtag_id[2] = {ID_DAP_JTAG_IDCODE, 0u};
    assert(pu_dap_process_packet(jtag_id, sizeof(jtag_id), resp, sizeof(resp), 220u) == 6u && resp[1] == DAP_OK);
    const uint8_t jtag_seq[4] = {ID_DAP_JTAG_Sequence, 1u, (uint8_t)(0x80u | 8u) /* capture 8 bits, TMS=0 */, 0xA5u};
    assert(pu_dap_process_packet(jtag_seq, sizeof(jtag_seq), resp, sizeof(resp), 230u) == 3u && resp[1] == DAP_OK);
    const uint8_t disc[1] = {ID_DAP_Disconnect};
    assert(pu_dap_process_packet(disc, 1u, resp, sizeof(resp), 240u) == 2u && resp[1] == DAP_OK);

    /* SWJ_Sequence with bit_count == 0 (256 bits) requires 2 + 32 = 34 bytes */
    uint8_t swj_256[34];
    memset(swj_256, 0xFF, sizeof(swj_256));
    swj_256[0] = ID_DAP_SWJ_Sequence;
    swj_256[1] = 0u; /* 256 bits */
    assert(pu_dap_process_packet(swj_256, 33u, resp, sizeof(resp), 300u) == 1u && resp[0] == ID_DAP_Invalid);
    assert(pu_dap_process_packet(conn_jtag, 2u, resp, sizeof(resp), 310u) == 2u);
    assert(pu_dap_process_packet(swj_256, 34u, resp, sizeof(resp), 320u) == 2u && resp[1] == DAP_OK);
    (void)pu_dap_process_packet(disc, 1u, resp, sizeof(resp), 330u);

    /* TransferBlock read overflow: 16 words -> 4 + 64 = 68B > 64B rejected; 15 words -> 64B valid */
    const uint8_t blk_16[5] = {ID_DAP_TransferBlock, 0u, 16u, 0u, DAP_TRANSFER_RnW};
    assert(pu_dap_process_packet(blk_16, sizeof(blk_16), resp, sizeof(resp), 400u) == 1u && resp[0] == ID_DAP_Invalid);
    const uint8_t blk_15[5] = {ID_DAP_TransferBlock, 0u, 15u, 0u, DAP_TRANSFER_RnW};
    assert(pu_dap_process_packet(blk_15, sizeof(blk_15), resp, sizeof(resp), 410u) >= 4u && resp[0] == ID_DAP_TransferBlock);

    /* Overflowing batch rejected BEFORE executing any sub-command */
    init_spy_dap();
    const uint8_t overflow_batch[] = {
        ID_DAP_ExecuteCommands, 3u,
        ID_DAP_Connect, DAP_PORT_SWD,
        ID_DAP_TransferBlock, 0u, 10u, 0u, DAP_TRANSFER_RnW, /* 44B reply */
        ID_DAP_TransferBlock, 0u, 10u, 0u, DAP_TRANSFER_RnW  /* +44B -> 92B > 64B! */
    };
    assert(pu_dap_process_packet(overflow_batch, sizeof(overflow_batch), resp, sizeof(resp), 500u) == 1u);
    assert(resp[0] == ID_DAP_Invalid);
    assert(g_spy.port_setup_calls == 0u && g_spy.swd_transfer_calls == 0u);

    /* Nested ExecuteCommands rejected */
    const uint8_t nested_batch[] = {ID_DAP_ExecuteCommands, 1u, ID_DAP_QueueCommands, 1u, ID_DAP_Disconnect};
    assert(pu_dap_process_packet(nested_batch, sizeof(nested_batch), resp, sizeof(resp), 510u) == 1u);
    assert(resp[0] == ID_DAP_Invalid);
}

static void test_50000_fuzzed_packets(void) {
    pu_dap_init_for_test();
    uint32_t seed = 0xC0FFEE42u;

    for (uint32_t i = 0; i < 50000u; ++i) {
        size_t req_len = xorshift32(&seed) % 69u; /* 0..68 including oversized >64 */
        size_t resp_cap = (i % 17u == 0u) ? (xorshift32(&seed) % 65u) : 64u;

        uint8_t *req = (uint8_t *)malloc(req_len != 0u ? req_len : 1u);
        uint8_t *resp = (uint8_t *)malloc(resp_cap != 0u ? resp_cap : 1u);
        assert(req != NULL && resp != NULL);

        for (size_t j = 0; j < req_len; ++j) {
            req[j] = (uint8_t)xorshift32(&seed);
        }

        size_t out = pu_dap_process_packet(req, req_len, resp, resp_cap, (uint64_t)i * 100u);
        assert(out <= resp_cap);
        assert(out <= PU_DAP_PACKET_SIZE);
        if (resp_cap == 0u) {
            assert(out == 0u);
        }

        free(resp);
        free(req);
    }
}

int main(void) {
    test_dap_info_and_basic_commands();
    test_dap_guard_snapshot_survives_buffer_reuse();
    test_dap_cross_interface_contention_and_deadline_renewal();
    test_dap_swj_pins_handoff_and_bounded_wait();
    test_dap_clock_64bit_math();
    test_dap_bounds_jtag_and_batch_guards();
    test_50000_fuzzed_packets();
    puts("test_dap_guard_fuzz: ALL PASSED (incl. 50,000 fuzzed packets)");
    return 0;
}

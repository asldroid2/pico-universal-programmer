#include "firmware/engine_owner.h"

#include <stddef.h>
#include <string.h>

#if !defined(PU_HOST_TEST) && (defined(__linux__) || defined(_WIN32) || defined(__APPLE__))
#define PU_HOST_TEST 1
#endif

#if !defined(PU_HOST_TEST)
#if defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wundef"
#endif
#include "hardware/sync.h"
#if defined(__GNUC__)
#pragma GCC diagnostic pop
#endif
#ifndef PU_ENGINE_SPINLOCK_ID
#define PU_ENGINE_SPINLOCK_ID PICO_SPINLOCK_ID_STRIPED_FIRST
#endif
#endif

static pu_pin_hal_t s_hal;
static pu_engine_state_t s_state = PU_ENGINE_IDLE;
static uint64_t s_deadline_us = 0u;
static uint32_t s_fault_mask = 0u;
static uint32_t s_epoch = 0u;
static uint32_t s_hal_inflight = 0u;

static inline uint32_t engine_lock(void) {
#if !defined(PU_HOST_TEST)
    return spin_lock_blocking(spin_lock_instance(PU_ENGINE_SPINLOCK_ID));
#else
    return 0u;
#endif
}

static inline void engine_unlock(uint32_t saved_irq) {
#if !defined(PU_HOST_TEST)
    spin_unlock(spin_lock_instance(PU_ENGINE_SPINLOCK_ID), saved_irq);
#else
    (void)saved_irq;
#endif
}

static bool is_acquirable_engine(pu_engine_state_t state) {
    switch (state) {
    case PU_ENGINE_SWD:
    case PU_ENGINE_JTAG:
    case PU_ENGINE_SWIO:
    case PU_ENGINE_RECOVERY:
        return true;
    case PU_ENGINE_IDLE:
    case PU_ENGINE_FAULT:
    default:
        return false;
    }
}

/*
 * Wrap-safe monotonic deadline comparison equivalent to two's-complement
 * (int64_t)(now_us - deadline_us) >= 0 without implementation-defined
 * unsigned-to-signed conversion when bit 63 is set.
 */
static bool is_deadline_expired(uint64_t now_us, uint64_t deadline_us) {
    return ((now_us - deadline_us) & (UINT64_C(1) << 63)) == 0u;
}

static void run_teardown_callbacks(const pu_pin_hal_t *hal, bool cut_vtarg_power) {
    if (hal->drain_pio != NULL) {
        hal->drain_pio();
    }
    if (hal->tristate_debug_pins != NULL) {
        hal->tristate_debug_pins();
    }
    if (hal->set_swio_pullup != NULL) {
        hal->set_swio_pullup(false);
    }
    if (cut_vtarg_power && hal->set_vtarg_power != NULL) {
        hal->set_vtarg_power(false);
    }
}

void pu_engine_init(const pu_pin_hal_t *hal) {
    uint32_t irq_state = engine_lock();
    if (hal != NULL) {
        s_hal = *hal;
    } else {
        memset(&s_hal, 0, sizeof(s_hal));
    }
    s_state = PU_ENGINE_IDLE;
    s_deadline_us = 0u;
    s_fault_mask = 0u;
    ++s_epoch;
    s_hal_inflight = 0u;
    engine_unlock(irq_state);
}

pu_status_t pu_engine_acquire(pu_engine_state_t target, uint64_t now_us, uint32_t timeout_us) {
    if (!is_acquirable_engine(target)) {
        return PU_ERR_INVALID_ARG;
    }

    uint32_t irq_state = engine_lock();
    if (s_state == PU_ENGINE_FAULT) {
        engine_unlock(irq_state);
        return PU_ERR_FAULT_LATCHED;
    }
    if (s_state != PU_ENGINE_IDLE || s_hal_inflight != 0u) {
        engine_unlock(irq_state);
        return PU_ERR_ENGINE_BUSY;
    }

    s_state = target;
    s_deadline_us = now_us + (uint64_t)timeout_us;
    uint32_t acquire_epoch = ++s_epoch;
    pu_pin_hal_t hal = s_hal;
    bool enable_swio_pu = (target == PU_ENGINE_SWIO && hal.set_swio_pullup != NULL);
    if (enable_swio_pu) {
        ++s_hal_inflight;
    }
    engine_unlock(irq_state);

    if (enable_swio_pu) {
        hal.set_swio_pullup(true);

        /* Re-check epoch in case a fault IRQ or USB reset preempted pull-up activation. */
        irq_state = engine_lock();
        bool preempted = (s_epoch != acquire_epoch);
        bool faulted = (s_state == PU_ENGINE_FAULT);
        if (!preempted && s_hal_inflight > 0u) {
            --s_hal_inflight;
        }
        engine_unlock(irq_state);

        if (preempted) {
            if (hal.tristate_debug_pins != NULL) {
                hal.tristate_debug_pins();
            }
            hal.set_swio_pullup(false);

            irq_state = engine_lock();
            if (s_hal_inflight > 0u) {
                --s_hal_inflight;
            }
            faulted = (s_state == PU_ENGINE_FAULT);
            engine_unlock(irq_state);

            if (faulted) {
                return PU_ERR_FAULT_LATCHED;
            }
        }
    }

    return PU_OK;
}

pu_status_t pu_engine_renew_deadline(pu_engine_state_t expected_owner,
                                     uint64_t now_us,
                                     uint32_t timeout_us) {
    if (!is_acquirable_engine(expected_owner)) {
        return PU_ERR_INVALID_ARG;
    }

    uint32_t irq_state = engine_lock();
    if (s_state == PU_ENGINE_FAULT) {
        engine_unlock(irq_state);
        return PU_ERR_FAULT_LATCHED;
    }
    if (s_state != expected_owner) {
        engine_unlock(irq_state);
        return PU_ERR_NOT_OWNER;
    }

    s_deadline_us = now_us + (uint64_t)timeout_us;
    engine_unlock(irq_state);
    return PU_OK;
}

pu_status_t pu_engine_release(pu_engine_state_t expected_owner) {
    if (!is_acquirable_engine(expected_owner)) {
        return PU_ERR_INVALID_ARG;
    }

    uint32_t irq_state = engine_lock();
    if (s_state != expected_owner) {
        engine_unlock(irq_state);
        return PU_ERR_NOT_OWNER;
    }

    s_state = PU_ENGINE_IDLE;
    s_deadline_us = 0u;
    ++s_epoch;
    ++s_hal_inflight;
    pu_pin_hal_t hal = s_hal;
    engine_unlock(irq_state);

    run_teardown_callbacks(&hal, false);

    irq_state = engine_lock();
    if (s_hal_inflight > 0u) {
        --s_hal_inflight;
    }
    engine_unlock(irq_state);
    return PU_OK;
}

void pu_engine_tick(uint64_t now_us) {
    uint32_t irq_state = engine_lock();
    if (!is_acquirable_engine(s_state) || !is_deadline_expired(now_us, s_deadline_us)) {
        engine_unlock(irq_state);
        return;
    }

    s_state = PU_ENGINE_IDLE;
    s_deadline_us = 0u;
    ++s_epoch;
    ++s_hal_inflight;
    pu_pin_hal_t hal = s_hal;
    engine_unlock(irq_state);

    run_teardown_callbacks(&hal, false);

    irq_state = engine_lock();
    if (s_hal_inflight > 0u) {
        --s_hal_inflight;
    }
    engine_unlock(irq_state);
}

void pu_engine_on_usb_reset(void) {
    uint32_t irq_state = engine_lock();
    if (!is_acquirable_engine(s_state)) {
        engine_unlock(irq_state);
        return;
    }

    s_state = PU_ENGINE_IDLE;
    s_deadline_us = 0u;
    ++s_epoch;
    ++s_hal_inflight;
    pu_pin_hal_t hal = s_hal;
    engine_unlock(irq_state);

    run_teardown_callbacks(&hal, false);

    irq_state = engine_lock();
    if (s_hal_inflight > 0u) {
        --s_hal_inflight;
    }
    engine_unlock(irq_state);
}

void pu_engine_latch_fault(uint32_t fault_mask) {
    if (fault_mask == 0u) {
        return;
    }

    uint32_t irq_state = engine_lock();
    s_state = PU_ENGINE_FAULT;
    s_deadline_us = 0u;
    s_fault_mask |= fault_mask;
    ++s_epoch;
    ++s_hal_inflight;
    pu_pin_hal_t hal = s_hal;
    engine_unlock(irq_state);

    run_teardown_callbacks(&hal, true);

    irq_state = engine_lock();
    if (s_hal_inflight > 0u) {
        --s_hal_inflight;
    }
    engine_unlock(irq_state);
}

uint32_t pu_engine_fault_mask(void) {
    uint32_t irq_state = engine_lock();
    uint32_t mask = s_fault_mask;
    engine_unlock(irq_state);
    return mask;
}

pu_status_t pu_engine_clear_fault(void) {
    uint32_t irq_state = engine_lock();
    if (s_hal_inflight != 0u || is_acquirable_engine(s_state)) {
        engine_unlock(irq_state);
        return PU_ERR_ENGINE_BUSY;
    }

    s_fault_mask = 0u;
    s_state = PU_ENGINE_IDLE;
    s_deadline_us = 0u;
    ++s_epoch;
    engine_unlock(irq_state);
    return PU_OK;
}

pu_engine_state_t pu_engine_current(void) {
    uint32_t irq_state = engine_lock();
    pu_engine_state_t current = s_state;
    engine_unlock(irq_state);
    return current;
}

// SPDX-License-Identifier: GPL-2.0-only
// sched_yield(2) releases the single guest CPU.
//
// A parent thread spins on a flag until a child thread sets it, calling
// sched_yield each iteration. Before yieldThread(), the syscall returned 0
// without leaving uc_emu_start, so the parent held the execution lock forever
// and the child never ran. The 2 s call budget turns that regression into a
// Timeout instead of a hung test.

#include <array>
#include <cstdint>

#include "runtime/instance/runtime_instance.hpp"
#include "runtime/memory/region.hpp"
#include "support/blob_loader.hpp"
#include "support/test_harness.hpp"

using namespace duckemu;
using namespace duckemu::runtime;

int main() {
    RuntimeConfig config;
    config.default_timeout_us = 2 * 1000 * 1000; // 2 s backstop

    auto instance = RuntimeInstance::create(config);
    CHECK_RESULT(instance);
    if (!instance.ok()) {
        return test::finish("09_sched_yield");
    }

    auto blob = test::loadBlob("09_yield.bin");
    CHECK_RESULT(blob);
    if (!blob.ok()) {
        return test::finish("09_sched_yield");
    }

    auto code = instance.value()->mapMemory(blob.value().size(),
                                            PermRead | PermExec,
                                            "yield-blob");
    auto data = instance.value()->mapMemory(0x1000, PermRead | PermWrite, "yield-data");
    auto stack = instance.value()->mapMemory(0x4000, PermRead | PermWrite, "yield-stack");
    CHECK_RESULT(code);
    CHECK_RESULT(data);
    CHECK_RESULT(stack);
    if (!code.ok() || !data.ok() || !stack.ok()) {
        return test::finish("09_sched_yield");
    }

    auto written = instance.value()->writeMemory(code.value(), blob.value().data(),
                                                 blob.value().size());
    CHECK_RESULT(written);
    if (!written.ok()) {
        return test::finish("09_sched_yield");
    }

    const std::array<uint64_t, 8> args = {
        data.value().value(),
        (stack.value() + 0x4000).value(),
    };
    auto call = instance.value()->callFunction(code.value(), args);
    CHECK_RESULT(call);
    if (call.ok()) {
        CHECK(call.value().exit_code.has_value());
        CHECK_EQ(call.value().exit_code.value_or(-1), 0);
    }

    uint32_t flag = 0;
    auto read = instance.value()->readMemory(data.value(), &flag, sizeof(flag));
    CHECK_RESULT(read);
    CHECK_EQ(flag, 1);

    return test::finish("09_sched_yield");
}

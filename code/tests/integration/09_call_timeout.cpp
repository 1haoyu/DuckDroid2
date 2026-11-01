// SPDX-License-Identifier: GPL-2.0-only
// RuntimeConfig::default_timeout_us is a real budget, not a dead field.
//
// The guest blob is `b .`; the host call must come back with Timeout, and a
// timed-out instance must refuse further calls (it is left Faulted, the same
// terminal state as a fault or exit_group).

#include <chrono>

#include "runtime/instance/runtime_instance.hpp"
#include "runtime/memory/region.hpp"
#include "support/blob_loader.hpp"
#include "support/test_harness.hpp"

using namespace duckemu;
using namespace duckemu::runtime;

int main() {
    RuntimeConfig config;
    config.default_timeout_us = 200 * 1000; // 200 ms

    auto instance = RuntimeInstance::create(config);
    CHECK_RESULT(instance);
    if (!instance.ok()) {
        return test::finish("09_call_timeout");
    }

    auto blob = test::loadBlob("09_timeout.bin");
    CHECK_RESULT(blob);
    if (!blob.ok()) {
        return test::finish("09_call_timeout");
    }

    auto code = instance.value()->mapMemory(blob.value().size(),
                                            PermRead | PermExec,
                                            "timeout-blob");
    CHECK_RESULT(code);
    if (!code.ok()) {
        return test::finish("09_call_timeout");
    }

    auto written = instance.value()->writeMemory(code.value(), blob.value().data(),
                                                 blob.value().size());
    CHECK_RESULT(written);
    if (!written.ok()) {
        return test::finish("09_call_timeout");
    }

    const auto started = std::chrono::steady_clock::now();
    auto call = instance.value()->callFunction(code.value());
    const auto elapsed = std::chrono::steady_clock::now() - started;

    CHECK(!call.ok());
    if (!call.ok()) {
        CHECK(call.error().code == ErrorCode::Timeout);
    }
    // The call must end near the budget, not at the ctest backstop.
    CHECK(elapsed < std::chrono::seconds(10));

    auto again = instance.value()->callFunction(code.value());
    CHECK(!again.ok());
    if (!again.ok()) {
        CHECK(again.error().code == ErrorCode::InvalidArgument);
    }

    return test::finish("09_call_timeout");
}

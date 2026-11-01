// SPDX-License-Identifier: GPL-2.0-only
// M1 gate: a bare native blob runs to completion.
//
// Exercises the non-blocking SVC path (getpid/gettid/mmap/mprotect/munmap/
// write), a host stub through the thunk page, and exit_group.
//
// M2 gate: the same run produces a complete svc trace, semantic memory events,
// and the opt-in diagnostic memory-access feed.

#include <array>
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "runtime/instance/runtime_instance.hpp"
#include "runtime/memory/region.hpp"
#include "runtime/observer/event_bus.hpp"
#include "runtime/observer/trace/svc_trace.hpp"
#include "support/blob_loader.hpp"
#include "support/test_harness.hpp"
#include "support/trace_path.hpp"

using namespace duckemu;
using namespace duckemu::runtime;

namespace {

constexpr uint32_t kPid = 1000;
constexpr uint32_t kTid = 1;

struct NativeOutput {
    uint64_t pid;
    uint64_t tid;
    uint64_t mmap_address;
    uint64_t loaded;
    uint64_t mprotect_return;
    uint64_t host_return;
    uint64_t write_return;
    uint64_t munmap_return;
};
static_assert(sizeof(NativeOutput) == 64, "guest writes 64 bytes");

Result<GuestVA> loadBlobInto(RuntimeInstance& guest,
                             const std::vector<uint8_t>& blob,
                             std::string_view name) {
    auto code = guest.mapMemory(blob.size(), PermRead | PermExec, name);
    if (!code.ok()) {
        return code.error();
    }
    auto written = guest.writeMemory(code.value(), blob.data(), blob.size());
    if (!written.ok()) {
        return written.error();
    }
    return code.value();
}

Result<std::vector<observer::SvcEvent>> readTrace(const std::string& path) {
    std::ifstream input(path);
    if (!input) {
        return Error{ ErrorCode::NotFound, "cannot read " + path };
    }
    std::vector<observer::SvcEvent> records;
    std::string line;
    while (std::getline(input, line)) {
        if (line.empty()) {
            continue;
        }
        auto record = observer::parseSvcTraceLine(line);
        if (!record.has_value()) {
            return Error{ ErrorCode::Internal, "unparseable trace line: " + line };
        }
        records.push_back(std::move(record).value());
    }
    return records;
}

void printTrace(const std::vector<observer::SvcEvent>& records) {
    std::printf("  svc.log (%zu record(s)):\n", records.size());
    for (const auto& record : records) {
        std::printf("    %s\n", observer::formatSvcTraceLine(record).c_str());
    }
}

void checkSvcTrace(const std::vector<observer::SvcEvent>& records, const NativeOutput& output) {
    printTrace(records);

    CHECK_EQ(records.size(), 8);
    if (records.size() != 8) {
        return;
    }

    const char* expected_names[8] = {
        "getpid", "gettid", "mmap", "mprotect", "host_add", "write", "munmap", "exit_group",
    };
    for (size_t i = 0; i < records.size(); ++i) {
        CHECK_EQ(records[i].id, i);
        CHECK_EQ(records[i].seq, i);
        CHECK(records[i].name == expected_names[i]);
        CHECK_EQ(records[i].tid, kTid);
        CHECK(records[i].support == observer::SvcSupport::Supported);
        CHECK(records[i].stack.empty());
        CHECK_EQ(records[i].svc_address % 4, 0);
    }

    CHECK(records[0].kind == observer::SvcKind::Syscall);
    CHECK(records[4].kind == observer::SvcKind::HostStub);

    CHECK_EQ(records[0].result, kPid);
    CHECK_EQ(records[1].result, kTid);
    CHECK_EQ(records[2].result, output.mmap_address);
    CHECK_EQ(records[3].result, 0);
    CHECK_EQ(records[4].result, kPid + kTid);
    CHECK_EQ(records[5].result, 3);
    CHECK_EQ(records[6].result, 0);
    CHECK_EQ(records[7].result, 0);

    // mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0)
    CHECK_EQ(records[2].args[0], 0);
    CHECK_EQ(records[2].args[1], 4096);
    CHECK_EQ(records[2].args[2], 3);
    CHECK_EQ(records[2].args[3], 0x22);
    CHECK_EQ(records[2].args[4], UINT64_MAX);
    CHECK_EQ(records[2].args[5], 0);

    // host_add(pid, tid)
    CHECK_EQ(records[4].args[0], kPid);
    CHECK_EQ(records[4].args[1], kTid);
}

void checkMemoryEvents(const std::vector<observer::MemoryEvent>& events, const NativeOutput& output) {
    size_t maps = 0;
    size_t protects = 0;
    size_t unmaps = 0;
    bool mapped_guest = false;
    bool protected_guest = false;
    bool unmapped_guest = false;

    for (const auto& event : events) {
        switch (event.op) {
        case observer::MemoryOp::Map:
            ++maps;
            if (event.name == "guest-mmap" && event.address == output.mmap_address &&
                event.size == 4096 && event.perms == PermReadWrite) {
                mapped_guest = true;
            }
            break;
        case observer::MemoryOp::Protect:
            ++protects;
            if (event.address == output.mmap_address && event.size == 4096 &&
                event.perms == PermRead) {
                protected_guest = true;
            }
            break;
        case observer::MemoryOp::Unmap:
            ++unmaps;
            if (event.address == output.mmap_address && event.size == 4096) {
                unmapped_guest = true;
            }
            break;
        case observer::MemoryOp::Brk:
            break;
        }
    }

    std::printf("  memory events: %zu (map=%zu protect=%zu unmap=%zu)\n", events.size(), maps,
                protects, unmaps);
    CHECK(mapped_guest);
    CHECK(protected_guest);
    CHECK(unmapped_guest);
}

void checkDiagnostics(const std::vector<observer::DiagnosticEvent>& events,
                      const NativeOutput& output,
                      uint64_t dropped) {
    std::printf("  diagnostic events: %zu (dropped=%llu)\n", events.size(),
                static_cast<unsigned long long>(dropped));
    CHECK(!events.empty());
    CHECK_EQ(dropped, 0);

    bool saw_write = false;
    bool saw_read = false;
    for (const auto& event : events) {
        if (event.address != output.mmap_address || event.size != 4) {
            continue;
        }
        if (event.kind == observer::DiagnosticKind::MemoryWrite && event.value == 0x1234) {
            saw_write = true;
        }
        if (event.kind == observer::DiagnosticKind::MemoryRead) {
            saw_read = true;
        }
    }
    CHECK(saw_write);
    CHECK(saw_read);
}

// A listener must not start the engine: it runs inside a delivery window, and
// a nested uc_emu_start on the same engine clobbers the outer register set
// (M0 probe 6). Uses the memory channel because a memory event can be
// published while the instance is Ready -- on the svc path the "not Ready"
// state check would already refuse the nested call, which is a different
// mechanism. Uses its own instance so the gate's svc.log stays exactly the
// eight records asserted above.
void checkReentrancyGuard(const std::vector<uint8_t>& blob) {
    RuntimeConfig config;
    config.pid = kPid;
    config.tid = kTid;

    auto instance = RuntimeInstance::create(config);
    CHECK_RESULT(instance);
    if (!instance.ok()) {
        return;
    }
    RuntimeInstance& guest = *instance.value();

    auto thunk = guest.registerHostFunction(
        "host_add", [](HostCallArgs& args) -> int64_t {
            return static_cast<int64_t>(args.x[0] + args.x[1]);
        });
    auto code = loadBlobInto(guest, blob, "reentry-code");
    auto out = guest.mapMemory(0x100, PermReadWrite, "reentry-out");
    CHECK_RESULT(thunk);
    CHECK_RESULT(code);
    CHECK_RESULT(out);
    if (!thunk.ok() || !code.ok() || !out.ok()) {
        return;
    }

    std::array<uint64_t, 8> args{};
    args[0] = out.value().value();
    args[1] = thunk.value().value();

    bool listener_ran = false;
    bool nested_call_refused = false;
    const uint32_t listener_id = guest.addMemoryListener([&](const observer::MemoryEvent&) {
        if (listener_ran) {
            return;
        }
        listener_ran = true;
        auto nested = guest.callFunction(code.value(), args);
        nested_call_refused = !nested.ok();
    });

    auto extra = guest.mapMemory(0x100, PermReadWrite, "reentry-probe");
    CHECK_RESULT(extra);
    CHECK(listener_ran);
    CHECK(nested_call_refused);
    CHECK(guest.removeMemoryListener(listener_id));
}

void runPureNative() {
    auto blob = test::loadBlob("02_pure_native.bin");
    CHECK_RESULT(blob);
    auto exit_blob = test::loadBlob("02_exit_group.bin");
    CHECK_RESULT(exit_blob);
    if (!blob.ok() || !exit_blob.ok()) {
        return;
    }

    RuntimeConfig config;
    config.pid = kPid;
    config.tid = kTid;
    config.trace_path = test::tracePath("02_pure_native.svc.log");
    config.record_memory_access = true;
    config.diagnostic_capacity = 1u << 16;

    auto instance = RuntimeInstance::create(config);
    CHECK_RESULT(instance);
    if (!instance.ok()) {
        return;
    }
    RuntimeInstance& guest = *instance.value();

    std::vector<observer::MemoryEvent> memory_events;
    guest.addMemoryListener([&memory_events](const observer::MemoryEvent& event) {
        memory_events.push_back(event);
    });

    auto thunk = guest.registerHostFunction(
        "host_add", [](HostCallArgs& args) -> int64_t {
            return static_cast<int64_t>(args.x[0] + args.x[1]);
        });
    CHECK_RESULT(thunk);
    if (!thunk.ok()) {
        return;
    }

    auto code = loadBlobInto(guest, blob.value(), "code-native");
    CHECK_RESULT(code);
    auto exit_code_blob = loadBlobInto(guest, exit_blob.value(), "code-exit");
    CHECK_RESULT(exit_code_blob);
    if (!code.ok() || !exit_code_blob.ok()) {
        return;
    }

    auto out = guest.mapMemory(0x100, PermReadWrite, "native-out");
    CHECK_RESULT(out);
    if (!out.ok()) {
        return;
    }

    std::array<uint64_t, 8> args{};
    args[0] = out.value().value();
    args[1] = thunk.value().value();

    auto call = guest.callFunction(code.value(), args);
    CHECK_RESULT(call);
    if (!call.ok()) {
        return;
    }
    CHECK(!call.value().exit_code.has_value());

    NativeOutput output{};
    CHECK_RESULT(guest.readMemory(out.value(), &output, sizeof(output)));

    std::printf(
        "  pid=%llu tid=%llu mmap=0x%llx loaded=0x%llx mprotect=%llu "
        "host=%llu write=%llu munmap=%llu\n",
        static_cast<unsigned long long>(output.pid),
        static_cast<unsigned long long>(output.tid),
        static_cast<unsigned long long>(output.mmap_address),
        static_cast<unsigned long long>(output.loaded),
        static_cast<unsigned long long>(output.mprotect_return),
        static_cast<unsigned long long>(output.host_return),
        static_cast<unsigned long long>(output.write_return),
        static_cast<unsigned long long>(output.munmap_return));

    CHECK_EQ(output.pid, kPid);
    CHECK_EQ(output.tid, kTid);
    CHECK(output.mmap_address != 0);
    CHECK_EQ(output.mmap_address % kGuestPageSize, 0);
    CHECK_EQ(output.loaded, 0x1234);
    CHECK_EQ(output.mprotect_return, 0);
    CHECK_EQ(output.host_return, kPid + kTid);
    CHECK_EQ(output.write_return, 3);
    CHECK_EQ(output.munmap_return, 0);

    const uint64_t expected = output.loaded + output.host_return +
                              output.write_return + output.munmap_return +
                              output.mprotect_return;
    CHECK_EQ(call.value().return_value, expected);
    CHECK_EQ(expected, 0x1234 + kPid + kTid + 3);

    auto exit_call = guest.callFunction(exit_code_blob.value());
    CHECK_RESULT(exit_call);
    if (!exit_call.ok()) {
        return;
    }
    CHECK(exit_call.value().exit_code.has_value());
    if (exit_call.value().exit_code.has_value()) {
        CHECK_EQ(*exit_call.value().exit_code, 7);
    }

    // --- M2 observation gates -------------------------------------------

    auto trace = readTrace(config.trace_path);
    CHECK_RESULT(trace);
    if (trace.ok()) {
        std::printf("  trace file: %s\n", config.trace_path.c_str());
        checkSvcTrace(trace.value(), output);
    }

    checkMemoryEvents(memory_events, output);

    std::vector<observer::DiagnosticEvent> diagnostics;
    (void)guest.drainDiagnostics(diagnostics);
    checkDiagnostics(diagnostics, output, guest.droppedDiagnostics());

    checkReentrancyGuard(blob.value());
}

} // namespace

int main() {
    runPureNative();
    return test::finish("02_pure_native");
}

// SPDX-License-Identifier: GPL-2.0-only
// M2 gate: an unimplemented syscall dumps the guest frame chain (LR chain).
//
// The blob builds three nested frame records and calls io_setup (syscall 0),
// which DuckEmu does not implement. The dump must therefore show:
//   frame 0 = the `svc` instruction
//   frame 1 = the return address stored by level2's caller (level1)
//   frame 2 = the return address stored by level1's caller (_start)
//   frame 3 = the host return trap
// The blob also writes the two return addresses into its output buffer, so the
// test compares the dump against values the guest actually computed instead of
// against constants baked into the test.

#include <array>
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <string>
#include <utility>
#include <vector>

#include "runtime/instance/runtime_instance.hpp"
#include "runtime/memory/region.hpp"
#include "runtime/observer/trace/svc_trace.hpp"
#include "runtime/svc/syscall_numbers.hpp"
#include "support/blob_loader.hpp"
#include "support/test_harness.hpp"
#include "support/trace_path.hpp"

using namespace duckemu;
using namespace duckemu::runtime;

namespace {

constexpr uint32_t kPid = 1000;
constexpr uint32_t kTid = 1;

struct DumpOutput {
    uint64_t reserved;
    uint64_t level1_return;
    uint64_t start_return;
    uint64_t errno_value;
};
static_assert(sizeof(DumpOutput) == 32, "guest writes 32 bytes");

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

void runStackDump() {
    auto blob = test::loadBlob("02_stack_dump.bin");
    CHECK_RESULT(blob);
    if (!blob.ok()) {
        return;
    }

    RuntimeConfig config;
    config.pid = kPid;
    config.tid = kTid;
    config.trace_path = test::tracePath("02_stack_dump.svc.log");

    auto instance = RuntimeInstance::create(config);
    CHECK_RESULT(instance);
    if (!instance.ok()) {
        return;
    }
    RuntimeInstance& guest = *instance.value();

    auto code = guest.mapMemory(blob.value().size(), PermRead | PermExec, "stack-dump-code");
    CHECK_RESULT(code);
    auto out = guest.mapMemory(0x100, PermReadWrite, "stack-dump-out");
    CHECK_RESULT(out);
    if (!code.ok() || !out.ok()) {
        return;
    }
    CHECK_RESULT(guest.writeMemory(code.value(), blob.value().data(), blob.value().size()));

    std::array<uint64_t, 8> args{};
    args[0] = out.value().value();

    auto call = guest.callFunction(code.value(), args);
    CHECK_RESULT(call);
    if (!call.ok()) {
        return;
    }
    CHECK(!call.value().exit_code.has_value());

    DumpOutput output{};
    CHECK_RESULT(guest.readMemory(out.value(), &output, sizeof(output)));

    const uint64_t enosys = static_cast<uint64_t>(svc::kError(svc::kEnosys));
    CHECK_EQ(output.errno_value, enosys);
    CHECK(output.level1_return != 0);
    CHECK(output.start_return != 0);

    auto trace = readTrace(config.trace_path);
    CHECK_RESULT(trace);
    if (!trace.ok()) {
        return;
    }
    const auto& records = trace.value();

    std::printf("  svc.log (%zu record(s)):\n", records.size());
    for (const auto& record : records) {
        std::printf("    %s\n", observer::formatSvcTraceLine(record).c_str());
    }
    CHECK_EQ(records.size(), 1);
    if (records.empty()) {
        return;
    }

    const observer::SvcEvent& record = records.front();
    CHECK_EQ(record.id, 0);
    CHECK_EQ(record.seq, 0);
    CHECK(record.kind == observer::SvcKind::Syscall);
    CHECK(record.name == "io_setup");
    CHECK_EQ(record.tid, kTid);
    CHECK(record.support == observer::SvcSupport::Unsupported);
    CHECK_EQ(record.result, enosys);
    CHECK(record.stack_stop == "fp=0");

    std::printf("  guest stack dump (%zu frames, walk stopped: %s):\n", record.stack.size(),
                record.stack_stop.c_str());
    for (const auto& frame : record.stack) {
        std::printf("    0x%llx  %s\n", static_cast<unsigned long long>(frame.pc),
                    frame.name.c_str());
    }

    CHECK_EQ(record.stack.size(), 4);
    if (record.stack.size() == 4) {
        CHECK_EQ(record.stack[0].pc, record.svc_address);
        CHECK_EQ(record.stack[1].pc, output.level1_return);
        CHECK_EQ(record.stack[2].pc, output.start_return);
        CHECK(record.stack[3].name == "return-trap!0x0");
    }
}

} // namespace

int main() {
    runStackDump();
    return test::finish("02_stack_dump");
}

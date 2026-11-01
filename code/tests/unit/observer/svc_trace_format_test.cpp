// SPDX-License-Identifier: GPL-2.0-only
#include <cstdint>
#include <string>

#include "runtime/observer/trace/svc_trace.hpp"
#include "support/test_harness.hpp"

using namespace duckemu;
using duckemu::runtime::observer::formatSvcTraceLine;
using duckemu::runtime::observer::GuestFrame;
using duckemu::runtime::observer::parseSvcTraceLine;
using duckemu::runtime::observer::SvcEvent;
using duckemu::runtime::observer::SvcKind;
using duckemu::runtime::observer::SvcSupport;

namespace {

SvcEvent makeSyscallEvent() {
    SvcEvent event;
    event.id = 5;
    event.seq = 4;
    event.tid = 1;
    event.svc_address = 0x4010020c;
    event.kind = SvcKind::Syscall;
    event.number = 222;
    event.name = "mmap";
    event.args = { 0, 4096, 3, 0x22, UINT64_MAX, 0 };
    event.result = 0x40018000;
    return event;
}

void testGoldenLine() {
    const std::string line = formatSvcTraceLine(makeSyscallEvent());
    const std::string expected =
        "5\t4\t0x1\t0x4010020c\tsys\tmmap\t"
        "[\"0x0\",\"0x1000\",\"0x3\",\"0x22\",\"0xffffffffffffffff\",\"0x0\"]\t"
        "0x40018000\t{}";
    CHECK(line == expected);
}

void testSupportedRoundTrip() {
    const SvcEvent original = makeSyscallEvent();
    const auto parsed = parseSvcTraceLine(formatSvcTraceLine(original));
    CHECK(parsed.has_value());
    if (!parsed.has_value()) {
        return;
    }
    CHECK_EQ(parsed->id, original.id);
    CHECK_EQ(parsed->seq, original.seq);
    CHECK_EQ(parsed->tid, original.tid);
    CHECK_EQ(parsed->svc_address, original.svc_address);
    CHECK(parsed->kind == original.kind);
    CHECK(parsed->name == original.name);
    CHECK_EQ(parsed->result, original.result);
    CHECK(parsed->support == SvcSupport::Supported);
    CHECK(parsed->stack.empty());
    CHECK(parsed->stack_stop.empty());
    for (size_t i = 0; i < original.args.size(); ++i) {
        CHECK_EQ(parsed->args[i], original.args[i]);
    }
}

void testUnsupportedRoundTrip() {
    SvcEvent original = makeSyscallEvent();
    original.kind = SvcKind::HostStub;
    original.name = "host_add";
    original.support = SvcSupport::Unsupported;
    original.result = static_cast<uint64_t>(static_cast<int64_t>(-38));
    original.stack.push_back(GuestFrame{ 0x4010020c, "code-native!0x20c" });
    original.stack.push_back(GuestFrame{ 0x40100310, "return-trap!0x0" });
    original.stack_stop = "fp=0";

    const std::string line = formatSvcTraceLine(original);
    const std::string expected_note =
        "{\"unsupported\":1,\"stop\":\"fp=0\",\"stack\":["
        "{\"pc\":\"0x4010020c\",\"name\":\"code-native!0x20c\"},"
        "{\"pc\":\"0x40100310\",\"name\":\"return-trap!0x0\"}]}";
    CHECK(line.size() > expected_note.size());
    CHECK(line.compare(line.size() - expected_note.size(), expected_note.size(), expected_note) == 0);

    const auto parsed = parseSvcTraceLine(line);
    CHECK(parsed.has_value());
    if (!parsed.has_value()) {
        return;
    }
    CHECK(parsed->support == SvcSupport::Unsupported);
    CHECK(parsed->kind == SvcKind::HostStub);
    CHECK(parsed->name == "host_add");
    CHECK_EQ(parsed->result, original.result);
    CHECK(parsed->stack_stop == "fp=0");
    CHECK_EQ(parsed->stack.size(), 2);
    if (parsed->stack.size() == 2) {
        CHECK_EQ(parsed->stack[0].pc, 0x4010020c);
        CHECK(parsed->stack[0].name == "code-native!0x20c");
        CHECK_EQ(parsed->stack[1].pc, 0x40100310);
        CHECK(parsed->stack[1].name == "return-trap!0x0");
    }
}

void testDegradedRoundTrip() {
    SvcEvent original = makeSyscallEvent();
    original.name = "clone";
    original.support = SvcSupport::Degraded;
    original.degraded_reason = "clone without CLONE_VM|CLONE_THREAD";
    original.result = static_cast<uint64_t>(static_cast<int64_t>(-22));

    const std::string line = formatSvcTraceLine(original);
    const std::string expected_note =
        "{\"degraded\":1,\"reason\":\"clone without CLONE_VM|CLONE_THREAD\"}";
    CHECK(line.size() > expected_note.size());
    CHECK(line.compare(line.size() - expected_note.size(), expected_note.size(), expected_note) == 0);

    const auto parsed = parseSvcTraceLine(line);
    CHECK(parsed.has_value());
    if (!parsed.has_value()) {
        return;
    }
    CHECK(parsed->support == SvcSupport::Degraded);
    CHECK(parsed->degraded_reason == original.degraded_reason);
    CHECK(parsed->stack.empty());
    CHECK(parsed->stack_stop.empty());

    // A degraded call without a reason keeps the note minimal.
    SvcEvent bare = original;
    bare.degraded_reason.clear();
    const auto bare_parsed = parseSvcTraceLine(formatSvcTraceLine(bare));
    CHECK(bare_parsed.has_value());
    if (bare_parsed.has_value()) {
        CHECK(bare_parsed->support == SvcSupport::Degraded);
        CHECK(bare_parsed->degraded_reason.empty());
    }
}

void testEmptyStackUnsupported() {
    SvcEvent original = makeSyscallEvent();
    original.support = SvcSupport::Unsupported;
    original.stack_stop = "cannot read sp/fp";
    const auto parsed = parseSvcTraceLine(formatSvcTraceLine(original));
    CHECK(parsed.has_value());
    if (parsed.has_value()) {
        CHECK(parsed->support == SvcSupport::Unsupported);
        CHECK(parsed->stack.empty());
        CHECK(parsed->stack_stop == "cannot read sp/fp");
    }
}

void testTabInNameIsSanitized() {
    SvcEvent original = makeSyscallEvent();
    original.name = "bad\tname";
    const auto parsed = parseSvcTraceLine(formatSvcTraceLine(original));
    CHECK(parsed.has_value());
    if (parsed.has_value()) {
        CHECK(parsed->name == "bad_name");
    }
}

void testMalformedLines() {
    CHECK(!parseSvcTraceLine("").has_value());
    CHECK(!parseSvcTraceLine("5\t4\t0x1").has_value());
    // Not enough args.
    CHECK(!parseSvcTraceLine("5\t4\t0x1\t0x4010020c\tsys\tmmap\t[\"0x0\"]\t0x40018000\t{}")
               .has_value());
    // Unknown kind.
    CHECK(!parseSvcTraceLine("5\t4\t0x1\t0x4010020c\tbogus\tmmap\t"
                             "[\"0x0\",\"0x0\",\"0x0\",\"0x0\",\"0x0\",\"0x0\"]\t0x0\t{}")
               .has_value());
    // Trailing column.
    CHECK(!parseSvcTraceLine("5\t4\t0x1\t0x4010020c\tsys\tmmap\t"
                             "[\"0x0\",\"0x0\",\"0x0\",\"0x0\",\"0x0\",\"0x0\"]\t0x0\t{}\textra")
               .has_value());
}

} // namespace

int main() {
    testGoldenLine();
    testSupportedRoundTrip();
    testUnsupportedRoundTrip();
    testDegradedRoundTrip();
    testEmptyStackUnsupported();
    testTabInNameIsSanitized();
    testMalformedLines();
    return test::finish("svc_trace_format_test");
}

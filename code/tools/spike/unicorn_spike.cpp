// SPDX-License-Identifier: GPL-2.0-only
// M0 spike: pin down Unicorn 2.1 AArch64 semantics with the raw C API.
//
// Deliberately flat: no runtime/, no abstractions, no helpers beyond what an
// assembly-writing probe needs. Every measurement printed here goes into
// docs/devlogs/2026-10-27-03-M0探针结果.md.
//
// Usage:
//   unicorn_spike all     # run all probes in order
//   unicorn_spike 1..11   # run a single probe
//
// Probes 1-9 are the M0 set. Probes 10-11 are the M8 instruction-trace and
// address-hook pre-work: they pin PC redirect from a code hook, callback
// ordering, and SVC replay across a stop/resume.
//
// Exit code is the number of failed expectations (0 = all probes matched the
// design assumptions).

#include <unicorn/unicorn.h>

#include <atomic>
#include <chrono>
#include <cinttypes>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <thread>
#include <vector>

#include <sys/mman.h>
#include <unistd.h>

namespace {

// ---------------------------------------------------------------------------
// Guest address layout used by every probe
// ---------------------------------------------------------------------------
constexpr uint64_t kPage = 0x1000;
constexpr uint64_t kCode = 0x10000;
constexpr uint64_t kData = 0x20000;
constexpr uint64_t kStack = 0x30000;
constexpr uint64_t kTls = 0x40000;
constexpr uint64_t kShared = 0x50000;
constexpr uint64_t kExtra = 0x60000;

constexpr uint64_t kProbeTimeoutUs = 2000000; // safety net, not under test

// ---------------------------------------------------------------------------
// Reporting
// ---------------------------------------------------------------------------
int g_failures = 0;

void expect(bool ok, const char* what) {
    std::printf("  %-58s %s\n", what, ok ? "PASS" : "FAIL");
    if (!ok) {
        ++g_failures;
    }
}

void expect_u64(const char* what, uint64_t actual, uint64_t expected) {
    std::printf("  %-46s actual=0x%016" PRIx64 " expected=0x%016" PRIx64 "  %s\n",
                what, actual, expected, actual == expected ? "PASS" : "FAIL");
    if (actual != expected) {
        ++g_failures;
    }
}

void show_u64(const char* what, uint64_t value) {
    std::printf("  %-46s 0x%016" PRIx64 "\n", what, value);
}

void show_i64(const char* what, int64_t value) {
    std::printf("  %-46s %" PRId64 "\n", what, value);
}

void show_err(const char* what, uc_err err) {
    std::printf("  %-46s %s (%d)\n", what, uc_strerror(err), static_cast<int>(err));
}

// ---------------------------------------------------------------------------
// Tiny AArch64 encoder (verified against llvm-mc)
//
// Only the instructions the nine probes need are implemented. Branch targets
// are patched by absolute address; every program is built at a known base.
// ---------------------------------------------------------------------------
class Assembler {
public:
    explicit Assembler(uint64_t base) : base_(base) {}

    [[nodiscard]] uint64_t pc() const { return base_ + words_.size() * 4; }
    [[nodiscard]] size_t label() const { return words_.size(); }
    [[nodiscard]] uint64_t addr_of(size_t label) const { return base_ + label * 4; }
    [[nodiscard]] const std::vector<uint32_t>& words() const { return words_; }
    [[nodiscard]] size_t size() const { return words_.size(); }

    Assembler& emit(uint32_t word) {
        words_.push_back(word);
        return *this;
    }

    Assembler& mov(uint32_t rd, uint64_t value) {
        emit(0xD2800000u | (static_cast<uint32_t>(value & 0xFFFFu) << 5) | rd);
        for (uint32_t shift = 16; shift <= 48; shift += 16) {
            const auto part = static_cast<uint32_t>((value >> shift) & 0xFFFFu);
            if (part != 0) {
                emit(0xF2800000u | ((shift / 16) << 21) | (part << 5) | rd);
            }
        }
        return *this;
    }

    Assembler& svc(uint32_t imm) {
        return emit(0xD4000001u | ((imm & 0xFFFFu) << 5));
    }
    Assembler& mrs_tpidr(uint32_t rd) { return emit(0xD53BD040u | rd); }
    Assembler& nop() { return emit(0xD503201Fu); }
    Assembler& br(uint32_t rn) { return emit(0xD61F0000u | (rn << 5)); }

    Assembler& ldr_x(uint32_t rt, uint32_t rn, uint32_t byte_offset = 0) {
        return emit(0xF9400000u | ((byte_offset / 8) << 10) | (rn << 5) | rt);
    }
    Assembler& str_x(uint32_t rt, uint32_t rn, uint32_t byte_offset = 0) {
        return emit(0xF9000000u | ((byte_offset / 8) << 10) | (rn << 5) | rt);
    }
    Assembler& ldr_w(uint32_t rt, uint32_t rn, uint32_t byte_offset = 0) {
        return emit(0xB9400000u | ((byte_offset / 4) << 10) | (rn << 5) | rt);
    }
    Assembler& str_w(uint32_t rt, uint32_t rn, uint32_t byte_offset = 0) {
        return emit(0xB9000000u | ((byte_offset / 4) << 10) | (rn << 5) | rt);
    }
    Assembler& ldrb(uint32_t rt, uint32_t rn, uint32_t byte_offset = 0) {
        return emit(0x39400000u | (byte_offset << 10) | (rn << 5) | rt);
    }
    Assembler& strb(uint32_t rt, uint32_t rn, uint32_t byte_offset = 0) {
        return emit(0x39000000u | (byte_offset << 10) | (rn << 5) | rt);
    }
    Assembler& add_imm(uint32_t rd, uint32_t rn, uint32_t imm) {
        return emit(0x91000000u | ((imm & 0xFFFu) << 10) | (rn << 5) | rd);
    }
    // cmp wN, #imm  ==  subs wzr, wN, #imm
    Assembler& cmp_w_imm(uint32_t rn, uint32_t imm) {
        return emit(0x71000000u | ((imm & 0xFFFu) << 10) | (rn << 5) | 31u);
    }

    size_t b_placeholder() {
        words_.push_back(0x14000000u);
        return words_.size() - 1;
    }
    size_t b_ne_placeholder() {
        words_.push_back(0x54000001u); // b.ne with imm19 = 0
        return words_.size() - 1;
    }
    void patch_branch(size_t index, uint64_t target) {
        const auto delta_bytes =
            static_cast<int64_t>(target) - static_cast<int64_t>(base_ + index * 4);
        const auto delta = static_cast<uint32_t>(delta_bytes / 4);
        const uint32_t word = words_[index];
        if ((word & 0xFC000000u) == 0x14000000u) {
            words_[index] = 0x14000000u | (delta & 0x03FFFFFFu);
        } else {
            words_[index] = (word & 0xFF00001Fu) | ((delta & 0x7FFFFu) << 5);
        }
    }
    Assembler& b(uint64_t target) {
        patch_branch(b_placeholder(), target);
        return *this;
    }
    Assembler& b_ne(uint64_t target) {
        patch_branch(b_ne_placeholder(), target);
        return *this;
    }

private:
    uint64_t base_;
    std::vector<uint32_t> words_;
};

// ---------------------------------------------------------------------------
// Engine helpers
// ---------------------------------------------------------------------------
bool map_region(uc_engine* uc, uint64_t address, uint64_t size, uint32_t perms,
                const char* what) {
    const uc_err err = uc_mem_map(uc, address, size, perms);
    if (err != UC_ERR_OK) {
        std::printf("  map %s failed: %s\n", what, uc_strerror(err));
        ++g_failures;
        return false;
    }
    return true;
}

bool map_basic(uc_engine* uc) {
    if (!map_region(uc, kCode, kPage, UC_PROT_ALL, "code")) {
        return false;
    }
    if (!map_region(uc, kData, kPage, UC_PROT_READ | UC_PROT_WRITE, "data")) {
        return false;
    }
    if (!map_region(uc, kStack, kPage, UC_PROT_READ | UC_PROT_WRITE, "stack")) {
        return false;
    }
    const uint64_t sp = kStack + kPage - 0x10;
    uc_reg_write(uc, UC_ARM64_REG_SP, &sp);
    return true;
}

void load_code(uc_engine* uc, const Assembler& program) {
    const uc_err err = uc_mem_write(uc, program.addr_of(0), program.words().data(),
                                    program.size() * sizeof(uint32_t));
    if (err != UC_ERR_OK) {
        std::printf("  uc_mem_write failed: %s\n", uc_strerror(err));
        ++g_failures;
    }
}

uint64_t read_reg(uc_engine* uc, int reg) {
    uint64_t value = 0;
    uc_reg_read(uc, reg, &value);
    return value;
}

uint64_t read_mem_u64(uc_engine* uc, uint64_t address) {
    uint64_t value = 0;
    uc_mem_read(uc, address, &value, sizeof(value));
    return value;
}

uc_engine* open_engine(const char* owner) {
    uc_engine* uc = nullptr;
    const uc_err err = uc_open(UC_ARCH_ARM64, UC_MODE_ARM, &uc);
    if (err != UC_ERR_OK) {
        std::printf("  [%s] uc_open failed: %s\n", owner, uc_strerror(err));
        ++g_failures;
        return nullptr;
    }
    return uc;
}

// ---------------------------------------------------------------------------
// Probe 1/2/3/4: SVC interception
// ---------------------------------------------------------------------------
struct IntrCtx {
    int hits = 0;
    uint32_t intno = 0;
    uint64_t pc = 0;
    uint64_t x0 = 0;
    uint64_t x5 = 0;
    uint64_t x8 = 0;
    uint64_t sp = 0;
    bool write_x0 = false;
    uint64_t x0_new = 0;
    bool stop = false;
};

void on_intr(uc_engine* uc, uint32_t intno, void* user_data) {
    auto* ctx = static_cast<IntrCtx*>(user_data);
    ++ctx->hits;
    if (ctx->hits != 1) {
        return;
    }
    ctx->intno = intno;
    uc_reg_read(uc, UC_ARM64_REG_PC, &ctx->pc);
    uc_reg_read(uc, UC_ARM64_REG_X0, &ctx->x0);
    uc_reg_read(uc, UC_ARM64_REG_X5, &ctx->x5);
    uc_reg_read(uc, UC_ARM64_REG_X8, &ctx->x8);
    uc_reg_read(uc, UC_ARM64_REG_SP, &ctx->sp);
    if (ctx->write_x0) {
        uc_reg_write(uc, UC_ARM64_REG_X0, &ctx->x0_new);
    }
    if (ctx->stop) {
        uc_emu_stop(uc);
    }
}

bool add_intr_hook(uc_engine* uc, IntrCtx* ctx) {
    uc_hook hook = 0;
    const uc_err err = uc_hook_add(uc, &hook, UC_HOOK_INTR,
                                   reinterpret_cast<void*>(&on_intr), ctx, 1, 0);
    if (err != UC_ERR_OK) {
        std::printf("  uc_hook_add(UC_HOOK_INTR) failed: %s\n", uc_strerror(err));
        ++g_failures;
        return false;
    }
    return true;
}

// Shared body of probes 1-3: mov x8,#98; svc #0; mov x0,#0x1234; b done
struct BasicSvc {
    uc_err err = UC_ERR_OK;
    uint64_t svc_pc = 0;
    uint64_t done = 0;
    IntrCtx ctx;
};

bool run_basic_svc(uc_engine* uc, IntrCtx ctx, BasicSvc& out) {
    Assembler a(kCode);
    a.mov(8, 98);
    out.svc_pc = a.pc();
    a.svc(0);
    a.mov(0, 0x1234);
    const size_t b_index = a.b_placeholder();
    const size_t done_label = a.label();
    a.nop();
    a.b(a.addr_of(done_label));
    a.patch_branch(b_index, a.addr_of(done_label));
    out.done = a.addr_of(done_label);

    load_code(uc, a);
    if (!add_intr_hook(uc, &ctx)) {
        return false;
    }
    out.err = uc_emu_start(uc, kCode, out.done, kProbeTimeoutUs, 0);
    out.ctx = ctx;
    return true;
}

bool probe1() {
    std::printf("\n== Probe 1: svc #0 -> UC_HOOK_INTR, intno == 2 ==\n");
    uc_engine* uc = open_engine("p1");
    if (uc == nullptr || !map_basic(uc)) {
        return false;
    }
    BasicSvc r;
    const bool ok = run_basic_svc(uc, IntrCtx{}, r);
    show_err("uc_emu_start", r.err);
    show_u64("svc address", r.svc_pc);
    show_u64("intr hits", static_cast<uint64_t>(r.ctx.hits));
    show_u64("intno passed to hook", r.ctx.intno);
    show_u64("x8 seen in hook", r.ctx.x8);
    expect_u64("intno == 2 (EXCP_SWI)", r.ctx.intno, 2);
    expect_u64("hook fired exactly once", static_cast<uint64_t>(r.ctx.hits), 1);
    uc_close(uc);
    return ok;
}

bool probe2() {
    std::printf("\n== Probe 2: PC in the hook == svc + 4 ==\n");
    uc_engine* uc = open_engine("p2");
    if (uc == nullptr || !map_basic(uc)) {
        return false;
    }
    BasicSvc r;
    const bool ok = run_basic_svc(uc, IntrCtx{}, r);
    show_err("uc_emu_start", r.err);
    show_u64("svc address", r.svc_pc);
    show_u64("PC in hook", r.ctx.pc);
    show_u64("svc + 4", r.svc_pc + 4);
    expect_u64("PC == svc + 4", r.ctx.pc, r.svc_pc + 4);
    uc_close(uc);
    return ok;
}

bool probe3() {
    std::printf("\n== Probe 3: hook writes x0 without touching PC ==\n");
    uc_engine* uc = open_engine("p3");
    if (uc == nullptr || !map_basic(uc)) {
        return false;
    }

    IntrCtx ctx;
    ctx.write_x0 = true;
    ctx.x0_new = 0xCAFE;

    Assembler a(kCode);
    a.mov(0, 0xDEAD);
    const uint64_t svc_pc = a.pc();
    a.svc(0);
    a.add_imm(0, 0, 1); // x0 = 0xCAFE + 1
    const size_t b_index = a.b_placeholder();
    const size_t done_label = a.label();
    a.nop();
    a.b(a.addr_of(done_label));
    a.patch_branch(b_index, a.addr_of(done_label));

    load_code(uc, a);
    if (!add_intr_hook(uc, &ctx)) {
        return false;
    }

    const uc_err err = uc_emu_start(uc, kCode, a.addr_of(done_label), kProbeTimeoutUs, 0);
    const uint64_t x0 = read_reg(uc, UC_ARM64_REG_X0);
    const uint64_t pc = read_reg(uc, UC_ARM64_REG_PC);

    show_err("uc_emu_start", err);
    show_u64("svc address", svc_pc);
    show_u64("x0 written by hook", ctx.x0_new);
    show_u64("x0 after add #1", x0);
    show_u64("PC after run", pc);
    show_u64("until address", a.addr_of(done_label));
    expect_u64("hook ran", static_cast<uint64_t>(ctx.hits), 1);
    expect_u64("guest continued at svc+4 (x0 == 0xCAFF)", x0, 0xCAFF);
    expect_u64("run stopped at 'until'", pc, a.addr_of(done_label));
    uc_close(uc);
    return true;
}

bool probe4() {
    std::printf("\n== Probe 4: stop inside hook, resume from host ==\n");
    uc_engine* uc = open_engine("p4");
    if (uc == nullptr || !map_basic(uc)) {
        return false;
    }

    IntrCtx ctx;
    ctx.write_x0 = true;
    ctx.x0_new = 0x1111;
    ctx.stop = true;

    Assembler a(kCode);
    a.mov(6, kData);
    a.mov(5, 0x7777);
    a.str_x(5, 6, 8); // [data+8] = 0x7777
    a.mov(0, 0xDEAD);
    const uint64_t svc_pc = a.pc();
    a.svc(0);
    a.add_imm(1, 0, 1); // x1 = x0 + 1
    a.str_x(1, 6, 16);
    const size_t b_index = a.b_placeholder();
    const size_t done_label = a.label();
    a.nop();
    a.b(a.addr_of(done_label));
    a.patch_branch(b_index, a.addr_of(done_label));

    load_code(uc, a);
    if (!add_intr_hook(uc, &ctx)) {
        return false;
    }

    const uc_err err1 = uc_emu_start(uc, kCode, a.addr_of(done_label), kProbeTimeoutUs, 0);
    const uint64_t pc1 = read_reg(uc, UC_ARM64_REG_PC);
    const uint64_t x0_1 = read_reg(uc, UC_ARM64_REG_X0);
    const uint64_t x5_1 = read_reg(uc, UC_ARM64_REG_X5);
    const uint64_t sp_1 = read_reg(uc, UC_ARM64_REG_SP);
    const uint64_t mem_before = read_mem_u64(uc, kData + 8);

    show_err("first uc_emu_start", err1);
    show_u64("PC after stop", pc1);
    show_u64("svc + 4", svc_pc + 4);
    show_u64("x0 written by hook", x0_1);
    show_u64("x5 before svc", ctx.x5);
    show_u64("x5 after stop", x5_1);
    show_u64("SP in hook", ctx.sp);
    show_u64("SP after stop", sp_1);
    show_u64("mem[data+8] written before svc", mem_before);
    show_u64("hook hits after first run", static_cast<uint64_t>(ctx.hits));

    expect_u64("first run fired hook once", static_cast<uint64_t>(ctx.hits), 1);
    expect_u64("PC stayed at svc+4", pc1, svc_pc + 4);
    expect_u64("x0 write visible after stop", x0_1, 0x1111);
    expect_u64("x5 preserved across stop", x5_1, 0x7777);
    expect_u64("SP preserved across stop", sp_1, ctx.sp);
    expect_u64("memory preserved across stop", mem_before, 0x7777);

    // Resume from svc+4. No re-entry: the hook must not fire again.
    const uint64_t x0_resume = 0x42;
    uc_reg_write(uc, UC_ARM64_REG_X0, &x0_resume);
    const uc_err err2 =
        uc_emu_start(uc, pc1, a.addr_of(done_label), kProbeTimeoutUs, 0);
    const uint64_t x1_2 = read_reg(uc, UC_ARM64_REG_X1);
    const uint64_t mem_after = read_mem_u64(uc, kData + 16);

    show_err("second uc_emu_start", err2);
    show_u64("x1 after resume (x0+1)", x1_2);
    show_u64("mem[data+16] after resume", mem_after);
    show_u64("hook hits after resume", static_cast<uint64_t>(ctx.hits));

    expect(err2 == UC_ERR_OK, "second run completed without error");
    expect_u64("x1 == x0 + 1 with host-written x0", x1_2, 0x43);
    expect_u64("resumed store reached guest memory", mem_after, 0x43);
    expect_u64("no re-entry of the same svc", static_cast<uint64_t>(ctx.hits), 1);

    uc_close(uc);
    return true;
}

// ---------------------------------------------------------------------------
// Probe 5: TPIDR_EL0
// ---------------------------------------------------------------------------
bool probe5() {
    std::printf("\n== Probe 5: mrs x0, tpidr_el0 reads host-written TLS ==\n");
    uc_engine* uc = open_engine("p5");
    if (uc == nullptr || !map_basic(uc)) {
        return false;
    }
    if (!map_region(uc, kTls, 2 * kPage, UC_PROT_READ | UC_PROT_WRITE, "tls")) {
        return false;
    }

    const uint64_t self1 = kTls;
    const uint64_t self2 = kTls + kPage;
    uc_mem_write(uc, kTls, &self1, sizeof(self1));
    uc_mem_write(uc, self2, &self2, sizeof(self2));

    Assembler a(kCode);
    a.mrs_tpidr(0);
    a.ldr_x(1, 0);
    const size_t b_index = a.b_placeholder();
    const size_t done_label = a.label();
    a.nop();
    a.b(a.addr_of(done_label));
    a.patch_branch(b_index, a.addr_of(done_label));
    load_code(uc, a);

    uint64_t tls = self1;
    uc_reg_write(uc, UC_ARM64_REG_TPIDR_EL0, &tls);
    uc_err err = uc_emu_start(uc, kCode, a.addr_of(done_label), kProbeTimeoutUs, 0);
    const uint64_t x0_run1 = read_reg(uc, UC_ARM64_REG_X0);
    const uint64_t x1_run1 = read_reg(uc, UC_ARM64_REG_X1);

    show_err("uc_emu_start (tls=0x40000)", err);
    show_u64("x0 = read TPIDR_EL0", x0_run1);
    show_u64("x1 = [x0]", x1_run1);
    expect_u64("mrs reads UC_ARM64_REG_TPIDR_EL0", x0_run1, self1);
    expect_u64("ldr [tpidr] sees host-written slot 0", x1_run1, self1);

    tls = self2;
    uc_reg_write(uc, UC_ARM64_REG_TPIDR_EL0, &tls);
    err = uc_emu_start(uc, kCode, a.addr_of(done_label), kProbeTimeoutUs, 0);
    const uint64_t x0_run2 = read_reg(uc, UC_ARM64_REG_X0);
    const uint64_t x1_run2 = read_reg(uc, UC_ARM64_REG_X1);
    const uint64_t tls_readback = read_reg(uc, UC_ARM64_REG_TPIDR_EL0);

    show_err("uc_emu_start (tls=0x41000)", err);
    show_u64("x0 = read TPIDR_EL0", x0_run2);
    show_u64("x1 = [x0]", x1_run2);
    show_u64("TPIDR_EL0 readback", tls_readback);
    expect_u64("host can move TLS base between runs", x0_run2, self2);
    expect_u64("slot 0 of the new TLS base", x1_run2, self2);
    expect_u64("TPIDR_EL0 readback matches", tls_readback, self2);

    uc_close(uc);
    return true;
}

// ---------------------------------------------------------------------------
// Probe 6: nested uc_emu_start on one engine
// ---------------------------------------------------------------------------
struct NestCtx {
    uc_context* saved = nullptr;
    uint64_t begin = 0;
    uint64_t until = 0;
    int limit = 32;
    bool verbose = false;
    bool save_context = false;
    int depth = 0;
    int max_depth = 0;
    int hook_calls = 0;
    int nested_ok = 0;
    int first_error_at = 0;
    uc_err first_error = UC_ERR_OK;
    int64_t nested_us = 0;
};

void on_nest_intr(uc_engine* uc, uint32_t /*intno*/, void* user_data) {
    auto* ctx = static_cast<NestCtx*>(user_data);
    ++ctx->hook_calls;
    ++ctx->depth;
    if (ctx->verbose) {
        std::printf("    nest enter depth=%d\n", ctx->depth);
    }
    if (ctx->depth > ctx->max_depth) {
        ctx->max_depth = ctx->depth;
    }

    if (ctx->depth <= ctx->limit) {
        const auto t0 = std::chrono::steady_clock::now();
        if (ctx->save_context) {
            uc_context_save(uc, ctx->saved);
        }
        const uc_err err = uc_emu_start(uc, ctx->begin, ctx->until, 0, 0);
        if (ctx->save_context) {
            uc_context_restore(uc, ctx->saved);
        }
        ctx->nested_us += std::chrono::duration_cast<std::chrono::microseconds>(
                              std::chrono::steady_clock::now() - t0)
                              .count();
        if (ctx->verbose) {
            std::printf("    nest leave depth=%d err=%s\n", ctx->depth, uc_strerror(err));
        }
        if (err == UC_ERR_OK) {
            ++ctx->nested_ok;
        } else if (ctx->first_error_at == 0) {
            ctx->first_error_at = ctx->depth;
            ctx->first_error = err;
        }
    }
    --ctx->depth;
}

struct NestResult {
    uc_err err = UC_ERR_OK;
    int max_depth = 0;
    int nested_ok = 0;
    int hook_calls = 0;
    int first_error_at = 0;
    uc_err first_error = UC_ERR_OK;
    uint64_t mem_counter = 0;
    uint64_t pc_after = 0;
    int64_t elapsed_us = 0;
    int64_t nested_us = 0;
};

// Guest body:
//   svc #1
//   ldr x2, [x3]; add x2, x2, #1; str x2, [x3]   ; persistent guest-memory counter
//   b done
// Memory survives a nested call; registers do not.
NestResult run_nest_engine(int limit, bool save_context) {
    NestResult result;
    uc_engine* uc = open_engine(save_context ? "p6-save" : "p6-nosave");
    if (uc == nullptr || !map_basic(uc)) {
        return result;
    }

    const uint64_t zero = 0;
    uc_mem_write(uc, kData, &zero, sizeof(zero));
    const uint64_t data = kData;
    uc_reg_write(uc, UC_ARM64_REG_X3, &data);

    Assembler a(kCode);
    a.svc(1);
    a.ldr_x(2, 3);
    a.add_imm(2, 2, 1);
    a.str_x(2, 3);
    const size_t b_index = a.b_placeholder();
    const size_t done_label = a.label();
    a.nop();
    a.b(a.addr_of(done_label));
    a.patch_branch(b_index, a.addr_of(done_label));
    load_code(uc, a);

    NestCtx ctx;
    ctx.begin = kCode;
    ctx.until = a.addr_of(done_label);
    ctx.limit = limit;
    ctx.save_context = save_context;
    ctx.verbose = std::getenv("DUCKEMU_NEST_VERBOSE") != nullptr;

    if (save_context && uc_context_alloc(uc, &ctx.saved) != UC_ERR_OK) {
        std::printf("  uc_context_alloc failed\n");
        ++g_failures;
        uc_close(uc);
        return result;
    }

    uc_hook hook = 0;
    const uc_err hook_err = uc_hook_add(uc, &hook, UC_HOOK_INTR,
                                        reinterpret_cast<void*>(&on_nest_intr), &ctx,
                                        1, 0);
    if (hook_err != UC_ERR_OK) {
        std::printf("  uc_hook_add failed: %s\n", uc_strerror(hook_err));
        ++g_failures;
        if (ctx.saved != nullptr) {
            uc_context_free(ctx.saved);
        }
        uc_close(uc);
        return result;
    }

    const auto t0 = std::chrono::steady_clock::now();
    result.err = uc_emu_start(uc, ctx.begin, ctx.until, kProbeTimeoutUs, 0);
    result.elapsed_us = std::chrono::duration_cast<std::chrono::microseconds>(
                            std::chrono::steady_clock::now() - t0)
                            .count();
    result.max_depth = ctx.max_depth;
    result.nested_ok = ctx.nested_ok;
    result.hook_calls = ctx.hook_calls;
    result.first_error_at = ctx.first_error_at;
    result.first_error = ctx.first_error;
    result.nested_us = ctx.nested_us;
    result.mem_counter = read_mem_u64(uc, kData);
    result.pc_after = read_reg(uc, UC_ARM64_REG_PC);

    if (ctx.saved != nullptr) {
        uc_context_free(ctx.saved);
    }
    uc_close(uc);
    return result;
}

bool probe6() {
    std::printf("\n== Probe 6: nested uc_emu_start on the same engine ==\n");

    // Total nesting = limit + 1 levels (outermost run plus one per hook).
    //
    // Measured: 63 total levels (limit=62) is fine; 64 total levels (limit=63)
    // corrupts uc->nested_level inside Unicorn and segfaults in
    // uc_addr_is_exit. UC_MAX_NESTED_LEVEL is 64 on paper, 63 in practice.
    // Default to a conservative 32; raise via DUCKEMU_NEST_LIMIT to reproduce
    // the boundary (see docs/devlogs/2026-10-27-03-M0探针结果.md).
    int limit = 32;
    if (const char* env = std::getenv("DUCKEMU_NEST_LIMIT")) {
        limit = std::atoi(env);
    }

    const NestResult no_save = run_nest_engine(limit, false);
    std::printf("  -- without uc_context_save/restore --\n");
    show_err("outer uc_emu_start", no_save.err);
    show_i64("nest limit (nested re-entries)", limit);
    show_i64("max hook depth (= total emu_start levels)", no_save.max_depth);
    show_i64("successful nested uc_emu_start calls", no_save.nested_ok);
    show_i64("total hook invocations", no_save.hook_calls);
    show_i64("first rejected call at depth", no_save.first_error_at);
    show_err("first rejected call error", no_save.first_error);
    show_u64("guest-memory counter after unwind", no_save.mem_counter);
    show_u64("PC after outer run", no_save.pc_after);
    show_i64("elapsed us", no_save.elapsed_us);
    show_i64("nested call time total (us)", no_save.nested_us);

    const NestResult with_save = run_nest_engine(limit, true);
    std::printf("  -- with uc_context_save/restore around each nested run --\n");
    show_err("outer uc_emu_start", with_save.err);
    show_i64("nest limit (nested re-entries)", limit);
    show_i64("max hook depth (= total emu_start levels)", with_save.max_depth);
    show_i64("successful nested uc_emu_start calls", with_save.nested_ok);
    show_i64("total hook invocations", with_save.hook_calls);
    show_i64("first rejected call at depth", with_save.first_error_at);
    show_err("first rejected call error", with_save.first_error);
    show_u64("guest-memory counter after unwind", with_save.mem_counter);
    show_u64("PC after outer run", with_save.pc_after);
    show_i64("elapsed us", with_save.elapsed_us);
    show_i64("nested call time total (us)", with_save.nested_us);

    const auto expected_levels = static_cast<uint64_t>(limit) + 1;
    expect_u64("nested calls succeed without save/restore",
               static_cast<uint64_t>(no_save.nested_ok), static_cast<uint64_t>(limit));
    expect_u64("max nesting == limit + 1 (no save)",
               static_cast<uint64_t>(no_save.max_depth), expected_levels);
    expect_u64("without save/restore only the innermost level resumes its code",
               no_save.mem_counter, 1);
    expect_u64("nested calls succeed with save/restore",
               static_cast<uint64_t>(with_save.nested_ok),
               static_cast<uint64_t>(limit));
    expect_u64("max nesting == limit + 1 (with save)",
               static_cast<uint64_t>(with_save.max_depth), expected_levels);
    expect_u64("with save/restore every level resumes its code",
               with_save.mem_counter, expected_levels);
    expect_u64("every level entered the hook exactly once",
               static_cast<uint64_t>(with_save.hook_calls), expected_levels);
    expect(with_save.err == UC_ERR_OK, "outer run completed with save/restore");
    if (limit >= 64) {
        expect_u64("rejected call returns UC_ERR_RESOURCE",
                   static_cast<uint64_t>(with_save.first_error), UC_ERR_RESOURCE);
    } else {
        expect_u64("no nested call was rejected",
                   static_cast<uint64_t>(with_save.first_error_at), 0);
    }
    return true;
}

// ---------------------------------------------------------------------------
// Probe 7: two engines, two host threads, one uc_mem_map_ptr buffer
// ---------------------------------------------------------------------------
struct EngineRun {
    uc_engine* uc = nullptr;
    uint64_t begin = 0;
    uint64_t until = 0;
    std::atomic<bool>* start = nullptr;
    std::atomic<bool>* in_emu = nullptr;
    std::atomic<bool>* done = nullptr;
    uc_err err = UC_ERR_OK;
};

void run_engine_thread(EngineRun* run) {
    while (!run->start->load(std::memory_order_acquire)) {
        std::this_thread::yield();
    }
    run->in_emu->store(true, std::memory_order_release);
    run->err = uc_emu_start(run->uc, run->begin, run->until, 0, 0);
    run->in_emu->store(false, std::memory_order_release);
    run->done->store(true, std::memory_order_release);
}

bool probe7() {
    std::printf("\n== Probe 7: two engines on two threads sharing one map_ptr ==\n");

    void* shared = mmap(nullptr, kPage, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (shared == MAP_FAILED) {
        std::printf("  mmap failed\n");
        ++g_failures;
        return false;
    }
    std::memset(shared, 0, kPage);

    uc_engine* uc_a = open_engine("p7-a");
    uc_engine* uc_b = open_engine("p7-b");
    if (uc_a == nullptr || uc_b == nullptr) {
        return false;
    }
    if (!map_basic(uc_a) || !map_basic(uc_b)) {
        return false;
    }
    expect_u64("engine A uc_mem_map_ptr",
               uc_mem_map_ptr(uc_a, kShared, kPage, UC_PROT_READ | UC_PROT_WRITE, shared),
               UC_ERR_OK);
    expect_u64("engine B uc_mem_map_ptr",
               uc_mem_map_ptr(uc_b, kShared, kPage, UC_PROT_READ | UC_PROT_WRITE, shared),
               UC_ERR_OK);

    std::atomic<bool> start{false};
    std::atomic<bool> in_a{false};
    std::atomic<bool> in_b{false};
    std::atomic<bool> done_a{false};
    std::atomic<bool> done_b{false};

    EngineRun run_a;
    run_a.uc = uc_a;
    run_a.begin = kCode;
    EngineRun run_b;
    run_b.uc = uc_b;
    run_b.begin = kCode;

    // A: phase=1; wait phase==2; ack=0xAAAA; phase=3.

    // Rebuild with explicit until addresses.
    Assembler a2(kCode);
    a2.mov(0, kShared);
    a2.mov(1, 1);
    a2.str_w(1, 0);
    const size_t a_loop = a2.label();
    a2.ldr_w(2, 0);
    a2.cmp_w_imm(2, 2);
    a2.b_ne(a2.addr_of(a_loop));
    a2.mov(1, 0xAAAA);
    a2.str_w(1, 0, 4);
    a2.mov(1, 3);
    a2.str_w(1, 0);
    const size_t a_b = a2.b_placeholder();
    const size_t a_done = a2.label();
    a2.nop();
    a2.b(a2.addr_of(a_done));
    a2.patch_branch(a_b, a2.addr_of(a_done));
    load_code(uc_a, a2);

    Assembler b2(kCode);
    b2.mov(0, kShared);
    const size_t b_loop1 = b2.label();
    b2.ldr_w(2, 0);
    b2.cmp_w_imm(2, 1);
    b2.b_ne(b2.addr_of(b_loop1));
    b2.mov(1, 0xBBBB);
    b2.str_w(1, 0, 8);
    b2.mov(1, 2);
    b2.str_w(1, 0);
    const size_t b_loop2 = b2.label();
    b2.ldr_w(2, 0);
    b2.cmp_w_imm(2, 3);
    b2.b_ne(b2.addr_of(b_loop2));
    const size_t b_b = b2.b_placeholder();
    const size_t b_done = b2.label();
    b2.nop();
    b2.b(b2.addr_of(b_done));
    b2.patch_branch(b_b, b2.addr_of(b_done));
    load_code(uc_b, b2);

    run_a.until = a2.addr_of(a_done);
    run_b.until = b2.addr_of(b_done);
    run_a.start = &start;
    run_a.in_emu = &in_a;
    run_a.done = &done_a;
    run_b.start = &start;
    run_b.in_emu = &in_b;
    run_b.done = &done_b;

    const auto t0 = std::chrono::steady_clock::now();
    std::thread ta(run_engine_thread, &run_a);
    std::thread tb(run_engine_thread, &run_b);
    start.store(true, std::memory_order_release);

    bool overlap = false;
    bool timed_out = false;
    const auto deadline = t0 + std::chrono::seconds(5);
    while (!(done_a.load(std::memory_order_acquire) &&
             done_b.load(std::memory_order_acquire))) {
        if (in_a.load(std::memory_order_acquire) && in_b.load(std::memory_order_acquire)) {
            overlap = true;
        }
        if (std::chrono::steady_clock::now() > deadline) {
            timed_out = true;
            uc_emu_stop(uc_a);
            uc_emu_stop(uc_b);
            break;
        }
        std::this_thread::sleep_for(std::chrono::microseconds(50));
    }
    ta.join();
    tb.join();
    const auto elapsed_us = std::chrono::duration_cast<std::chrono::microseconds>(
                                std::chrono::steady_clock::now() - t0)
                                .count();

    const auto* words = static_cast<const uint32_t*>(shared);
    show_err("engine A uc_emu_start", run_a.err);
    show_err("engine B uc_emu_start", run_b.err);
    show_u64("shared[0] phase", words[0]);
    show_u64("shared[1] A ack", words[1]);
    show_u64("shared[2] B marker", words[2]);
    show_i64("elapsed us", elapsed_us);
    show_u64("sampled both-in-emu overlap", overlap ? 1 : 0);
    // `overlap` is only a sampled observation. The real proof of concurrency is
    // the guest handshake: A spins until B writes phase=2 and B spins until A
    // writes phase=1, and uc_emu_start never yields. Serial execution on one
    // host thread could not complete; both finishing means both engines ran at
    // the same time.
    expect(!timed_out, "both engines finished before the 5s watchdog");
    expect_u64("A completed", run_a.err, UC_ERR_OK);
    expect_u64("B completed", run_b.err, UC_ERR_OK);
    expect_u64("A saw B's write (phase == 3)", words[0], 3);
    expect_u64("host sees A's write through the shared pointer", words[1], 0xAAAA);
    expect_u64("host sees B's write through the shared pointer", words[2], 0xBBBB);

    uc_close(uc_a);
    uc_close(uc_b);
    munmap(shared, kPage);
    return true;
}

// ---------------------------------------------------------------------------
// Probe 8: uc_mem_map_ptr permissions are per-engine
// ---------------------------------------------------------------------------
std::string host_mapping_perms(void* address) {
    FILE* file = std::fopen("/proc/self/maps", "r");
    if (file == nullptr) {
        return "?";
    }
    const auto target = reinterpret_cast<uintptr_t>(address);
    char line[512];
    std::string result = "not-found";
    while (std::fgets(line, sizeof(line), file) != nullptr) {
        unsigned long lo = 0;
        unsigned long hi = 0;
        char perms[8] = {};
        if (std::sscanf(line, "%lx-%lx %7s", &lo, &hi, perms) == 3) {
            if (target >= lo && target < hi) {
                result = perms;
                break;
            }
        }
    }
    std::fclose(file);
    return result;
}

bool probe8() {
    std::printf("\n== Probe 8: uc_mem_map_ptr + uc_mem_protect ==\n");

    void* shared = mmap(nullptr, kPage, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (shared == MAP_FAILED) {
        std::printf("  mmap failed\n");
        ++g_failures;
        return false;
    }
    std::memset(shared, 0, kPage);
    auto* bytes = static_cast<uint8_t*>(shared);
    bytes[0x100] = 0x5A;

    // Stub in the shared page: ldrb w0, [x1]; b done
    Assembler stub(kShared + 0x200);
    stub.ldrb(0, 1);
    const size_t stub_b = stub.b_placeholder();
    const size_t stub_done = stub.label();
    stub.nop();
    stub.b(stub.addr_of(stub_done));
    stub.patch_branch(stub_b, stub.addr_of(stub_done));
    std::memcpy(bytes + 0x200, stub.words().data(), stub.size() * sizeof(uint32_t));

    const std::string host_perms_before = host_mapping_perms(shared);

    uc_engine* uc_a = open_engine("p8-a");
    uc_engine* uc_b = open_engine("p8-b");
    if (uc_a == nullptr || uc_b == nullptr) {
        return false;
    }
    if (!map_basic(uc_a) || !map_basic(uc_b)) {
        return false;
    }
    expect_u64("A: map_ptr(RW)",
             uc_mem_map_ptr(uc_a, kShared, kPage, UC_PROT_READ | UC_PROT_WRITE, shared),
             UC_ERR_OK);
    expect_u64("B: map_ptr(RX)",
             uc_mem_map_ptr(uc_b, kShared, kPage, UC_PROT_READ | UC_PROT_EXEC, shared),
             UC_ERR_OK);
    expect_u64("A write canary via guest",
             [&] {
                 Assembler w(kCode);
                 w.mov(0, kShared + 0x100);
                 w.mov(1, 0x5A);
                 w.strb(1, 0);
                 const size_t bi = w.b_placeholder();
                 const size_t dl = w.label();
                 w.nop();
                 w.b(w.addr_of(dl));
                 w.patch_branch(bi, w.addr_of(dl));
                 load_code(uc_a, w);
                 return static_cast<uint64_t>(
                     uc_emu_start(uc_a, kCode, w.addr_of(dl), kProbeTimeoutUs, 0));
             }(),
             UC_ERR_OK);
    expect_u64("host mapping sees A's guest write", bytes[0x100], 0x5A);

    // B has no write permission on the same host page.
    Assembler wb(kCode);
    wb.mov(0, kShared + 0x100);
    wb.mov(1, 0x11);
    wb.strb(1, 0);
    const size_t wb_b = wb.b_placeholder();
    const size_t wb_done = wb.label();
    wb.nop();
    wb.b(wb.addr_of(wb_done));
    wb.patch_branch(wb_b, wb.addr_of(wb_done));
    load_code(uc_b, wb);
    const uc_err b_write_err =
        uc_emu_start(uc_b, kCode, wb.addr_of(wb_done), kProbeTimeoutUs, 0);
    show_err("B guest write to RX mapping", b_write_err);
    expect_u64("B write rejected with WRITE_PROT", b_write_err, UC_ERR_WRITE_PROT);
    expect_u64("B did not change the host byte", bytes[0x100], 0x5A);

    // A maps the shared page without EXEC: fetch must fail.
    const uc_err a_fetch_err =
        uc_emu_start(uc_a, kShared + 0x200, kShared + 0x208, kProbeTimeoutUs, 0);
    show_err("A fetch from RW (no EXEC) mapping", a_fetch_err);
    expect_u64("A fetch rejected with FETCH_PROT", a_fetch_err, UC_ERR_FETCH_PROT);

    // B maps the shared page with EXEC: the same bytes execute fine.
    const uint64_t data_ptr = kShared + 0x100;
    uc_reg_write(uc_b, UC_ARM64_REG_X1, &data_ptr);
    const uc_err b_fetch_err =
        uc_emu_start(uc_b, kShared + 0x200, kShared + 0x208, kProbeTimeoutUs, 0);
    const uint64_t b_fetch_value = read_reg(uc_b, UC_ARM64_REG_X0);
    show_err("B fetch from RX mapping", b_fetch_err);
    show_u64("B x0 after ldrb", b_fetch_value);
    expect_u64("B executes code from the shared host page", b_fetch_err, UC_ERR_OK);
    expect_u64("B reads the shared data byte", b_fetch_value, 0x5A);

    // Engine-local protect: A loses WRITE, B keeps EXEC. Host mapping unchanged.
    const uc_err prot_err = uc_mem_protect(uc_a, kShared, kPage, UC_PROT_READ);
    show_err("A uc_mem_protect(READ)", prot_err);
    expect_u64("A uc_mem_protect succeeded", prot_err, UC_ERR_OK);

    load_code(uc_a, wb);
    const uc_err a_write_after =
        uc_emu_start(uc_a, kCode, wb.addr_of(wb_done), kProbeTimeoutUs, 0);
    show_err("A guest write after protect(READ)", a_write_after);
    expect_u64("A write now rejected with WRITE_PROT", a_write_after, UC_ERR_WRITE_PROT);

    bytes[0x100] = 0x77;
    const std::string host_perms_after = host_mapping_perms(shared);
    show_u64("host wrote the shared byte directly", bytes[0x100]);

    Assembler ra(kCode);
    ra.mov(0, kShared + 0x100);
    ra.ldrb(1, 0);
    const size_t ra_b = ra.b_placeholder();
    const size_t ra_done = ra.label();
    ra.nop();
    ra.b(ra.addr_of(ra_done));
    ra.patch_branch(ra_b, ra.addr_of(ra_done));
    load_code(uc_a, ra);
    const uc_err a_read_err =
        uc_emu_start(uc_a, kCode, ra.addr_of(ra_done), kProbeTimeoutUs, 0);
    const uint64_t a_read_value = read_reg(uc_a, UC_ARM64_REG_X1);
    show_err("A guest read after protect(READ)", a_read_err);
    show_u64("A x1 after ldrb", a_read_value);
    expect_u64("A read still allowed", a_read_err, UC_ERR_OK);
    expect_u64("A sees the host's direct write", a_read_value, 0x77);

    uc_reg_write(uc_b, UC_ARM64_REG_X1, &data_ptr);
    const uc_err b_fetch_after =
        uc_emu_start(uc_b, kShared + 0x200, kShared + 0x208, kProbeTimeoutUs, 0);
    const uint64_t b_value_after = read_reg(uc_b, UC_ARM64_REG_X0);
    show_err("B fetch after A's protect", b_fetch_after);
    expect_u64("B EXEC unaffected by A's protect", b_fetch_after, UC_ERR_OK);
    expect_u64("B sees the host's direct write", b_value_after, 0x77);

    std::printf("  host /proc/self/maps perms before map_ptr: %s\n",
                host_perms_before.c_str());
    std::printf("  host /proc/self/maps perms after  map_ptr: %s\n",
                host_perms_after.c_str());
    expect(host_perms_before == host_perms_after,
           "engine permissions never changed the host mapping");

    uc_close(uc_a);
    uc_close(uc_b);
    munmap(shared, kPage);
    return true;
}

// ---------------------------------------------------------------------------
// Probe 9: cross-thread uc_emu_stop, then map/protect/ctl while paused
// ---------------------------------------------------------------------------
struct CountCtx {
    std::atomic<uint64_t> insns{0};
    std::atomic<bool> in_guest{false};
};

void on_code(uc_engine* /*uc*/, uint64_t /*address*/, uint32_t /*size*/, void* user_data) {
    auto* ctx = static_cast<CountCtx*>(user_data);
    ctx->insns.fetch_add(1, std::memory_order_relaxed);
    ctx->in_guest.store(true, std::memory_order_release);
}

struct StopRun {
    uc_engine* uc = nullptr;
    uint64_t begin = 0;
    std::atomic<bool>* done = nullptr;
    uc_err err = UC_ERR_OK;
    std::chrono::steady_clock::time_point started;
    std::chrono::steady_clock::time_point finished;
};

void run_stop_thread(StopRun* run) {
    run->started = std::chrono::steady_clock::now();
    run->err = uc_emu_start(run->uc, run->begin, 0, 0, 0);
    run->finished = std::chrono::steady_clock::now();
    run->done->store(true, std::memory_order_release);
}

bool probe9() {
    std::printf("\n== Probe 9: cross-thread stop; ops on a paused engine ==\n");
    uc_engine* uc = open_engine("p9");
    if (uc == nullptr || !map_basic(uc)) {
        return false;
    }

    Assembler loop(kCode);
    const size_t loop_label = loop.label();
    loop.add_imm(0, 0, 1);
    loop.b(loop.addr_of(loop_label));
    load_code(uc, loop);

    CountCtx count;
    uc_hook code_hook = 0;
    const uc_err hook_err =
        uc_hook_add(uc, &code_hook, UC_HOOK_CODE,
                    reinterpret_cast<void*>(&on_code), &count, 1, 0);
    if (hook_err != UC_ERR_OK) {
        std::printf("  uc_hook_add(UC_HOOK_CODE) failed: %s\n", uc_strerror(hook_err));
        ++g_failures;
        return false;
    }

    std::atomic<bool> done{false};
    StopRun run;
    run.uc = uc;
    run.begin = kCode;
    run.done = &done;

    const auto start_time = std::chrono::steady_clock::now();
    std::thread worker(run_stop_thread, &run);

    // Wait until the guest is actually executing, then let it spin a bit.
    const auto wait_deadline = start_time + std::chrono::seconds(3);
    while (!count.in_guest.load(std::memory_order_acquire) &&
           std::chrono::steady_clock::now() < wait_deadline) {
        std::this_thread::sleep_for(std::chrono::microseconds(100));
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    const auto stop_time = std::chrono::steady_clock::now();
    const uc_err stop_err = uc_emu_stop(uc);

    const auto join_deadline = stop_time + std::chrono::seconds(3);
    while (!done.load(std::memory_order_acquire) &&
           std::chrono::steady_clock::now() < join_deadline) {
        std::this_thread::sleep_for(std::chrono::microseconds(100));
    }
    const bool stopped = done.load(std::memory_order_acquire);
    const auto stop_latency_us =
        std::chrono::duration_cast<std::chrono::microseconds>(run.finished - stop_time)
            .count();
    worker.join();

    const uint64_t insns_at_stop = count.insns.load(std::memory_order_acquire);
    const uint64_t pc_after_stop = read_reg(uc, UC_ARM64_REG_PC);

    show_err("uc_emu_stop from another thread", stop_err);
    show_err("uc_emu_start return", run.err);
    show_u64("emu_start returned", stopped ? 1 : 0);
    show_u64("instructions executed before stop", insns_at_stop);
    show_i64("stop -> emu_start return latency (us)", stop_latency_us);
    show_u64("PC after stop", pc_after_stop);

    expect(stopped, "cross-thread uc_emu_stop unblocked the running engine");
    expect_u64("uc_emu_stop returned UC_ERR_OK", stop_err, UC_ERR_OK);
    expect_u64("stopping does not report a fault", run.err, UC_ERR_OK);
    expect(insns_at_stop > 0, "the engine was really executing guest code");

    // Engine is now idle ("paused"): map / protect / uc_ctl from another thread.
    const uc_err map_err = uc_mem_map(uc, kExtra, kPage, UC_PROT_READ | UC_PROT_WRITE);
    const uc_err prot_err = uc_mem_protect(uc, kExtra, kPage, UC_PROT_READ);
    // Unicorn's public header implements uc_ctl_* as C-style-cast macros; that
    // expands at our call site, so silence only this warning around the calls.
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wold-style-cast"
#endif
    const uc_err cache_err = uc_ctl_remove_cache(uc, kCode, kCode + kPage);
    const uc_err flush_err = uc_ctl_flush_tb(uc);
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic pop
#endif
    size_t page_size = 0;
    size_t arch = 0;
    size_t mode = 0;
    const uc_err query_page = uc_query(uc, UC_QUERY_PAGE_SIZE, &page_size);
    const uc_err query_arch = uc_query(uc, UC_QUERY_ARCH, &arch);
    const uc_err query_mode = uc_query(uc, UC_QUERY_MODE, &mode);

    show_err("uc_mem_map while paused", map_err);
    show_err("uc_mem_protect while paused", prot_err);
    show_err("uc_ctl_remove_cache while paused", cache_err);
    show_err("uc_ctl_flush_tb while paused", flush_err);
    show_err("uc_query(PAGE_SIZE) while paused", query_page);
    show_err("uc_query(ARCH) while paused", query_arch);
    show_err("uc_query(MODE) while paused", query_mode);
    show_u64("queried page size", page_size);
    show_u64("queried arch", arch);
    show_u64("queried mode", mode);

    expect_u64("map on paused engine", map_err, UC_ERR_OK);
    expect_u64("protect on paused engine", prot_err, UC_ERR_OK);
    expect_u64("TB remove-cache on paused engine", cache_err, UC_ERR_OK);
    expect_u64("TB flush on paused engine", flush_err, UC_ERR_OK);
    expect_u64("uc_query page size", query_page, UC_ERR_OK);
    expect_u64("uc_query arch", query_arch, UC_ERR_OK);
    expect_u64("uc_query mode", query_mode, UC_ERR_OK);

    // Resume the same engine from its own PC; use a timeout so the loop ends.
    const uc_err resume_err =
        uc_emu_start(uc, pc_after_stop, 0, 100000 /* 100 ms */, 0);
    size_t timed_out = 0;
    const uc_err timeout_query = uc_query(uc, UC_QUERY_TIMEOUT, &timed_out);
    const uint64_t insns_after_resume = count.insns.load(std::memory_order_acquire);
    const uint64_t pc_after_resume = read_reg(uc, UC_ARM64_REG_PC);

    show_err("resume after paused ops", resume_err);
    show_err("uc_query(TIMEOUT)", timeout_query);
    show_u64("timed_out flag", timed_out);
    show_u64("instructions after resume", insns_after_resume);
    show_u64("PC after resume", pc_after_resume);

    expect_u64("engine resumes from the stop PC", resume_err, UC_ERR_OK);
    expect_u64("timeout flag set", timed_out, 1);
    expect(insns_after_resume > insns_at_stop, "guest executed after resume");

    uc_close(uc);
    return true;
}

// ---------------------------------------------------------------------------
// Probe 10/11: M8 pre-work -- code-hook PC redirect and hook ordering.
//
// Probe 10 answers the one question the trace/hook design cannot guess:
// can a UC_HOOK_CODE callback redirect execution by writing PC? Probe 11 pins
// the order of code/memory/intr callbacks and whether an SVC is replayed when
// the intr handler stops and the host resumes from svc + 4.
// ---------------------------------------------------------------------------
enum class TraceEventKind { Code = 0, MemRead, MemWrite, Intr };

struct TraceEvent {
    TraceEventKind kind;
    uint64_t address;
    uint32_t size;
    uint64_t pc = 0;
};

struct HookTraceCtx {
    std::vector<TraceEvent> events;
    uint64_t hook_address = 0;
    uint64_t redirect_to = 0;
    int redirects = 0;
    int intr_hits = 0;
    bool stop_on_intr = false;
};

const char* trace_event_name(TraceEventKind kind) {
    switch (kind) {
    case TraceEventKind::Code: return "code";
    case TraceEventKind::MemRead: return "read";
    case TraceEventKind::MemWrite: return "write";
    case TraceEventKind::Intr: return "intr";
    }
    return "?";
}

void on_trace_code(uc_engine* uc, uint64_t address, uint32_t size, void* user_data) {
    auto* ctx = static_cast<HookTraceCtx*>(user_data);
    ctx->events.push_back({TraceEventKind::Code, address, size, address});
    if (ctx->redirect_to != 0 && address == ctx->hook_address) {
        ++ctx->redirects;
        uint64_t target = ctx->redirect_to;
        uc_reg_write(uc, UC_ARM64_REG_PC, &target);
    }
}

bool on_trace_mem(uc_engine* uc, uc_mem_type type, uint64_t address, int size,
                  int64_t /*value*/, void* user_data) {
    auto* ctx = static_cast<HookTraceCtx*>(user_data);
    const uint64_t pc = read_reg(uc, UC_ARM64_REG_PC);
    if (type == UC_MEM_READ) {
        ctx->events.push_back({TraceEventKind::MemRead, address,
                               static_cast<uint32_t>(size), pc});
    } else if (type == UC_MEM_WRITE) {
        ctx->events.push_back({TraceEventKind::MemWrite, address,
                               static_cast<uint32_t>(size), pc});
    }
    return true;
}

void on_trace_intr(uc_engine* uc, uint32_t intno, void* user_data) {
    auto* ctx = static_cast<HookTraceCtx*>(user_data);
    ++ctx->intr_hits;
    const uint64_t pc = read_reg(uc, UC_ARM64_REG_PC);
    ctx->events.push_back({TraceEventKind::Intr, pc, intno, pc});
    if (ctx->stop_on_intr) {
        uc_emu_stop(uc);
    }
}

bool add_trace_hooks(uc_engine* uc, HookTraceCtx* ctx, uint64_t code_begin,
                     uint64_t code_end) {
    uc_hook hook = 0;
    uc_err err = uc_hook_add(uc, &hook, UC_HOOK_CODE,
                             reinterpret_cast<void*>(&on_trace_code), ctx,
                             code_begin, code_end);
    if (err != UC_ERR_OK) {
        std::printf("  uc_hook_add(UC_HOOK_CODE) failed: %s\n", uc_strerror(err));
        ++g_failures;
        return false;
    }
    hook = 0;
    err = uc_hook_add(uc, &hook, UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE,
                      reinterpret_cast<void*>(&on_trace_mem), ctx, 1, 0);
    if (err != UC_ERR_OK) {
        std::printf("  uc_hook_add(UC_HOOK_MEM_READ|WRITE) failed: %s\n",
                    uc_strerror(err));
        ++g_failures;
        return false;
    }
    hook = 0;
    err = uc_hook_add(uc, &hook, UC_HOOK_INTR,
                      reinterpret_cast<void*>(&on_trace_intr), ctx, 1, 0);
    if (err != UC_ERR_OK) {
        std::printf("  uc_hook_add(UC_HOOK_INTR) failed: %s\n", uc_strerror(err));
        ++g_failures;
        return false;
    }
    return true;
}

void print_trace_events(const HookTraceCtx& ctx) {
    std::printf("  event sequence (%zu):\n", ctx.events.size());
    for (size_t i = 0; i < ctx.events.size(); ++i) {
        std::printf("    %2zu  %-5s addr=0x%05" PRIx64 "  size=%u  pc=0x%05" PRIx64 "\n", i,
                    trace_event_name(ctx.events[i].kind), ctx.events[i].address,
                    ctx.events[i].size, ctx.events[i].pc);
    }
}

int count_events(const HookTraceCtx& ctx, TraceEventKind kind, uint64_t address) {
    int count = 0;
    for (const auto& event : ctx.events) {
        if (event.kind == kind && event.address == address) {
            ++count;
        }
    }
    return count;
}

int index_of_event(const HookTraceCtx& ctx, TraceEventKind kind, uint64_t address) {
    for (size_t i = 0; i < ctx.events.size(); ++i) {
        if (ctx.events[i].kind == kind && ctx.events[i].address == address) {
            return static_cast<int>(i);
        }
    }
    return -1;
}

// Case A: redirect to an address inside the straight-line block.
bool probe10_redirect_same_block() {
    uc_engine* uc = open_engine("p10a");
    if (uc == nullptr || !map_basic(uc)) {
        return false;
    }

    Assembler a(kCode);
    a.mov(0, 0x10);
    const uint64_t hook_pc = a.pc();
    a.mov(1, 0x11); // must be skipped
    a.mov(2, 0x12); // must be skipped
    const uint64_t landing = a.pc();
    a.mov(3, 0x13); // must run
    const size_t b_done = a.b_placeholder();
    const size_t done_label = a.label();
    a.nop();
    a.b(a.addr_of(done_label));
    a.patch_branch(b_done, a.addr_of(done_label));

    load_code(uc, a);

    HookTraceCtx ctx;
    ctx.hook_address = hook_pc;
    ctx.redirect_to = landing;
    if (!add_trace_hooks(uc, &ctx, hook_pc, hook_pc + 4)) {
        return false;
    }

    const uc_err err = uc_emu_start(uc, kCode, a.addr_of(done_label),
                                    kProbeTimeoutUs, 0);
    const uint64_t x1 = read_reg(uc, UC_ARM64_REG_X1);
    const uint64_t x2 = read_reg(uc, UC_ARM64_REG_X2);
    const uint64_t x3 = read_reg(uc, UC_ARM64_REG_X3);

    std::printf("  -- same-block redirect --\n");
    show_err("uc_emu_start", err);
    show_u64("hook address", hook_pc);
    show_u64("redirect target", landing);
    show_u64("redirects", static_cast<uint64_t>(ctx.redirects));
    show_u64("x1 (must stay 0)", x1);
    show_u64("x2 (must stay 0)", x2);
    show_u64("x3 (must be 0x13)", x3);
    print_trace_events(ctx);

    const bool ok = x1 == 0 && x2 == 0 && x3 == 0x13;
    expect(ok, "code hook PC write redirects execution (same block)");
    uc_close(uc);
    return true;
}

// Case B: redirect to a different executable page.
bool probe10_redirect_other_page() {
    uc_engine* uc = open_engine("p10b");
    if (uc == nullptr || !map_basic(uc)) {
        return false;
    }
    if (!map_region(uc, kExtra, kPage, UC_PROT_ALL, "extra")) {
        return false;
    }

    Assembler main(kCode);
    main.mov(0, 0x10);
    const uint64_t hook_pc = main.pc();
    main.mov(1, 0x11); // must be skipped
    const size_t b_done = main.b_placeholder();
    const size_t done_label = main.label();
    main.nop();
    main.b(main.addr_of(done_label));
    main.patch_branch(b_done, main.addr_of(done_label));
    const uint64_t done = main.addr_of(done_label);
    load_code(uc, main);

    Assembler extra(kExtra);
    extra.mov(4, 0x44);
    extra.b(done);
    const uc_err write_err =
        uc_mem_write(uc, kExtra, extra.words().data(),
                     extra.size() * sizeof(uint32_t));
    if (write_err != UC_ERR_OK) {
        std::printf("  write extra page failed: %s\n", uc_strerror(write_err));
        ++g_failures;
        return false;
    }

    HookTraceCtx ctx;
    ctx.hook_address = hook_pc;
    ctx.redirect_to = kExtra;
    if (!add_trace_hooks(uc, &ctx, hook_pc, hook_pc + 4)) {
        return false;
    }

    const uc_err err = uc_emu_start(uc, kCode, done, kProbeTimeoutUs, 0);
    const uint64_t x1 = read_reg(uc, UC_ARM64_REG_X1);
    const uint64_t x4 = read_reg(uc, UC_ARM64_REG_X4);
    const uint64_t pc = read_reg(uc, UC_ARM64_REG_PC);

    std::printf("  -- cross-page redirect --\n");
    show_err("uc_emu_start", err);
    show_u64("x1 (must stay 0)", x1);
    show_u64("x4 (must be 0x44)", x4);
    show_u64("PC after run", pc);
    print_trace_events(ctx);

    const bool ok = x1 == 0 && x4 == 0x44;
    expect(ok, "code hook PC write redirects execution (other page)");
    uc_close(uc);
    return true;
}

bool probe10() {
    std::printf("\n== Probe 10: UC_HOOK_CODE writes PC (redirect) ==\n");
    probe10_redirect_same_block();
    probe10_redirect_other_page();
    return true;
}

bool probe11() {
    std::printf("\n== Probe 11: code/mem/intr order; SVC replay on resume ==\n");
    uc_engine* uc = open_engine("p11");
    if (uc == nullptr || !map_basic(uc)) {
        return false;
    }

    uint64_t initial = 0x1122334455667788ULL;
    uc_mem_write(uc, kData, &initial, sizeof(initial));

    Assembler a(kCode);
    a.mov(0, kData);
    a.mov(8, 39); // getpid
    const uint64_t ldr_pc = a.pc();
    a.ldr_x(1, 0, 0);
    const uint64_t str_pc = a.pc();
    a.str_x(2, 0, 8);
    const uint64_t svc_pc = a.pc();
    a.svc(0);
    const size_t b_done = a.b_placeholder();
    const size_t done_label = a.label();
    a.nop();
    a.b(a.addr_of(done_label));
    a.patch_branch(b_done, a.addr_of(done_label));
    const uint64_t done = a.addr_of(done_label);
    load_code(uc, a);

    HookTraceCtx ctx;
    if (!add_trace_hooks(uc, &ctx, kCode, done)) {
        return false;
    }

    const uc_err err = uc_emu_start(uc, kCode, done, kProbeTimeoutUs, 0);
    const uint64_t x1 = read_reg(uc, UC_ARM64_REG_X1);

    std::printf("  -- normal run --\n");
    show_err("uc_emu_start", err);
    show_u64("x1 (loaded value)", x1);
    print_trace_events(ctx);

    const int ldr_index = index_of_event(ctx, TraceEventKind::Code, ldr_pc);
    const int read_index = index_of_event(ctx, TraceEventKind::MemRead, kData);
    const int str_index = index_of_event(ctx, TraceEventKind::Code, str_pc);
    const int write_index = index_of_event(ctx, TraceEventKind::MemWrite, kData + 8);
    const int svc_code_hits = count_events(ctx, TraceEventKind::Code, svc_pc);
    const int intr_hits = count_events(ctx, TraceEventKind::Intr, svc_pc + 4);

    expect_u64("x1 == loaded memory", x1, 0x1122334455667788ULL);
    expect(ldr_index >= 0 && read_index >= 0 && ldr_index < read_index,
           "code hook runs before the instruction's memory read");
    expect(str_index >= 0 && write_index >= 0 && str_index < write_index,
           "code hook runs before the instruction's memory write");
    expect_u64("intr hook hit once", static_cast<uint64_t>(intr_hits), 1);
    show_u64("code hook hits at the SVC address", static_cast<uint64_t>(svc_code_hits));

    // Stop inside the intr handler, then resume from svc + 4. The SVC must not
    // be replayed: a replayed SVC would show up as a second code hook hit at
    // svc_pc or a second intr hit.
    HookTraceCtx resumed;
    resumed.stop_on_intr = true;
    uc_engine* uc2 = open_engine("p11-resume");
    if (uc2 == nullptr || !map_basic(uc2)) {
        return false;
    }
    uc_mem_write(uc2, kData, &initial, sizeof(initial));
    load_code(uc2, a);
    if (!add_trace_hooks(uc2, &resumed, kCode, done)) {
        return false;
    }

    const uc_err first_err = uc_emu_start(uc2, kCode, done, kProbeTimeoutUs, 0);
    const uint64_t pc_after_stop = read_reg(uc2, UC_ARM64_REG_PC);
    const uc_err resume_err =
        uc_emu_start(uc2, pc_after_stop, done, kProbeTimeoutUs, 0);

    std::printf("  -- stop in intr + resume --\n");
    show_err("first uc_emu_start", first_err);
    show_u64("PC after stop", pc_after_stop);
    show_u64("svc + 4", svc_pc + 4);
    show_err("resume uc_emu_start", resume_err);
    print_trace_events(resumed);

    expect_u64("stop lands on svc + 4", pc_after_stop, svc_pc + 4);
    expect_u64("intr fired once across stop/resume",
               static_cast<uint64_t>(count_events(resumed, TraceEventKind::Intr,
                                                  svc_pc + 4)),
               1);
    expect_u64("SVC code hook not replayed on resume",
               static_cast<uint64_t>(count_events(resumed, TraceEventKind::Code,
                                                  svc_pc)),
               static_cast<uint64_t>(svc_code_hits));

    uc_close(uc2);
    uc_close(uc);
    return true;
}

// ---------------------------------------------------------------------------
// Probe 12 (M9): debugger stop semantics.
//   A) uc_emu_stop from a code hook: does the hooked instruction execute?
//   B) BRK #0: which error, which PC, does UC_HOOK_INTR fire?
//   C) Instruction count: does count = 1 execute exactly one instruction?
// ---------------------------------------------------------------------------
struct StopCtx {
    int code_hits = 0;
    int intr_hits = 0;
    uint32_t last_intr = 0;
    uint64_t stop_address = 0;
};

void on_stop_code(uc_engine* uc, uint64_t address, uint32_t /*size*/, void* user_data) {
    auto* ctx = static_cast<StopCtx*>(user_data);
    ++ctx->code_hits;
    if (ctx->stop_address != 0 && address == ctx->stop_address) {
        uc_emu_stop(uc);
    }
}

void on_stop_intr(uc_engine* uc, uint32_t intno, void* user_data) {
    (void)uc;
    auto* ctx = static_cast<StopCtx*>(user_data);
    ++ctx->intr_hits;
    ctx->last_intr = intno;
}

void write_program(uc_engine* uc, const Assembler& a) {
    uc_mem_write(uc, kCode, a.words().data(), a.words().size() * sizeof(uint32_t));
}

bool probe12_stop_from_code_hook() {
    std::printf("\n== Probe 12A: uc_emu_stop from a code hook ==\n");
    uc_engine* uc = open_engine("p12a");
    if (uc == nullptr || !map_basic(uc)) {
        return false;
    }
    Assembler a(kCode);
    a.mov(0, 0x10);
    const uint64_t bp = a.pc();
    a.mov(1, 0x11); // hooked instruction
    a.mov(2, 0x12);
    write_program(uc, a);

    StopCtx ctx;
    ctx.stop_address = bp;
    uc_hook hook = 0;
    uc_hook_add(uc, &hook, UC_HOOK_CODE, reinterpret_cast<void*>(&on_stop_code), &ctx, bp, bp);
    const uc_err err = uc_emu_start(uc, kCode, 0, 0, 0);
    const uint64_t pc = read_reg(uc, UC_ARM64_REG_PC);
    const uint64_t x1 = read_reg(uc, UC_ARM64_REG_X1);
    show_err("run error", err);
    show_u64("bp address", bp);
    show_u64("PC after stop", pc);
    show_u64("x1 after stop (0x11 => instruction executed)", x1);
    std::printf("  %-46s %s\n", "PC == bp (stopped before execution)",
                pc == bp ? "YES" : "NO");
    std::printf("  %-46s %s\n", "PC == bp + 4 (stopped after execution)",
                pc == bp + 4 ? "YES" : "NO");
    uc_close(uc);
    return true;
}

bool probe12_brk() {
    std::printf("\n== Probe 12B: BRK #0 semantics ==\n");
    uc_engine* uc = open_engine("p12b");
    if (uc == nullptr || !map_basic(uc)) {
        return false;
    }
    Assembler a(kCode);
    a.mov(0, 0x10);
    const uint64_t brk_pc = a.pc();
    a.emit(0xD4200000u); // brk #0
    a.mov(2, 0x12);
    write_program(uc, a);

    StopCtx ctx;
    uc_hook intr = 0;
    uc_hook_add(uc, &intr, UC_HOOK_INTR, reinterpret_cast<void*>(&on_stop_intr), &ctx, 1, 0);
    // Bound the run with an instruction count: if Unicorn does not consume the
    // BRK exception it can retry the same PC forever.
    const uc_err err = uc_emu_start(uc, kCode, 0, 0, 1000);
    const uint64_t pc = read_reg(uc, UC_ARM64_REG_PC);
    const uint64_t x2 = read_reg(uc, UC_ARM64_REG_X2);
    show_err("run error", err);
    show_u64("BRK address", brk_pc);
    show_u64("PC after BRK", pc);
    show_u64("x2 (0x12 => BRK skipped the rest)", x2);
    std::printf("  %-46s %d (last intno %u)\n", "UC_HOOK_INTR hits", ctx.intr_hits,
                ctx.last_intr);
    std::printf("  %-46s %s\n", "PC stuck on BRK",
                pc == brk_pc ? "YES" : "NO");
    uc_close(uc);
    return true;
}

bool probe12_count() {
    std::printf("\n== Probe 12C: uc_emu_start count = 1 ==\n");
    uc_engine* uc = open_engine("p12c");
    if (uc == nullptr || !map_basic(uc)) {
        return false;
    }
    Assembler a(kCode);
    a.mov(0, 0x10);
    a.mov(1, 0x11);
    a.mov(2, 0x12);
    write_program(uc, a);

    uc_err err = uc_emu_start(uc, kCode, 0, 0, 1);
    show_err("first count=1", err);
    expect_u64("after 1 instruction: pc", read_reg(uc, UC_ARM64_REG_PC), kCode + 4);
    expect_u64("after 1 instruction: x0", read_reg(uc, UC_ARM64_REG_X0), 0x10);
    expect_u64("after 1 instruction: x1", read_reg(uc, UC_ARM64_REG_X1), 0);

    err = uc_emu_start(uc, read_reg(uc, UC_ARM64_REG_PC), 0, 0, 1);
    show_err("second count=1", err);
    expect_u64("after 2 instructions: pc", read_reg(uc, UC_ARM64_REG_PC), kCode + 8);
    expect_u64("after 2 instructions: x1", read_reg(uc, UC_ARM64_REG_X1), 0x11);
    uc_close(uc);
    return true;
}

// Does an installed code hook change what count = 1 means? The debugger
// always has a hook exactly at the instruction it is stepping over.
bool probe12_count_with_hook() {
    std::printf("\n== Probe 12D: count = 1 with a code hook at the same address ==\n");
    uc_engine* uc = open_engine("p12d");
    if (uc == nullptr || !map_basic(uc)) {
        return false;
    }
    Assembler a(kCode);
    a.mov(0, 0x10);
    const uint64_t hooked = a.pc();
    a.mov(1, 0x11);
    a.mov(2, 0x12);
    write_program(uc, a);

    StopCtx ctx; // stop_address == 0: the hook never stops
    uc_hook hook = 0;
    uc_hook_add(uc, &hook, UC_HOOK_CODE, reinterpret_cast<void*>(&on_stop_code), &ctx,
                hooked, hooked);
    uc_err err = uc_emu_start(uc, kCode, 0, 0, 2); // two instructions: mov, mov
    show_err("run count=2 with hook", err);
    show_u64("pc after count=2", read_reg(uc, UC_ARM64_REG_PC));
    show_u64("x0", read_reg(uc, UC_ARM64_REG_X0));
    show_u64("x1", read_reg(uc, UC_ARM64_REG_X1));
    show_u64("x2", read_reg(uc, UC_ARM64_REG_X2));
    std::printf("  %-46s %s\n", "hook fired", ctx.code_hits ? "YES" : "NO");
    uc_close(uc);
    return true;
}

// Decisive case for the real debugger: hook exactly at the instruction we
// start from, then count = 1.
bool probe12_count_hook_at_start() {
    std::printf("\n== Probe 12E: count = 1, hook at the first instruction ==\n");
    uc_engine* uc = open_engine("p12e");
    if (uc == nullptr || !map_basic(uc)) {
        return false;
    }
    Assembler a(kCode);
    a.mov(0, 0x10);
    a.mov(1, 0x11);
    a.mov(2, 0x12);
    write_program(uc, a);

    StopCtx ctx;
    uc_hook hook = 0;
    uc_hook_add(uc, &hook, UC_HOOK_CODE, reinterpret_cast<void*>(&on_stop_code), &ctx,
                kCode, kCode);
    const uc_err err = uc_emu_start(uc, kCode, 0, 0, 1);
    show_err("run count=1", err);
    show_u64("pc", read_reg(uc, UC_ARM64_REG_PC));
    show_u64("x0", read_reg(uc, UC_ARM64_REG_X0));
    show_u64("x1", read_reg(uc, UC_ARM64_REG_X1));
    show_u64("x2", read_reg(uc, UC_ARM64_REG_X2));
    std::printf("  %-46s %s\n", "exactly one instruction",
                read_reg(uc, UC_ARM64_REG_PC) == kCode + 4 ? "YES" : "NO");
    uc_close(uc);
    return true;
}

bool probe12() {
    probe12_stop_from_code_hook();
    probe12_brk();
    probe12_count();
    probe12_count_with_hook();
    probe12_count_hook_at_start();
    return true;
}

// ---------------------------------------------------------------------------
// Runner
// ---------------------------------------------------------------------------
struct Probe {
    int number;
    const char* name;
    bool (*run)();
};

const Probe kProbes[] = {
    {1, "svc -> UC_HOOK_INTR/intno", &probe1},
    {2, "PC == svc + 4 in hook", &probe2},
    {3, "write x0 without touching PC", &probe3},
    {4, "stop and resume from svc + 4", &probe4},
    {5, "mrs tpidr_el0", &probe5},
    {6, "nested uc_emu_start", &probe6},
    {7, "two engines + map_ptr", &probe7},
    {8, "map_ptr + per-engine permissions", &probe8},
    {9, "cross-thread stop + paused engine", &probe9},
    {10, "code hook writes PC (redirect)", &probe10},
    {11, "code/mem/intr order + SVC replay", &probe11},
    {12, "debugger stop / BRK / count=1", &probe12},
};

} // namespace

int main(int argc, char** argv) {
    std::setvbuf(stdout, nullptr, _IONBF, 0);

    const std::string which = argc > 1 ? argv[1] : "all";

    std::printf("Unicorn probe spike: build=%s %s, arch=UC_ARCH_ARM64\n", __DATE__,
                __TIME__);

    for (const Probe& probe : kProbes) {
        const bool selected = which == "all" || std::to_string(probe.number) == which;
        if (!selected) {
            continue;
        }
        probe.run();
    }

    std::printf("\nSummary: failures=%d\n", g_failures);
    return g_failures;
}

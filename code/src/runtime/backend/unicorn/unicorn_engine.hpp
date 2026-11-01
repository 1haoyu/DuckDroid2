// SPDX-License-Identifier: GPL-2.0-only
#pragma once

#include <cstddef>
#include <functional>
#include <memory>

#include <unicorn/unicorn.h>

#include "common/error/result.hpp"
#include "runtime/memory/region.hpp"
#include "runtime/observer/diagnostic/diagnostic_event.hpp"

namespace duckemu::runtime
{

struct RunOutcome
{
	uc_err err = UC_ERR_OK;
	uint64_t pc = 0;
};

// One guest CPU: one uc_engine. A UnicornEngine belongs to exactly one
// RuntimeThread. Only its owning host thread runs it; the instance execution
// lock guarantees that no two engines execute guest code at the same time.
class UnicornEngine
{
    public:
	using SvcTrapHandler = std::function<void(uc_engine *, uint32_t)>;
	using DiagnosticSink = std::function<void(const observer::DiagnosticEvent &)>;
	using CodeWriteSink = std::function<void(GuestVA, uint64_t)>;
	using RunEndSink = std::function<void(uc_engine *)>;

	using CodeHookCallback = void (*)(uc_engine *, uint64_t, uint32_t, void *);
	using MemoryHookCallback = bool (*)(uc_engine *, uc_mem_type, uint64_t, int, int64_t, void *);

	static Result<std::unique_ptr<UnicornEngine> > create();
	~UnicornEngine();

	UnicornEngine(const UnicornEngine &) = delete;
	UnicornEngine &operator=(const UnicornEngine &) = delete;
	UnicornEngine(UnicornEngine &&) = delete;
	UnicornEngine &operator=(UnicornEngine &&) = delete;

	[[nodiscard]] uc_engine *handle() const
	{
		return engine_;
	}

	// Handler for every UC_HOOK_INTR on this engine (SVC dispatch).
	void setSvcTrapHandler(SvcTrapHandler handler);

	// Optional diagnostic feed. Installing a non-empty sink adds the read/write
	// hooks; an empty sink disables the data path but leaves the hook installed.
	void setDiagnosticSink(DiagnosticSink sink);

	// Guest wrote to memory. The sink runs on the emulating thread and is
	// expected to invalidate translated code in every engine of the instance.
	void setCodeWriteSink(CodeWriteSink sink);

	// Called after every uc_emu_start returns, before the caller inspects the
	// engine. The trace uses it to flush the last instruction's POST values.
	void setRunEndSink(RunEndSink sink);

	// Generic hook installation used by UnicornBackend for instruction tracing
	// and address hooks. The callback and user_data are passed to Unicorn
	// verbatim; the caller owns the user_data lifetime.
	Result<uc_hook> addCodeHook(uint64_t begin, uint64_t end, CodeHookCallback callback, void *user_data);
	Result<uc_hook> addMemoryHook(uint32_t type, MemoryHookCallback callback, void *user_data);
	Result<void> removeHook(uc_hook hook);

	// Runs guest code until `until`, a stop request, a timeout or a fault.
	// `until == 0` means "no end address"; the thread only leaves through an
	// SVC handler, a fault or a stop request. `count == 0` means "no
	// instruction budget"; a count of 1 is the debugger's single-step.
	Result<RunOutcome> run(GuestVA begin, GuestVA until, uint64_t timeout_us, size_t count = 0);
	void stop();

	Result<uint64_t> readRegister(int reg) const;
	Result<void> writeRegister(int reg, uint64_t value);

	void invalidateCode(GuestVA address, uint64_t size);

	// Region mirroring. The backend drives these for every engine so all CPUs
	// of an instance share one address-space view.
	Result<void> mapRegion(const Region &region);
	Result<void> unmapRegion(GuestVA address, uint64_t size);
	Result<void> protectRegion(GuestVA address, uint64_t size, uint32_t perms);

	// Whole CPU context (PC/GPR/SP and CP registers). Clone saves the parent
	// and restores the child; both engines are the same arch, so the context
	// is portable between them. Not a substitute for save/restore around a
	// nested uc_emu_start (M0 probe 6 / M2 decision) -- that still needs the
	// full save-run-restore sequence.
	class SavedContext
	{
	    public:
		~SavedContext();
		SavedContext(const SavedContext &) = delete;
		SavedContext &operator=(const SavedContext &) = delete;

	    private:
		friend class UnicornEngine;
		explicit SavedContext(uc_context *context);
		uc_context *context_ = nullptr;
	};

	Result<std::unique_ptr<SavedContext> > saveContext();
	Result<void> restoreContext(const SavedContext &context);

    private:
	explicit UnicornEngine(uc_engine *engine);

	static void onIntr(uc_engine *uc, uint32_t intno, void *user_data);
	static bool
	onMemWrite(uc_engine *uc, uc_mem_type type, uint64_t address, int size, int64_t value, void *user_data);
	static bool
	onDiagnosticAccess(uc_engine *uc, uc_mem_type type, uint64_t address, int size, int64_t value, void *user_data);
	// Fault diagnostics: Unicorn only reports UC_ERR_*_UNMAPPED, without the
	// address that caused it. Log pc/address before stopping.
	static bool
	onUnmappedAccess(uc_engine *uc, uc_mem_type type, uint64_t address, int size, int64_t value, void *user_data);

	uc_engine *engine_ = nullptr;
	SvcTrapHandler svc_handler_;
	DiagnosticSink diagnostic_sink_;
	CodeWriteSink code_write_sink_;
	RunEndSink run_end_sink_;
	uc_hook intr_hook_ = 0;
	uc_hook mem_write_hook_ = 0;
	uc_hook diagnostic_hook_ = 0;
	uc_hook unmapped_hook_ = 0;
};

} // namespace duckemu::runtime

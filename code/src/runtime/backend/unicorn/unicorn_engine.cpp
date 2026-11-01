// SPDX-License-Identifier: GPL-2.0-only
#include "runtime/backend/unicorn/unicorn_engine.hpp"

#include <cstdio>
#include <utility>

#include "common/log/logger.hpp"

namespace duckemu::runtime
{
namespace
{

Error unicornError(uc_err err, const char *what)
{
	return Error{ ErrorCode::EmulationFault, std::string(what) + ": " + uc_strerror(err) };
}

} // namespace

UnicornEngine::UnicornEngine(uc_engine *engine)
	: engine_(engine)
{
}

UnicornEngine::~UnicornEngine()
{
	if (engine_ != nullptr)
	{
		uc_close(engine_);
	}
}

Result<std::unique_ptr<UnicornEngine> > UnicornEngine::create()
{
	uc_engine *engine = nullptr;
	const uc_err open_err = uc_open(UC_ARCH_ARM64, UC_MODE_ARM, &engine);
	if (open_err != UC_ERR_OK)
	{
		return unicornError(open_err, "uc_open");
	}

	// Unicorn's default AArch64 model (cortex-a72) does not advertise FEAT_LSE,
	// so the ROM's libc dies on its first `ldaprb` with an undefined-instruction
	// trap. `max` advertises ATOMIC (LSE) in ID_AA64ISAR0; guest-visible HWCAP
	// still comes from our IFUNC/auxv values, which stay 0.
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wold-style-cast"
#endif
	const uc_err model_err = uc_ctl_set_cpu_model(engine, UC_CPU_ARM64_MAX);
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic pop
#endif
	if (model_err != UC_ERR_OK)
	{
		uc_close(engine);
		return unicornError(model_err, "uc_ctl_set_cpu_model");
	}

	// M0 measured Unicorn's default ARM64 page size as 0x400 (TARGET_PAGE_BITS_MIN
	// = 10). Android's guest pages are 4 KiB; align the emulator with that
	// before the engine is initialized by the first map/run.
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wold-style-cast"
#endif
	const uc_err page_err = uc_ctl_set_page_size(engine, static_cast<uint32_t>(kGuestPageSize));
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic pop
#endif
	if (page_err != UC_ERR_OK)
	{
		uc_close(engine);
		return unicornError(page_err, "uc_ctl_set_page_size");
	}

	std::unique_ptr<UnicornEngine> self(new UnicornEngine(engine));

	const uc_err intr_err = uc_hook_add(engine,
		&self->intr_hook_,
		UC_HOOK_INTR,
		reinterpret_cast<void *>(&UnicornEngine::onIntr),
		self.get(),
		1,
		0);
	if (intr_err != UC_ERR_OK)
	{
		return unicornError(intr_err, "uc_hook_add(UC_HOOK_INTR)");
	}

	const uc_err write_err = uc_hook_add(engine,
		&self->mem_write_hook_,
		UC_HOOK_MEM_WRITE,
		reinterpret_cast<void *>(&UnicornEngine::onMemWrite),
		self.get(),
		1,
		0);
	if (write_err != UC_ERR_OK)
	{
		return unicornError(write_err, "uc_hook_add(UC_HOOK_MEM_WRITE)");
	}

	const uc_err unmapped_err = uc_hook_add(engine,
		&self->unmapped_hook_,
		UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED | UC_HOOK_MEM_FETCH_UNMAPPED,
		reinterpret_cast<void *>(&UnicornEngine::onUnmappedAccess),
		self.get(),
		1,
		0);
	if (unmapped_err != UC_ERR_OK)
	{
		return unicornError(unmapped_err, "uc_hook_add(unmapped)");
	}

	return self;
}

bool UnicornEngine::onUnmappedAccess(uc_engine *uc,
	uc_mem_type type,
	uint64_t address,
	int size,
	int64_t value,
	void *user_data)
{
	(void)value;
	(void)user_data;
	uint64_t pc = 0;
	(void)uc_reg_read(uc, UC_ARM64_REG_PC, &pc);
	const char *kind = type == UC_MEM_WRITE_UNMAPPED ? "write" :
				  type == UC_MEM_READ_UNMAPPED  ? "read" :
								  "fetch";
	char registers[416];
	size_t used = 0;
	for (int index = 0; index <= 28 && used < sizeof(registers); ++index)
	{
		uint64_t register_value = 0;
		if (uc_reg_read(uc, static_cast<uc_arm64_reg>(UC_ARM64_REG_X0 + index),
			    &register_value) != UC_ERR_OK)
		{
			break;
		}
		const int written = std::snprintf(registers + used, sizeof(registers) - used,
			"%s x%d=0x%llx", index == 0 ? "" : ",", index,
			static_cast<unsigned long long>(register_value));
		if (written <= 0)
		{
			break;
		}
		used += static_cast<size_t>(written);
	}
	DUCKEMU_ERROR("guest %s unmapped: address=0x%llx size=%d pc=0x%llx%s%s",
		kind,
		static_cast<unsigned long long>(address),
		size,
		static_cast<unsigned long long>(pc),
		used != 0 ? "\n  " : "",
		registers);
	return false;
}

void UnicornEngine::setSvcTrapHandler(SvcTrapHandler handler)
{
	svc_handler_ = std::move(handler);
}

void UnicornEngine::setDiagnosticSink(DiagnosticSink sink)
{
	diagnostic_sink_ = std::move(sink);
	if (!diagnostic_sink_ || diagnostic_hook_ != 0)
	{
		return;
	}

	const uc_err err = uc_hook_add(engine_,
		&diagnostic_hook_,
		UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE,
		reinterpret_cast<void *>(&UnicornEngine::onDiagnosticAccess),
		this,
		1,
		0);
	if (err != UC_ERR_OK)
	{
		DUCKEMU_WARN("uc_hook_add(UC_HOOK_MEM_READ|UC_HOOK_MEM_WRITE) failed: %s", uc_strerror(err));
	}
}

void UnicornEngine::setCodeWriteSink(CodeWriteSink sink)
{
	code_write_sink_ = std::move(sink);
}

void UnicornEngine::setRunEndSink(RunEndSink sink)
{
	run_end_sink_ = std::move(sink);
}

Result<uc_hook> UnicornEngine::addCodeHook(uint64_t begin,
	uint64_t end,
	CodeHookCallback callback,
	void *user_data)
{
	uc_hook hook = 0;
	const uc_err err = uc_hook_add(engine_,
		&hook,
		UC_HOOK_CODE,
		reinterpret_cast<void *>(callback),
		user_data,
		begin,
		end);
	if (err != UC_ERR_OK)
	{
		return unicornError(err, "uc_hook_add(UC_HOOK_CODE)");
	}
	return hook;
}

Result<uc_hook> UnicornEngine::addMemoryHook(uint32_t type, MemoryHookCallback callback, void *user_data)
{
	uc_hook hook = 0;
	const uc_err err = uc_hook_add(engine_,
		&hook,
		static_cast<int>(type),
		reinterpret_cast<void *>(callback),
		user_data,
		1,
		0);
	if (err != UC_ERR_OK)
	{
		return unicornError(err, "uc_hook_add(memory)");
	}
	return hook;
}

Result<void> UnicornEngine::removeHook(uc_hook hook)
{
	if (hook == 0)
	{
		return {};
	}
	const uc_err err = uc_hook_del(engine_, hook);
	if (err != UC_ERR_OK)
	{
		return unicornError(err, "uc_hook_del");
	}
	return {};
}

Result<RunOutcome> UnicornEngine::run(GuestVA begin, GuestVA until, uint64_t timeout_us, size_t count)
{
	// uc_emu_start installs its instruction-count hook lazily and does not
	// flush the TB cache when it does (uc.c:1202). A TB translated by an
	// earlier count = 0 run therefore keeps running to its end and ignores the
	// budget. Drop the page before a counted run so the TB is re-translated
	// with the count hook in place. (Observed as a libeleven single-step
	// jumping from the entry to the end of the function.)
	if (count != 0)
	{
		invalidateCode(begin, 4);
	}
	RunOutcome outcome;
	outcome.err = uc_emu_start(engine_, begin.value(), until.value(), timeout_us, count);
	if (run_end_sink_)
	{
		try
		{
			run_end_sink_(engine_);
		}
		catch (...)
		{
			DUCKEMU_ERROR("run-end sink threw; ignored");
		}
	}
	auto pc = readRegister(UC_ARM64_REG_PC);
	if (!pc.ok())
	{
		return pc.error();
	}
	outcome.pc = pc.value();
	return outcome;
}

void UnicornEngine::stop()
{
	uc_emu_stop(engine_);
}

Result<uint64_t> UnicornEngine::readRegister(int reg) const
{
	uint64_t value = 0;
	const uc_err err = uc_reg_read(engine_, reg, &value);
	if (err != UC_ERR_OK)
	{
		return unicornError(err, "uc_reg_read");
	}
	return value;
}

Result<void> UnicornEngine::writeRegister(int reg, uint64_t value)
{
	const uc_err err = uc_reg_write(engine_, reg, &value);
	if (err != UC_ERR_OK)
	{
		return unicornError(err, "uc_reg_write");
	}
	return {};
}

void UnicornEngine::invalidateCode(GuestVA address, uint64_t size)
{
	if (size == 0)
	{
		return;
	}
	const uint64_t start = pageDown(address.value());
	const uint64_t end = pageUp(address.value() + size);
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wold-style-cast"
#endif
	const uc_err err = uc_ctl_remove_cache(engine_, start, end);
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic pop
#endif
	if (err != UC_ERR_OK)
	{
		DUCKEMU_WARN("uc_ctl_remove_cache(0x%llx, 0x%llx) failed: %s",
			static_cast<unsigned long long>(start),
			static_cast<unsigned long long>(end),
			uc_strerror(err));
	}
}

Result<void> UnicornEngine::mapRegion(const Region &region)
{
	const uint64_t base = region.base.value();
	const uc_err err = uc_mem_map_ptr(engine_, base, region.size, region.perms, region.hostPtr());
	if (err != UC_ERR_OK)
	{
		return unicornError(err, "uc_mem_map_ptr");
	}

	// Unicorn has no AArch64 TBI. Scudo tags heap pointers in the top byte, so
	// mirror arena mappings at tag 1 and 2 over the same host pages.
	if (!inAnonymousArena(base))
	{
		return {};
	}
	for (uint64_t tag = 1; tag <= 2; ++tag)
	{
		const uint64_t alias = taggedAlias(base, tag);
		const uc_err alias_err =
			uc_mem_map_ptr(engine_, alias, region.size, region.perms, region.hostPtr());
		if (alias_err != UC_ERR_OK)
		{
			(void)uc_mem_unmap(engine_, base, region.size);
			return unicornError(alias_err, "uc_mem_map_ptr(alias)");
		}
	}
	return {};
}

Result<void> UnicornEngine::unmapRegion(GuestVA address, uint64_t size)
{
	const uint64_t base = untagAddress(address.value());
	const uc_err err = uc_mem_unmap(engine_, base, size);
	if (err != UC_ERR_OK)
	{
		return unicornError(err, "uc_mem_unmap");
	}
	if (inAnonymousArena(base))
	{
		for (uint64_t tag = 1; tag <= 2; ++tag)
		{
			(void)uc_mem_unmap(engine_, taggedAlias(base, tag), size);
		}
	}
	return {};
}

Result<void> UnicornEngine::protectRegion(GuestVA address, uint64_t size, uint32_t perms)
{
	const uint64_t base = untagAddress(address.value());
	const uc_err err = uc_mem_protect(engine_, base, size, perms);
	if (err != UC_ERR_OK)
	{
		return unicornError(err, "uc_mem_protect");
	}
	if (inAnonymousArena(base))
	{
		for (uint64_t tag = 1; tag <= 2; ++tag)
		{
			(void)uc_mem_protect(engine_, taggedAlias(base, tag), size, perms);
		}
	}
	return {};
}

UnicornEngine::SavedContext::SavedContext(uc_context *context)
	: context_(context)
{
}

UnicornEngine::SavedContext::~SavedContext()
{
	if (context_ != nullptr)
	{
		uc_free(context_);
	}
}

Result<std::unique_ptr<UnicornEngine::SavedContext> > UnicornEngine::saveContext()
{
	uc_context *context = nullptr;
	const uc_err alloc_err = uc_context_alloc(engine_, &context);
	if (alloc_err != UC_ERR_OK)
	{
		return unicornError(alloc_err, "uc_context_alloc");
	}

	std::unique_ptr<SavedContext> saved(new SavedContext(context));
	const uc_err save_err = uc_context_save(engine_, context);
	if (save_err != UC_ERR_OK)
	{
		return unicornError(save_err, "uc_context_save");
	}
	return saved;
}

Result<void> UnicornEngine::restoreContext(const SavedContext &context)
{
	const uc_err err = uc_context_restore(engine_, context.context_);
	if (err != UC_ERR_OK)
	{
		return unicornError(err, "uc_context_restore");
	}
	return {};
}

} // namespace duckemu::runtime

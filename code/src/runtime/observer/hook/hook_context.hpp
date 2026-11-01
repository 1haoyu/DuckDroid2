// SPDX-License-Identifier: GPL-2.0-only
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <vector>

#include "common/error/result.hpp"

namespace duckemu::runtime
{
class RuntimeMemory;
class UnicornBackend;
namespace observer
{

// The callback's view of one address-hook hit. It is valid only for the
// duration of the callback: the engine is mid-run, and the instance execution
// lock is held.
//
// The hook fires before the instruction at `address` executes. Register and
// memory writes take effect immediately; setPc() redirects execution (the
// trace then skips this instruction).
class HookContext
{
    public:
	HookContext(const HookContext &) = delete;
	HookContext &operator=(const HookContext &) = delete;
	HookContext(HookContext &&) = delete;
	HookContext &operator=(HookContext &&) = delete;

	[[nodiscard]] uint32_t tid() const noexcept
	{
		return tid_;
	}
	[[nodiscard]] uint64_t address() const noexcept
	{
		return address_;
	}
	[[nodiscard]] uint64_t hitCount() const noexcept
	{
		return hit_count_;
	}
	[[nodiscard]] uint64_t lr() const noexcept
	{
		return lr_;
	}
	[[nodiscard]] uint64_t sp() const noexcept
	{
		return sp_;
	}
	// Entry-time snapshot of x0..x7.
	[[nodiscard]] uint64_t x(int index) const noexcept;

	// Live register access. readX/writeX use X0..X30 (X29 = FP, X30 = LR);
	// readW/writeW use W0..W30 and truncate to 32 bits.
	[[nodiscard]] uint64_t readX(int index) const;
	void writeX(int index, uint64_t value);
	[[nodiscard]] uint32_t readW(int index) const;
	void writeW(int index, uint32_t value);
	[[nodiscard]] uint64_t readSp() const;
	void writeSp(uint64_t value);

	// Permission-checked guest memory access (PermRead / PermWrite).
	[[nodiscard]] Result<std::vector<uint8_t> > readMemory(uint64_t address, size_t size) const;
	[[nodiscard]] Result<void> writeMemory(uint64_t address, const void *data, size_t size);
	// Bypasses guest permissions but still requires the range to be mapped.
	// This is the fault-injection path for .rodata tables.
	[[nodiscard]] Result<void> forceWriteMemory(uint64_t address, const void *data, size_t size);

	// Writes PC. Returns an error if Unicorn rejects the register write.
	[[nodiscard]] Result<void> setPc(uint64_t address);

	// Stops the current uc_emu_start. Probe 12A: the instruction at `address`
	// does not execute, so this is a genuine pre-instruction breakpoint. The
	// scheduler parks the thread and hands control to the debugger.
	void requestStop();

    private:
	friend class ::duckemu::runtime::UnicornBackend;

	HookContext(void *engine,
		RuntimeMemory *memory,
		uint32_t tid,
		uint64_t address,
		uint64_t hit_count,
		const std::array<uint64_t, 8> &x,
		uint64_t lr,
		uint64_t sp)
		: engine_(engine)
		, memory_(memory)
		, tid_(tid)
		, address_(address)
		, hit_count_(hit_count)
		, x_(x)
		, lr_(lr)
		, sp_(sp)
	{
	}

	void *engine_ = nullptr;
	RuntimeMemory *memory_ = nullptr;
	uint32_t tid_ = 0;
	uint64_t address_ = 0;
	uint64_t hit_count_ = 0;
	std::array<uint64_t, 8> x_{};
	uint64_t lr_ = 0;
	uint64_t sp_ = 0;
};

using AddressHook = std::function<void(HookContext &)>;

} // namespace observer
} // namespace duckemu::runtime

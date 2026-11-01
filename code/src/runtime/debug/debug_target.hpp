// SPDX-License-Identifier: GPL-2.0-only
#pragma once

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

#include "common/error/result.hpp"

namespace duckemu::runtime::debug
{

struct ModuleInfo
{
	std::string path;
	std::string soname;
	uint64_t base = 0;
	uint64_t span = 0;
	bool is_virtual = false;
};

struct ThreadInfo
{
	uint32_t tid = 0;
	std::string state;
	uint64_t pc = 0;
};

struct Options
{
	uint16_t port = 31337;
};

// Narrow view of one RuntimeInstance for the RSP server. Implemented by
// RuntimeInstance::Impl so the facade does not grow getMemory()/getThreads().
class Target
{
    public:
	Target() = default;
	Target(const Target &) = delete;
	Target &operator=(const Target &) = delete;
	virtual ~Target() = default;

	virtual Result<void> readMemory(uint64_t address, void *out, uint64_t size) = 0;
	virtual Result<void> writeMemory(uint64_t address, const void *in, uint64_t size) = 0;
	virtual std::vector<ModuleInfo> modules() const = 0;
	virtual std::vector<ThreadInfo> threads() = 0;

	// Pre-instruction stop at `address`. `on_hit` runs on the emulating
	// thread while the execution lock is held; it must not block. It returns
	// true to stop before the instruction (a real breakpoint hit) and false to
	// let the instruction run (the one-shot skip after a resume).
	virtual Result<uint32_t> addStopHook(uint64_t address,
		std::function<bool(uint32_t)> on_hit) = 0;
	virtual void removeStopHook(uint32_t id) = 0;
};

} // namespace duckemu::runtime::debug

// SPDX-License-Identifier: GPL-2.0-only
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

#include "runtime/device/device_profile.hpp"
#include "runtime/memory/address_space.hpp"

namespace duckemu::runtime
{
class RandomSource;
class RuntimeClock;
}

namespace duckemu::runtime::threads
{
class RuntimeThread;
class ThreadSystem;
}

namespace duckemu::runtime::vfs
{
class VirtualFileSystem;
}

namespace duckemu::runtime::svc
{

struct SyscallContext
{
	uint64_t args[6] = {};
	RuntimeMemory &memory;
	uint32_t pid = 0;
	uint32_t tid = 0;
	// The calling guest thread and the scheduler operations handlers may use.
	threads::RuntimeThread &thread;
	threads::ThreadSystem &threads;
	// Process-wide file namespace and descriptor table.
	vfs::VirtualFileSystem &vfs;
	// Instance-wide wall/monotonic clock; shared with Java System.
	RuntimeClock &clock;
	// Device identity (uname, getuid/prctl, ownership).
	const device::DeviceProfile &device;
	// Instance entropy stream shared with /dev/{u,}random.
	RandomSource &random;
	// Set by a handler that answers the call but skips part of its effect.
	// The dispatcher turns this into SvcSupport::Degraded; the reason travels
	// to svc.log so a target's fallback path is visible without reading code.
	bool degraded_flag = false;
	std::string degraded_reason{};

	void degrade(std::string_view reason)
	{
		degraded_flag = true;
		if (!reason.empty())
		{
			degraded_reason.assign(reason);
		}
	}
	[[nodiscard]] bool degraded() const noexcept
	{
		return degraded_flag;
	}
	[[nodiscard]] std::string_view degradedReason() const noexcept
	{
		return degraded_reason;
	}
};

// Each subsystem returns nullopt for "not my syscall"; the dispatcher then
// tries the next one and finally answers -ENOSYS.
std::optional<int64_t> handleMemorySyscall(SyscallContext &ctx, uint32_t number);
std::optional<int64_t> handleFsSyscall(SyscallContext &ctx, uint32_t number);
std::optional<int64_t> handleMiscSyscall(SyscallContext &ctx, uint32_t number);
std::optional<int64_t> handleThreadSyscall(SyscallContext &ctx, uint32_t number);
std::optional<int64_t> handleEventSyscall(SyscallContext &ctx, uint32_t number);

} // namespace duckemu::runtime::svc

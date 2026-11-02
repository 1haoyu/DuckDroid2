// SPDX-License-Identifier: GPL-2.0-only
#pragma once

// Shared driver for the M10 VFS gates: the ROM libc is loaded once and the
// host-side tables call it through guest memory exactly as a target would.
// Header-only so every gate executable owns its own copy of the trivial
// helpers.

#include <array>
#include <cstdint>
#include <cstring>
#include <string>
#include <string_view>
#include <vector>

#include "runtime/instance/runtime_instance.hpp"
#include "runtime/memory/region.hpp"
#include "support/test_harness.hpp"

namespace duckemu::test
{

namespace vfs
{

inline constexpr uint64_t kO_RdOnly = 0;
inline constexpr uint64_t kO_WrOnly = 1;
inline constexpr uint64_t kO_RdWr = 2;
inline constexpr uint64_t kO_Creat = 0x40;
inline constexpr uint64_t kO_Excl = 0x80;
inline constexpr uint64_t kO_Trunc = 0x200;
inline constexpr uint64_t kO_Append = 0x400;
inline constexpr uint64_t kO_Directory = 0x10000;
inline constexpr uint64_t kF_GetFl = 3;
inline constexpr uint64_t kAccessModeMask = 3;
inline constexpr uint64_t kSeekSet = 0;
inline constexpr uint64_t kSeekCur = 1;
inline constexpr uint64_t kSeekEnd = 2;
inline constexpr uint64_t kAtFdcwd = static_cast<uint64_t>(-100);
inline constexpr uint64_t kAtRemoveDir = 0x200;

inline constexpr int kEperm = 1;
inline constexpr int kEnoent = 2;
inline constexpr int kEbadf = 9;
inline constexpr int kEacces = 13;
inline constexpr int kEexist = 17;
inline constexpr int kExdev = 18;
inline constexpr int kEnotdir = 20;
inline constexpr int kEisdir = 21;
inline constexpr int kEinval = 22;
inline constexpr int kEspipe = 29;
inline constexpr int kErofs = 30;
inline constexpr int kEnametoolong = 36;

inline constexpr uint64_t kReadBufferSize = 0x2000;
inline constexpr uint64_t kStatSize = 128;
inline constexpr uint64_t kStatfsSize = 128;

inline constexpr uint64_t kStatModeOffset = 16;
inline constexpr uint64_t kStatNlinkOffset = 20;
inline constexpr uint64_t kStatUidOffset = 24;
inline constexpr uint64_t kStatGidOffset = 28;
inline constexpr uint64_t kStatRdevOffset = 32;
inline constexpr uint64_t kStatSizeOffset = 48;
inline constexpr uint64_t kStatAtimeSecondsOffset = 72;
inline constexpr uint64_t kStatAtimeNanosecondsOffset = 80;
inline constexpr uint64_t kStatMtimeSecondsOffset = 88;
inline constexpr uint64_t kStatMtimeNanosecondsOffset = 96;
inline constexpr uint64_t kStatCtimeSecondsOffset = 104;
inline constexpr uint64_t kStatCtimeNanosecondsOffset = 112;

inline constexpr uint64_t kStatfsTypeOffset = 0;
inline constexpr uint64_t kStatfsBlockSizeOffset = 8;
inline constexpr uint64_t kStatfsBlocksOffset = 16;
inline constexpr uint64_t kStatfsBlocksAvailableOffset = 32;
inline constexpr uint64_t kStatfsFlagsOffset = 80;

inline constexpr uint32_t kSIfmt = 0170000;
inline constexpr uint32_t kSIfifo = 0010000;
inline constexpr uint32_t kSIfchr = 0020000;
inline constexpr uint32_t kSIfdir = 0040000;
inline constexpr uint32_t kSIfreg = 0100000;
inline constexpr uint32_t kSIflnk = 0120000;

inline constexpr uint64_t kF2fsMagic = 0xF2F52010;
inline constexpr uint64_t kErofsMagic = 0xE0F5E1E2;
inline constexpr uint64_t kProcMagic = 0x9fa0;
inline constexpr uint64_t kTmpfsMagic = 0x01021994;
inline constexpr uint64_t kMountReadOnly = 0x1;

// DT_* values used by getdents64.
inline constexpr uint8_t kDtUnknown = 0;
inline constexpr uint8_t kDtFifo = 1;
inline constexpr uint8_t kDtChr = 2;
inline constexpr uint8_t kDtDir = 4;
inline constexpr uint8_t kDtReg = 8;
inline constexpr uint8_t kDtLnk = 10;

// arm64 struct linux_dirent64 header size; the name follows at +19.
inline constexpr uint64_t kDirent64HeaderSize = 19;

} // namespace vfs

using namespace vfs;

inline uint64_t callGuest(runtime::RuntimeInstance &instance,
	duckemu::GuestVA entry,
	const std::array<uint64_t, 8> &args = {})
{
	auto call = instance.callFunction(entry, args);
	CHECK_RESULT(call);
	return call.ok() ? call.value().return_value : 0;
}

inline bool readGuest(runtime::RuntimeInstance &instance,
	uint64_t address,
	void *buffer,
	uint64_t size)
{
	auto read = instance.readMemory(duckemu::GuestVA{ address }, buffer, size);
	CHECK_RESULT(read);
	return read.ok();
}

// libc int-returning wrappers leave only w0 meaningful; ssize_t ones
// sign-extend. Both spell failure as -1 here.
inline bool failed(uint64_t value)
{
	return static_cast<int32_t>(value) == -1;
}

inline bool contains(const std::string &haystack, std::string_view needle)
{
	return haystack.find(needle) != std::string::npos;
}

struct GuestFunctions
{
	duckemu::GuestVA open = {};
	duckemu::GuestVA read = {};
	duckemu::GuestVA write = {};
	duckemu::GuestVA close = {};
	duckemu::GuestVA stat = {};
	duckemu::GuestVA fstat = {};
	duckemu::GuestVA access = {};
	duckemu::GuestVA dup = {};
	duckemu::GuestVA dup3 = {};
	duckemu::GuestVA lseek = {};
	duckemu::GuestVA fcntl = {};
	duckemu::GuestVA statfs = {};
	duckemu::GuestVA fstatfs = {};
	duckemu::GuestVA pread = {};
	duckemu::GuestVA pwrite = {};
	duckemu::GuestVA eventfd = {};
	duckemu::GuestVA pipe2 = {};
	duckemu::GuestVA poll = {};
	duckemu::GuestVA mkdir = {};
	duckemu::GuestVA unlink = {};
	duckemu::GuestVA rename = {};
	duckemu::GuestVA readlink = {};
	duckemu::GuestVA ftruncate = {};
	duckemu::GuestVA fsync = {};
	duckemu::GuestVA openat = {};
	duckemu::GuestVA fstatat = {};
	duckemu::GuestVA mkdirat = {};
	duckemu::GuestVA unlinkat = {};
	duckemu::GuestVA renameat = {};
	duckemu::GuestVA readlinkat = {};
	duckemu::GuestVA faccessat = {};
	duckemu::GuestVA errno_fn = {};
	// Provided by libvfsraw.so (raw SVC), for syscalls bionic does not export.
	duckemu::GuestVA raw_syscall = {};
};

class VfsProbe
{
    public:
	explicit VfsProbe(runtime::RuntimeInstance &target)
		: instance(target)
	{
	}

	bool initialize()
	{
		auto path_page = instance.mapMemory(0x1000, runtime::PermReadWrite, "probe-path");
		auto path2_page = instance.mapMemory(0x1000, runtime::PermReadWrite, "probe-path2");
		auto data_page =
			instance.mapMemory(kReadBufferSize, runtime::PermReadWrite, "probe-data");
		auto stat_page = instance.mapMemory(kStatSize, runtime::PermReadWrite, "probe-stat");
		auto statfs_page =
			instance.mapMemory(kStatfsSize, runtime::PermReadWrite, "probe-statfs");
		auto pair_page = instance.mapMemory(0x1000, runtime::PermReadWrite, "probe-pair");
		CHECK_RESULT(path_page);
		CHECK_RESULT(path2_page);
		CHECK_RESULT(data_page);
		CHECK_RESULT(stat_page);
		CHECK_RESULT(statfs_page);
		CHECK_RESULT(pair_page);
		if (!path_page.ok() || !path2_page.ok() || !data_page.ok() || !stat_page.ok() ||
			!statfs_page.ok() || !pair_page.ok())
		{
			return false;
		}
		path = path_page.value().value();
		path2 = path2_page.value().value();
		data = data_page.value().value();
		stat_buffer = stat_page.value().value();
		statfs_buffer = statfs_page.value().value();
		pair = pair_page.value().value();
		return true;
	}

	bool lookupAll(uint64_t handle)
	{
		const struct
		{
			const char *name;
			duckemu::GuestVA *slot;
		} lookups[] = {
			{ "open", &functions.open },
			{ "read", &functions.read },
			{ "write", &functions.write },
			{ "close", &functions.close },
			{ "stat", &functions.stat },
			{ "fstat", &functions.fstat },
			{ "access", &functions.access },
			{ "dup", &functions.dup },
			{ "dup3", &functions.dup3 },
			{ "lseek", &functions.lseek },
			{ "fcntl", &functions.fcntl },
			{ "statfs", &functions.statfs },
			{ "fstatfs", &functions.fstatfs },
			{ "pread", &functions.pread },
			{ "pwrite", &functions.pwrite },
			{ "eventfd", &functions.eventfd },
			{ "pipe2", &functions.pipe2 },
			{ "poll", &functions.poll },
			{ "mkdir", &functions.mkdir },
			{ "unlink", &functions.unlink },
			{ "rename", &functions.rename },
			{ "readlink", &functions.readlink },
			{ "ftruncate", &functions.ftruncate },
			{ "fsync", &functions.fsync },
			{ "openat", &functions.openat },
			{ "fstatat", &functions.fstatat },
			{ "mkdirat", &functions.mkdirat },
			{ "unlinkat", &functions.unlinkat },
			{ "renameat", &functions.renameat },
			{ "readlinkat", &functions.readlinkat },
			{ "faccessat", &functions.faccessat },
			{ "__errno", &functions.errno_fn },
		};
		for (const auto &lookup : lookups)
		{
			auto found = instance.lookupSymbol(handle, lookup.name);
			CHECK_RESULT(found);
			if (!found.ok())
			{
				return false;
			}
			*lookup.slot = found.value();
		}
		return true;
	}

	// libvfsraw.so: the one fixture entry point every raw syscall goes
	// through, for the numbers bionic does not export as functions.
	bool lookupRaw(uint64_t handle)
	{
		auto found = instance.lookupSymbol(handle, "vfs_syscall");
		CHECK_RESULT(found);
		if (!found.ok())
		{
			return false;
		}
		functions.raw_syscall = found.value();
		return true;
	}

	int64_t raw(uint64_t number,
		uint64_t a0 = 0,
		uint64_t a1 = 0,
		uint64_t a2 = 0,
		uint64_t a3 = 0,
		uint64_t a4 = 0,
		uint64_t a5 = 0)
	{
		return static_cast<int64_t>(callGuest(instance, functions.raw_syscall,
			{ number, a0, a1, a2, a3, a4, a5 }));
	}

	uint64_t writePath(std::string_view value)
	{
		auto written =
			instance.writeMemory(duckemu::GuestVA{ path }, value.data(), value.size() + 1);
		CHECK_RESULT(written);
		return path;
	}

	// Second path buffer, for syscalls that take two path arguments.
	uint64_t writePath2(std::string_view value)
	{
		auto written =
			instance.writeMemory(duckemu::GuestVA{ path2 }, value.data(), value.size() + 1);
		CHECK_RESULT(written);
		return path2;
	}

	int guestErrno()
	{
		const uint64_t pointer = callGuest(instance, functions.errno_fn);
		int value = 0;
		if (pointer != 0)
		{
			CHECK_RESULT(instance.readMemory(duckemu::GuestVA{ pointer }, &value,
				sizeof(value)));
		}
		return value;
	}

	int64_t openPath(std::string_view name, uint64_t flags, uint64_t mode = 0)
	{
		const uint64_t address = writePath(name);
		// open(2) returns int: only w0 is meaningful, so sign-extend it.
		return static_cast<int32_t>(
			callGuest(instance, functions.open, { address, flags, mode }));
	}

	int64_t closeFd(int64_t fd)
	{
		return static_cast<int64_t>(
			callGuest(instance, functions.close, { static_cast<uint64_t>(fd) }));
	}

	int64_t readFd(int64_t fd, uint64_t count)
	{
		return static_cast<int64_t>(callGuest(instance, functions.read,
			{ static_cast<uint64_t>(fd), data, count }));
	}

	int64_t writeFd(int64_t fd, const void *bytes, uint64_t count)
	{
		CHECK_RESULT(instance.writeMemory(duckemu::GuestVA{ data }, bytes, count));
		return static_cast<int64_t>(callGuest(instance, functions.write,
			{ static_cast<uint64_t>(fd), data, count }));
	}

	std::string dataString(uint64_t count)
	{
		std::vector<char> bytes(static_cast<size_t>(count) + 1, 0);
		if (count > 0)
		{
			readGuest(instance, data, bytes.data(), count);
		}
		return std::string(bytes.data(), static_cast<size_t>(count));
	}

	std::string readWhole(std::string_view guest_path, int64_t &fd_out)
	{
		fd_out = openPath(guest_path, kO_RdOnly);
		if (fd_out < 0)
		{
			return {};
		}
		const int64_t bytes = readFd(fd_out, kReadBufferSize - 1);
		const std::string content = dataString(bytes > 0 ? static_cast<uint64_t>(bytes) : 0);
		closeFd(fd_out);
		return content;
	}

	int64_t statPath(std::string_view guest_path)
	{
		const uint64_t address = writePath(guest_path);
		return static_cast<int64_t>(
			callGuest(instance, functions.stat, { address, stat_buffer }));
	}

	int64_t statFd(int64_t fd)
	{
		return static_cast<int64_t>(callGuest(instance, functions.fstat,
			{ static_cast<uint64_t>(fd), stat_buffer }));
	}

	int64_t statfsPath(std::string_view guest_path)
	{
		const uint64_t address = writePath(guest_path);
		return static_cast<int64_t>(
			callGuest(instance, functions.statfs, { address, statfs_buffer }));
	}

	int64_t preadFd(int64_t fd, uint64_t offset, uint64_t count)
	{
		return static_cast<int64_t>(callGuest(instance, functions.pread,
			{ static_cast<uint64_t>(fd), data, count, offset }));
	}

	int64_t pwriteFd(int64_t fd, const void *bytes, uint64_t count, uint64_t offset)
	{
		CHECK_RESULT(instance.writeMemory(duckemu::GuestVA{ data }, bytes, count));
		return static_cast<int64_t>(callGuest(instance, functions.pwrite,
			{ static_cast<uint64_t>(fd), data, count, offset }));
	}

	int64_t lseekFd(int64_t fd, int64_t offset, int whence)
	{
		return static_cast<int64_t>(callGuest(instance, functions.lseek,
			{ static_cast<uint64_t>(fd), static_cast<uint64_t>(offset),
				static_cast<uint64_t>(whence) }));
	}

	int64_t fcntlFd(int64_t fd, uint64_t command, uint64_t argument = 0)
	{
		return static_cast<int64_t>(callGuest(instance, functions.fcntl,
			{ static_cast<uint64_t>(fd), command, argument }));
	}

	uint32_t statU32(uint64_t offset)
	{
		uint32_t value = 0;
		readGuest(instance, stat_buffer + offset, &value, sizeof(value));
		return value;
	}

	uint64_t statU64(uint64_t offset)
	{
		uint64_t value = 0;
		readGuest(instance, stat_buffer + offset, &value, sizeof(value));
		return value;
	}

	uint64_t statfsU64(uint64_t offset)
	{
		uint64_t value = 0;
		readGuest(instance, statfs_buffer + offset, &value, sizeof(value));
		return value;
	}

	runtime::RuntimeInstance &instance;
	GuestFunctions functions;
	uint64_t path = 0;
	uint64_t path2 = 0;
	uint64_t data = 0;
	uint64_t stat_buffer = 0;
	uint64_t statfs_buffer = 0;
	uint64_t pair = 0;
};

// Loads the ROM libc and prepares the probe; reports through CHECK_RESULT.
inline bool prepareVfsProbe(VfsProbe &probe, std::string_view libc_path)
{
	auto libc = probe.instance.loadLibrary(std::string(libc_path));
	CHECK_RESULT(libc);
	if (!libc.ok())
	{
		std::printf("  libc error: %s\n", libc.error().message.c_str());
		return false;
	}
	return probe.initialize() && probe.lookupAll(libc.value());
}

// Adds the raw SVC trampoline (libvfsraw.so) to an initialized probe.
inline bool prepareRawSyscalls(VfsProbe &probe, std::string_view so_path)
{
	auto raw = probe.instance.loadLibrary(std::string(so_path));
	CHECK_RESULT(raw);
	return raw.ok() && probe.lookupRaw(raw.value());
}

} // namespace duckemu::test

// SPDX-License-Identifier: GPL-2.0-only
// M10 S0: the VFS contract baseline. No production code changes: every
// assertion below is the behavior the refactor must preserve, driven through
// the ROM libc so the guest-visible syscall surface is what gets pinned.
//
// The cases are table-driven where the behavior is a property of a path
// (read contents, stat owner/type, statfs classification); the rest are the
// cross-cutting rules: symlink escape, /proc snapshot precedence, dup offset
// sharing, stdio, eventfd/pipe readiness, and EROFS without a sandbox.

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <string>
#include <string_view>
#include <vector>

#include <unistd.h>

#include "runtime/instance/runtime_instance.hpp"
#include "support/test_harness.hpp"
#include "support/vfs_probe.hpp"

using namespace duckemu;
using namespace duckemu::runtime;
using namespace duckemu::test;

namespace
{

namespace fs = std::filesystem;

constexpr uint32_t kPid = 1000;
constexpr uint32_t kTid = 1;
constexpr uint32_t kAppUid = 10042;
constexpr uint32_t kAppGid = 20042;
constexpr const char *kProcessName = "contractproc";
constexpr const char *kKernelRelease = "6.6.1-contract";
constexpr uint64_t kInjectedWallNs = 1800000000123456789ULL;

constexpr short kPollIn = 0x001;

struct PollFd
{
	int32_t fd;
	int16_t events;
	int16_t revents;
};

static_assert(sizeof(PollFd) == 8, "arm64 pollfd is 8 bytes");

std::string romLibc()
{
	return std::string(DUCKEMU_ROM_BOOTSTRAP) + "/libc.so";
}

struct ReadCase
{
	const char *path;
	const char *needle;
};

struct StatCase
{
	const char *path;
	uint32_t uid;
	uint32_t gid;
	uint32_t type;
};

struct StatfsCase
{
	const char *path;
	uint64_t type;
	bool read_only;
};

struct FixtureFiles
{
	std::string root;
	std::string sandbox;
	std::string outside;
};

bool prepareDirectories(FixtureFiles &files)
{
	std::error_code error;
	files.root = (fs::temp_directory_path(error) /
			     ("duckemu-vfs-contract-root-" + std::to_string(::getpid())))
			     .string();
	files.sandbox = (fs::temp_directory_path(error) /
				("duckemu-vfs-contract-box-" + std::to_string(::getpid())))
				.string();
	files.outside = (fs::temp_directory_path(error) /
				("duckemu-vfs-contract-outside-" + std::to_string(::getpid())))
				.string();
	if (error)
	{
		return false;
	}
	fs::remove_all(files.root, error);
	fs::remove_all(files.sandbox, error);
	fs::remove_all(files.outside, error);
	fs::create_directories(fs::path(files.root) / "system" / "etc", error);
	fs::create_directories(fs::path(files.root) / "proc" / "self", error);
	fs::create_directories(fs::path(files.sandbox) / "data", error);
	fs::create_directories(files.outside, error);
	if (error)
	{
		return false;
	}

	{
		std::ofstream seed(fs::path(files.root) / "system" / "etc" / "ro.txt",
			std::ios::binary);
		seed << "ro-data";
	}
	{
		// The snapshot deliberately differs from the synthesizer's output, so
		// a read proves which one answered.
		std::ofstream snapshot(fs::path(files.root) / "proc" / "self" / "status",
			std::ios::binary);
		snapshot << "Name:\t" << kProcessName << "\nSnapshot: yes\n";
	}
	{
		std::ofstream seed(fs::path(files.sandbox) / "data" / "preloaded.txt",
			std::ios::binary);
		seed << "sandbox-data";
	}
	{
		std::ofstream secret(fs::path(files.outside) / "secret.txt", std::ios::binary);
		secret << "outside-data";
	}
	// A symlink that resolves outside the mounted root must be invisible.
	const fs::path escape = fs::path(files.root) / "system" / "escape.txt";
	fs::create_symlink((fs::path(files.outside) / "secret.txt").string(), escape, error);
	return !error;
}

void removeDirectories(const FixtureFiles &files)
{
	std::error_code ignored;
	fs::remove_all(files.root, ignored);
	fs::remove_all(files.sandbox, ignored);
	fs::remove_all(files.outside, ignored);
}

RuntimeConfig baseConfig(const FixtureFiles &files)
{
	RuntimeConfig config;
	config.pid = kPid;
	config.tid = kTid;
	config.library_search_paths = { DUCKEMU_ROM_BOOTSTRAP, DUCKEMU_ROM_LIB64 };
	config.filesystem_roots = { files.root };
	config.filesystem_write_root = files.sandbox;
	config.device.uid = kAppUid;
	config.device.gid = kAppGid;
	config.device.process_name = kProcessName;
	config.device.kernel_release = kKernelRelease;
	return config;
}

void checkReadCases(VfsProbe &probe)
{
	const std::vector<ReadCase> cases = {
		{ "/system/etc/ro.txt", "ro-data" },
		{ "/data/preloaded.txt", "sandbox-data" },
		{ "/proc/self/status", kProcessName },
		{ "/proc/1000/status", kProcessName },
		{ "/proc/version", kKernelRelease },
	};
	for (const ReadCase &pending : cases)
	{
		int64_t fd = -1;
		const std::string content = probe.readWhole(pending.path, fd);
		std::printf("  read(%s) fd=%lld bytes=%zu\n", pending.path,
			static_cast<long long>(fd), content.size());
		CHECK(fd >= 3);
		CHECK(contains(content, pending.needle));
	}
}

void checkSymlinkEscape(VfsProbe &probe)
{
	const int64_t fd = probe.openPath("/system/escape.txt", kO_RdOnly);
	std::printf("  open(/system/escape.txt) = %lld\n", static_cast<long long>(fd));
	CHECK(fd < 0);
}

void checkDevNodes(VfsProbe &probe)
{
	// /dev/null: swallows writes, reads EOF, root-owned char device 1:3.
	const int64_t null_fd = probe.openPath("/dev/null", kO_RdWr);
	CHECK(null_fd >= 3);
	if (null_fd >= 3)
	{
		CHECK_EQ(probe.writeFd(null_fd, "abcdefgh", 8), 8);
		CHECK_EQ(probe.readFd(null_fd, 8), 0);
		CHECK_EQ(probe.statFd(null_fd), 0);
		CHECK_EQ(probe.statU32(kStatModeOffset) & kSIfmt, kSIfchr);
		CHECK_EQ(probe.statU64(kStatRdevOffset), 0x103u);
		CHECK_EQ(probe.statU32(kStatUidOffset), 0u);
		CHECK_EQ(probe.statU32(kStatGidOffset), 0u);
		CHECK_EQ(probe.closeFd(null_fd), 0);
	}

	// /dev/zero: reads zeros; the read-only description refuses writes.
	const int64_t zero_fd = probe.openPath("/dev/zero", kO_RdOnly);
	CHECK(zero_fd >= 3);
	if (zero_fd >= 3)
	{
		const std::vector<uint8_t> poison(16, 0xa5);
		CHECK_RESULT(
			probe.instance.writeMemory(GuestVA{ probe.data }, poison.data(), poison.size()));
		CHECK_EQ(probe.readFd(zero_fd, 16), 16);
		std::array<uint8_t, 16> bytes{};
		readGuest(probe.instance, probe.data, bytes.data(), bytes.size());
		bool all_zero = true;
		for (uint8_t byte : bytes)
		{
			all_zero = all_zero && byte == 0;
		}
		CHECK(all_zero);
		CHECK(failed(callGuest(probe.instance, probe.functions.write,
			{ static_cast<uint64_t>(zero_fd), probe.data, 4 })));
		CHECK_EQ(probe.closeFd(zero_fd), 0);
	}

	// /dev/urandom: real bytes from the instance random source.
	const int64_t random_fd = probe.openPath("/dev/urandom", kO_RdOnly);
	CHECK(random_fd >= 3);
	if (random_fd >= 3)
	{
		CHECK_EQ(probe.readFd(random_fd, 16), 16);
		CHECK_EQ(probe.closeFd(random_fd), 0);
	}
}

void checkProperties(VfsProbe &probe)
{
	// The property images are root-owned 0444, which bionic's trie reader
	// validates before it trusts the area.
	const int64_t fd = probe.openPath("/dev/__properties__/property_info", kO_RdOnly);
	CHECK(fd >= 3);
	if (fd >= 3)
	{
		CHECK_EQ(probe.statFd(fd), 0);
		CHECK_EQ(probe.statU32(kStatModeOffset) & kSIfmt, kSIfreg);
		CHECK_EQ(probe.statU32(kStatModeOffset) & 0777, 0444u);
		CHECK_EQ(probe.statU32(kStatUidOffset), 0u);
		CHECK_EQ(probe.statU32(kStatGidOffset), 0u);
		CHECK(probe.readFd(fd, 64) > 0);
		CHECK_EQ(probe.closeFd(fd), 0);
	}
}

void checkStatCases(VfsProbe &probe)
{
	const std::vector<StatCase> cases = {
		{ "/system/etc/ro.txt", kAppUid, kAppGid, kSIfreg },
		{ "/dev/null", 0, 0, kSIfchr },
		{ "/dev/__properties__/property_info", 0, 0, kSIfreg },
	};
	for (const StatCase &pending : cases)
	{
		CHECK_EQ(probe.statPath(pending.path), 0);
		const uint32_t uid = probe.statU32(kStatUidOffset);
		const uint32_t gid = probe.statU32(kStatGidOffset);
		const uint32_t type = probe.statU32(kStatModeOffset) & kSIfmt;
		std::printf("  stat(%s) uid=%u gid=%u type=0%o\n", pending.path, uid, gid, type);
		CHECK_EQ(uid, pending.uid);
		CHECK_EQ(gid, pending.gid);
		CHECK_EQ(type, pending.type);
	}
}

void checkInjectedTimestamps(VfsProbe &probe)
{
	// Pin the wall clock immediately before the stat: applyOwner consumes
	// exactly one clock read per result, so the stamps are the injected base.
	probe.instance.setWallTimeNs(kInjectedWallNs);
	CHECK_EQ(probe.statPath("/system/etc/ro.txt"), 0);
	const uint64_t seconds = kInjectedWallNs / 1000000000ULL;
	const uint64_t nanoseconds = kInjectedWallNs % 1000000000ULL;
	CHECK_EQ(probe.statU64(kStatAtimeSecondsOffset), seconds);
	CHECK_EQ(probe.statU64(kStatAtimeNanosecondsOffset), nanoseconds);
	CHECK_EQ(probe.statU64(kStatMtimeSecondsOffset), seconds);
	CHECK_EQ(probe.statU64(kStatMtimeNanosecondsOffset), nanoseconds);
	CHECK_EQ(probe.statU64(kStatCtimeSecondsOffset), seconds);
	CHECK_EQ(probe.statU64(kStatCtimeNanosecondsOffset), nanoseconds);
	probe.instance.useHostWallClock();
}

void checkStatfsCases(VfsProbe &probe)
{
	const std::vector<StatfsCase> cases = {
		{ "/data", kF2fsMagic, false },
		{ "/system/etc/ro.txt", kErofsMagic, true },
		{ "/proc", kProcMagic, false },
		{ "/dev/null", kTmpfsMagic, false },
	};
	for (const StatfsCase &pending : cases)
	{
		CHECK_EQ(probe.statfsPath(pending.path), 0);
		const uint64_t type = probe.statfsU64(kStatfsTypeOffset);
		const uint64_t flags = probe.statfsU64(kStatfsFlagsOffset);
		std::printf("  statfs(%s) type=0x%llx flags=0x%llx\n", pending.path,
			static_cast<unsigned long long>(type),
			static_cast<unsigned long long>(flags));
		CHECK_EQ(type, pending.type);
		CHECK_EQ((flags & kMountReadOnly) != 0, pending.read_only);
	}
}

void checkDupSharing(VfsProbe &probe)
{
	const int64_t fd = probe.openPath("/system/etc/ro.txt", kO_RdOnly);
	CHECK(fd >= 3);
	if (fd < 3)
	{
		return;
	}
	const int64_t copy = static_cast<int64_t>(
		callGuest(probe.instance, probe.functions.dup, { static_cast<uint64_t>(fd) }));
	CHECK(copy >= 3);
	if (copy >= 3)
	{
		CHECK_EQ(probe.readFd(fd, 4), 4);
		const std::string first = probe.dataString(4);
		// The shared offset means the copy continues at byte 4.
		CHECK_EQ(probe.readFd(copy, 3), 3);
		const std::string second = probe.dataString(3);
		CHECK(first == "ro-d");
		CHECK(second == "ata");
		// Rewinding through the copy rewinds the original too.
		CHECK_EQ(probe.lseekFd(copy, 0, kSeekSet), 0);
		CHECK_EQ(probe.readFd(fd, 4), 4);
		CHECK(probe.dataString(4) == first);
		CHECK_EQ(probe.closeFd(copy), 0);
	}
	CHECK_EQ(probe.closeFd(fd), 0);
}

void checkStdio(VfsProbe &probe)
{
	const int64_t copy = static_cast<int64_t>(
		callGuest(probe.instance, probe.functions.dup, { 1 }));
	std::printf("  dup(1) = %lld\n", static_cast<long long>(copy));
	CHECK(copy >= 3);
	if (copy < 3)
	{
		return;
	}
	const int64_t flags = probe.fcntlFd(copy, kF_GetFl);
	CHECK_EQ(static_cast<uint64_t>(flags) & kAccessModeMask, kO_WrOnly);
	// The copy writes to the host's stdout, not into the guest.
	CHECK_EQ(probe.writeFd(copy, "c", 1), 1);
	CHECK_EQ(probe.closeFd(copy), 0);
}

void checkEventObjects(VfsProbe &probe)
{
	// eventfd: a written counter is readable and poll-ready, then drains.
	const int64_t event_fd =
		static_cast<int64_t>(callGuest(probe.instance, probe.functions.eventfd, { 0, 0 }));
	CHECK(event_fd >= 3);
	if (event_fd >= 3)
	{
		uint64_t one = 1;
		CHECK_EQ(probe.writeFd(event_fd, &one, sizeof(one)), 8);
		PollFd poll = { static_cast<int32_t>(event_fd), kPollIn, 0 };
		CHECK_RESULT(
			probe.instance.writeMemory(GuestVA{ probe.pair }, &poll, sizeof(poll)));
		CHECK_EQ(callGuest(probe.instance, probe.functions.poll, { probe.pair, 1, 0 }), 1);
		CHECK_RESULT(
			probe.instance.readMemory(GuestVA{ probe.pair }, &poll, sizeof(poll)));
		CHECK_EQ(poll.revents & kPollIn, kPollIn);
		uint64_t counter = 0;
		CHECK_EQ(probe.readFd(event_fd, 8), 8);
		CHECK_RESULT(
			probe.instance.readMemory(GuestVA{ probe.data }, &counter, sizeof(counter)));
		CHECK_EQ(counter, 1u);
		CHECK_EQ(probe.closeFd(event_fd), 0);
	}

	// pipe2: bytes written to the write end are readable from the read end.
	CHECK_EQ(callGuest(probe.instance, probe.functions.pipe2, { probe.pair, 0 }), 0);
	uint32_t read_end = 0;
	uint32_t write_end = 0;
	CHECK_RESULT(
		probe.instance.readMemory(GuestVA{ probe.pair }, &read_end, sizeof(read_end)));
	CHECK_RESULT(
		probe.instance.readMemory(GuestVA{ probe.pair + 4 }, &write_end, sizeof(write_end)));
	std::printf("  pipe2 -> read=%u write=%u\n", read_end, write_end);
	CHECK(read_end >= 3);
	CHECK(write_end >= 3);
	if (read_end >= 3 && write_end >= 3)
	{
		CHECK_EQ(probe.writeFd(static_cast<int64_t>(write_end), "pipe", 4), 4);
		PollFd poll = { static_cast<int32_t>(read_end), kPollIn, 0 };
		CHECK_RESULT(
			probe.instance.writeMemory(GuestVA{ probe.pair }, &poll, sizeof(poll)));
		CHECK_EQ(callGuest(probe.instance, probe.functions.poll, { probe.pair, 1, 0 }), 1);
		CHECK_EQ(probe.readFd(read_end, 4), 4);
		CHECK(probe.dataString(4) == "pipe");
		CHECK_EQ(probe.closeFd(read_end), 0);
		CHECK_EQ(probe.closeFd(write_end), 0);
	}
	// A closed pipe end answers EBADF, like the kernel.
	CHECK(failed(probe.readFd(read_end, 4)));
	CHECK_EQ(probe.guestErrno(), kEbadf);
}

void checkNoSandbox(const FixtureFiles &files)
{
	RuntimeConfig config = baseConfig(files);
	// No filesystem_write_root: the namespace stays read-only.
	config.filesystem_write_root.clear();
	auto created = RuntimeInstance::create(config);
	CHECK_RESULT(created);
	if (!created.ok())
	{
		return;
	}
	VfsProbe probe(*created.value());
	if (!prepareVfsProbe(probe, romLibc()))
	{
		return;
	}

	const int64_t fd = probe.openPath("/data/x.txt", kO_RdWr | kO_Creat, 0600);
	std::printf("  no-sandbox open(/data/x.txt, O_CREAT) = %lld errno=%d\n",
		static_cast<long long>(fd), probe.guestErrno());
	CHECK_EQ(fd, -1);
	CHECK_EQ(probe.guestErrno(), kErofs);

	// Read-only roots still read normally.
	int64_t read_fd = -1;
	CHECK(probe.readWhole("/system/etc/ro.txt", read_fd) == "ro-data");
	CHECK(read_fd >= 3);

	// A missing file stays ENOENT, not EROFS.
	const int64_t missing = probe.openPath("/system/missing.txt", kO_RdOnly);
	CHECK_EQ(missing, -1);
	CHECK_EQ(probe.guestErrno(), kEnoent);
}

} // namespace

int main()
{
	FixtureFiles files;
	if (!prepareDirectories(files))
	{
		std::fprintf(stderr, "cannot prepare the contract fixture directories\n");
		return test::finish("10a_vfs_contract");
	}

	auto created = RuntimeInstance::create(baseConfig(files));
	CHECK_RESULT(created);
	if (!created.ok())
	{
		removeDirectories(files);
		return test::finish("10a_vfs_contract");
	}

	VfsProbe probe(*created.value());
	if (!prepareVfsProbe(probe, romLibc()))
	{
		removeDirectories(files);
		return test::finish("10a_vfs_contract");
	}

	checkReadCases(probe);
	checkSymlinkEscape(probe);
	checkDevNodes(probe);
	checkProperties(probe);
	checkStatCases(probe);
	checkInjectedTimestamps(probe);
	checkStatfsCases(probe);
	checkDupSharing(probe);
	checkStdio(probe);
	checkEventObjects(probe);
	checkNoSandbox(files);

	removeDirectories(files);
	return test::finish("10a_vfs_contract");
}

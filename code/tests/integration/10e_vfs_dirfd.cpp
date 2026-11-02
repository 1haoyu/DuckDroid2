// SPDX-License-Identifier: GPL-2.0-only
// M10 S4 gate: directory-relative paths.
//   - openat/fstatat/faccessat/mkdirat/unlinkat/renameat/readlinkat all take
//     a directory descriptor and normalize ".." without leaving the namespace
//   - a non-directory dirfd answers ENOTDIR, an unopened one EBADF
//   - a rename across mounts answers EXDEV, and a rename keeps the inode
//   - /proc/self/fd/N names a directory descriptor too

#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <string>
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
constexpr uint64_t kAtEmptyPath = 0x1000;
constexpr uint64_t kROk = 4;
constexpr int kBadFd = 99;

std::string romLibc()
{
	return std::string(DUCKEMU_ROM_BOOTSTRAP) + "/libc.so";
}

struct Tree
{
	std::string root;
	std::string sandbox;
};

bool prepare(const Tree &tree)
{
	std::error_code error;
	fs::remove_all(tree.root, error);
	fs::remove_all(tree.sandbox, error);
	fs::create_directories(fs::path(tree.root) / "system" / "etc", error);
	fs::create_directories(fs::path(tree.sandbox) / "data", error);
	if (error)
	{
		return false;
	}
	{
		std::ofstream ro(fs::path(tree.root) / "system" / "etc" / "ro.txt");
		ro << "ro-data";
		std::ofstream shared(fs::path(tree.root) / "system" / "shared.txt");
		shared << "lower-only";
		std::ofstream alpha(fs::path(tree.sandbox) / "data" / "alpha.txt");
		alpha << "alpha";
		std::ofstream beta(fs::path(tree.sandbox) / "data" / "beta.txt");
		beta << "beta";
	}
	return true;
}

RuntimeConfig baseConfig(const Tree &tree)
{
	RuntimeConfig config;
	config.pid = kPid;
	config.tid = kTid;
	config.library_search_paths = { DUCKEMU_ROM_BOOTSTRAP, DUCKEMU_ROM_LIB64 };
	config.filesystem_roots = { tree.root };
	config.filesystem_write_root = tree.sandbox;
	return config;
}

int64_t guestCall(VfsProbe &probe, GuestVA function, const std::array<uint64_t, 8> &args)
{
	return static_cast<int32_t>(callGuest(probe.instance, function, args));
}

void expectError(VfsProbe &probe, const char *what, int64_t result, int expected)
{
	const int observed = probe.guestErrno();
	std::printf("  %s = %lld errno=%d\n", what, static_cast<long long>(result), observed);
	CHECK_EQ(result, -1);
	CHECK_EQ(observed, expected);
}

void checkDirectoryRelative(VfsProbe &probe)
{
	const int64_t data_fd = probe.openPath("/data", kO_RdOnly | kO_Directory);
	CHECK(data_fd >= 3);
	if (data_fd < 3)
	{
		return;
	}

	// openat + fstatat + faccessat.
	probe.writePath("alpha.txt");
	const int64_t alpha_fd = guestCall(probe, probe.functions.openat,
		{ static_cast<uint64_t>(data_fd), probe.path, kO_RdOnly, 0 });
	CHECK(alpha_fd >= 3);
	if (alpha_fd >= 3)
	{
		CHECK_EQ(probe.readFd(alpha_fd, 5), 5);
		CHECK(probe.dataString(5) == "alpha");
		CHECK_EQ(probe.closeFd(alpha_fd), 0);
	}

	probe.writePath("alpha.txt");
	CHECK_EQ(guestCall(probe, probe.functions.fstatat,
			 { static_cast<uint64_t>(data_fd), probe.path, probe.stat_buffer, 0 }),
		0);
	const uint64_t relative_ino = probe.statU64(8);
	CHECK_EQ(probe.statPath("/data/alpha.txt"), 0);
	CHECK_EQ(relative_ino, probe.statU64(8));

	probe.writePath("alpha.txt");
	CHECK_EQ(guestCall(probe, probe.functions.faccessat,
			 { static_cast<uint64_t>(data_fd), probe.path, kROk, 0 }),
		0);
	probe.writePath("missing.txt");
	expectError(probe, "faccessat(dirfd, missing)",
		guestCall(probe, probe.functions.faccessat,
			{ static_cast<uint64_t>(data_fd), probe.path, kROk, 0 }),
		kEnoent);

	// mkdirat twice: create then EEXIST.
	probe.writePath("sub");
	CHECK_EQ(guestCall(probe, probe.functions.mkdirat,
			 { static_cast<uint64_t>(data_fd), probe.path, 0700 }),
		0);
	probe.writePath("sub");
	expectError(probe, "mkdirat(dirfd, sub) again",
		guestCall(probe, probe.functions.mkdirat,
			{ static_cast<uint64_t>(data_fd), probe.path, 0700 }),
		kEexist);
	probe.writePath("sub");
	CHECK_EQ(guestCall(probe, probe.functions.fstatat,
			 { static_cast<uint64_t>(data_fd), probe.path, probe.stat_buffer, 0 }),
		0);
	CHECK_EQ(probe.statU32(kStatModeOffset) & kSIfmt, kSIfdir);

	// Create, rename (inode survives), stat the destination, unlink.
	probe.writePath("sub/new.txt");
	const int64_t new_fd = guestCall(probe, probe.functions.openat,
		{ static_cast<uint64_t>(data_fd), probe.path, kO_WrOnly | kO_Creat, 0600 });
	CHECK(new_fd >= 3);
	if (new_fd >= 3)
	{
		CHECK_EQ(probe.writeFd(new_fd, "moved", 5), 5);
		CHECK_EQ(probe.closeFd(new_fd), 0);
	}
	probe.writePath("sub/new.txt");
	CHECK_EQ(probe.statPath("/data/sub/new.txt"), 0);
	const uint64_t before_rename = probe.statU64(8);
	probe.writePath("sub/new.txt");
	probe.writePath2("sub/moved.txt");
	CHECK_EQ(guestCall(probe, probe.functions.renameat,
			 { static_cast<uint64_t>(data_fd), probe.path,
				 static_cast<uint64_t>(data_fd), probe.path2 }),
		0);
	CHECK_EQ(probe.statPath("/data/sub/moved.txt"), 0);
	CHECK_EQ(probe.statU64(8), before_rename);
	probe.writePath("sub/moved.txt");
	CHECK_EQ(guestCall(probe, probe.functions.unlinkat,
			 { static_cast<uint64_t>(data_fd), probe.path, 0 }),
		0);
	CHECK_EQ(probe.statPath("/data/sub/moved.txt"), -1);
	CHECK_EQ(probe.guestErrno(), kEnoent);

	// readlinkat: an existing non-symlink is EINVAL, a missing name ENOENT.
	probe.writePath("alpha.txt");
	expectError(probe, "readlinkat(dirfd, alpha.txt)",
		guestCall(probe, probe.functions.readlinkat,
			{ static_cast<uint64_t>(data_fd), probe.path, probe.data, 64 }),
		kEinval);
	probe.writePath("none.txt");
	expectError(probe, "readlinkat(dirfd, none.txt)",
		guestCall(probe, probe.functions.readlinkat,
			{ static_cast<uint64_t>(data_fd), probe.path, probe.data, 64 }),
		kEnoent);

	// ".." is resolved against the directory descriptor and clamped at "/".
	probe.writePath("../../system/etc/ro.txt");
	const int64_t escape_fd = guestCall(probe, probe.functions.openat,
		{ static_cast<uint64_t>(data_fd), probe.path, kO_RdOnly, 0 });
	CHECK(escape_fd >= 3);
	if (escape_fd >= 3)
	{
		CHECK_EQ(probe.readFd(escape_fd, 7), 7);
		CHECK(probe.dataString(7) == "ro-data");
		CHECK_EQ(probe.closeFd(escape_fd), 0);
	}

	// A relative path may cross into a sibling mount (/data/../dev/null).
	probe.writePath("../dev/null");
	const int64_t dev_fd = guestCall(probe, probe.functions.openat,
		{ static_cast<uint64_t>(data_fd), probe.path, kO_RdOnly, 0 });
	CHECK(dev_fd >= 3);
	if (dev_fd >= 3)
	{
		CHECK_EQ(probe.readFd(dev_fd, 8), 0);
		CHECK_EQ(probe.closeFd(dev_fd), 0);
	}

	// fstatat(AT_EMPTY_PATH) resolves the descriptor itself.
	probe.writePath("");
	CHECK_EQ(guestCall(probe, probe.functions.fstatat,
			 { static_cast<uint64_t>(data_fd), probe.path, probe.stat_buffer,
				 kAtEmptyPath }),
		0);
	CHECK_EQ(probe.statU32(kStatModeOffset) & kSIfmt, kSIfdir);

	// /proc/self/fd/N names a directory descriptor.
	const std::string fd_path = "/proc/self/fd/" + std::to_string(data_fd);
	const int64_t length = static_cast<int64_t>(callGuest(probe.instance,
		probe.functions.readlink,
		{ probe.writePath(fd_path), probe.data, 256 }));
	CHECK_EQ(length, static_cast<int64_t>(std::string("/data").size()));
	if (length > 0)
	{
		CHECK(probe.dataString(static_cast<uint64_t>(length)) == "/data");
	}

	// Clean up the directory through the descriptor.
	probe.writePath("sub");
	CHECK_EQ(guestCall(probe, probe.functions.unlinkat,
			 { static_cast<uint64_t>(data_fd), probe.path, kAtRemoveDir }),
		0);
	CHECK_EQ(probe.closeFd(data_fd), 0);
}

void checkBadDirfds(VfsProbe &probe)
{
	// A regular descriptor is not a directory.
	const int64_t file_fd = probe.openPath("/data/alpha.txt", kO_RdOnly);
	CHECK(file_fd >= 3);
	if (file_fd >= 3)
	{
		probe.writePath("x");
		expectError(probe, "openat(regular fd)",
			guestCall(probe, probe.functions.openat,
				{ static_cast<uint64_t>(file_fd), probe.path, kO_RdOnly, 0 }),
			kEnotdir);
		probe.writePath("x");
		expectError(probe, "fstatat(regular fd)",
			guestCall(probe, probe.functions.fstatat,
				{ static_cast<uint64_t>(file_fd), probe.path, probe.stat_buffer, 0 }),
			kEnotdir);
		CHECK_EQ(probe.closeFd(file_fd), 0);
	}

	// An unopened descriptor is EBADF.
	probe.writePath("x");
	expectError(probe, "openat(closed fd)",
		guestCall(probe, probe.functions.openat,
			{ static_cast<uint64_t>(kBadFd), probe.path, kO_RdOnly, 0 }),
		kEbadf);
	probe.writePath("x");
	expectError(probe, "mkdirat(closed fd)",
		guestCall(probe, probe.functions.mkdirat,
			{ static_cast<uint64_t>(kBadFd), probe.path, 0700 }),
		kEbadf);
}

void checkCrossMountRename(VfsProbe &probe)
{
	const int64_t data_fd = probe.openPath("/data", kO_RdOnly | kO_Directory);
	CHECK(data_fd >= 3);
	if (data_fd >= 3)
	{
		probe.writePath("alpha.txt");
		probe.writePath2("/dev/alpha.txt");
		const int64_t result = probe.raw(38 /* renameat */,
			static_cast<uint64_t>(data_fd), probe.path, kAtFdcwd, probe.path2);
		std::printf("  renameat(/data, alpha.txt -> /dev/alpha.txt) = %lld\n",
			static_cast<long long>(result));
		CHECK_EQ(result, -kExdev);
		CHECK_EQ(probe.closeFd(data_fd), 0);
	}

	// A source that only exists in the lower layer answers EROFS through the
	// dirfd route too.
	const int64_t system_fd = probe.openPath("/system", kO_RdOnly | kO_Directory);
	CHECK(system_fd >= 3);
	if (system_fd >= 3)
	{
		probe.writePath("shared.txt");
		probe.writePath2("/data/moved.txt");
		const int64_t result = probe.raw(38, static_cast<uint64_t>(system_fd), probe.path,
			kAtFdcwd, probe.path2);
		CHECK_EQ(result, -kErofs);
		CHECK_EQ(probe.closeFd(system_fd), 0);
	}
}

} // namespace

int main()
{
	Tree tree;
	tree.root = (fs::temp_directory_path() /
		     ("duckemu-vfs-dirfd-root-" + std::to_string(::getpid())))
		     .string();
	tree.sandbox = (fs::temp_directory_path() /
			("duckemu-vfs-dirfd-box-" + std::to_string(::getpid())))
			.string();
	if (!prepare(tree))
	{
		std::fprintf(stderr, "cannot prepare the dirfd fixture\n");
		return test::finish("10e_vfs_dirfd");
	}

	auto created = RuntimeInstance::create(baseConfig(tree));
	CHECK_RESULT(created);
	if (created.ok())
	{
		VfsProbe probe(*created.value());
		if (prepareVfsProbe(probe, romLibc()) &&
			prepareRawSyscalls(probe, std::string(DUCKEMU_SO_DIR) + "/libvfsraw.so"))
		{
			checkDirectoryRelative(probe);
			checkBadDirfds(probe);
			checkCrossMountRename(probe);
		}
	}

	std::error_code ignored;
	fs::remove_all(tree.root, ignored);
	fs::remove_all(tree.sandbox, ignored);
	return test::finish("10e_vfs_dirfd");
}

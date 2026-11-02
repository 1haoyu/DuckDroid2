// SPDX-License-Identifier: GPL-2.0-only
// M10 S1 gate: the namespace is a mount table.
//   - longest prefix wins (/dev/__properties__ over /dev)
//   - synthetic mounts shadow same-named host paths
//   - read-only mounts answer EROFS to every mutation
//   - /proc/<pid>/x and /proc/thread-self/x are the snapshot's self/x
//   - a mount with no writable layer answers EROFS

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

constexpr uint32_t kPid = 4242;
constexpr uint32_t kTid = 1;
constexpr const char *kProcessName = "mountproc";

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
	fs::create_directories(fs::path(tree.root) / "proc" / "self", error);
	fs::create_directories(fs::path(tree.root) / "dev" / "__properties__", error);
	fs::create_directories(fs::path(tree.sandbox) / "data", error);
	if (error)
	{
		return false;
	}
	{
		std::ofstream file(fs::path(tree.root) / "system" / "etc" / "ro.txt");
		file << "ro-data";
	}
	{
		std::ofstream file(fs::path(tree.root) / "proc" / "self" / "status");
		file << "Name:\t" << kProcessName << "\n";
	}
	// Decoys under the host copy of /dev: the synthetic mounts must win.
	{
		std::ofstream file(fs::path(tree.root) / "dev" / "null");
		file << "host-decoy-null";
	}
	{
		std::ofstream file(fs::path(tree.root) / "dev" / "__properties__" / "property_info");
		file << "host-decoy-property-info";
	}
	{
		std::ofstream file(fs::path(tree.root) / "dev" / "synth-shadow.txt");
		file << "host-only";
	}
	{
		std::ofstream file(fs::path(tree.sandbox) / "data" / "preloaded.txt");
		file << "sandbox-data";
	}
	return true;
}

RuntimeConfig baseConfig(const Tree &tree, bool writable)
{
	RuntimeConfig config;
	config.pid = kPid;
	config.tid = kTid;
	config.library_search_paths = { DUCKEMU_ROM_BOOTSTRAP, DUCKEMU_ROM_LIB64 };
	config.filesystem_roots = { tree.root };
	if (writable)
	{
		config.filesystem_write_root = tree.sandbox;
	}
	config.device.process_name = kProcessName;
	return config;
}

void checkSyntheticShadowing(VfsProbe &probe)
{
	// /dev/null is the character device, not the host decoy file.
	const int64_t null_fd = probe.openPath("/dev/null", kO_RdOnly);
	CHECK(null_fd >= 3);
	if (null_fd >= 3)
	{
		CHECK_EQ(probe.readFd(null_fd, 32), 0);
		CHECK_EQ(probe.statFd(null_fd), 0);
		CHECK_EQ(probe.statU32(kStatModeOffset) & kSIfmt, kSIfchr);
		CHECK_EQ(probe.statU64(kStatRdevOffset), 0x103u);
		CHECK_EQ(probe.closeFd(null_fd), 0);
	}

	// Longest prefix: /dev/__properties__/property_info belongs to the
	// property mount, not to /dev (whose backend has no such node).
	const int64_t property_fd = probe.openPath("/dev/__properties__/property_info",
		kO_RdOnly);
	std::printf("  open(property_info) = %lld\n", static_cast<long long>(property_fd));
	CHECK(property_fd >= 3);
	if (property_fd >= 3)
	{
		CHECK_EQ(probe.statFd(property_fd), 0);
		CHECK_EQ(probe.statU32(kStatUidOffset), 0u);
		CHECK_EQ(probe.statU32(kStatGidOffset), 0u);
		const int64_t bytes = probe.readFd(property_fd, 32);
		CHECK(bytes > 0);
		const std::string prefix = probe.dataString(static_cast<uint64_t>(bytes));
		// The decoy text must not leak through.
		CHECK(!contains(prefix, "host-decoy"));
		CHECK_EQ(probe.closeFd(property_fd), 0);
	}

	// The property mount directory itself is a directory owned by root.
	CHECK_EQ(probe.statPath("/dev/__properties__"), 0);
	CHECK_EQ(probe.statU32(kStatModeOffset) & kSIfmt, kSIfdir);
	CHECK_EQ(probe.statU32(kStatUidOffset), 0u);

	// Host files that exist only under the shadowed /dev tree are invisible.
	const int64_t shadow = probe.openPath("/dev/synth-shadow.txt", kO_RdOnly);
	CHECK_EQ(shadow, -1);
	CHECK_EQ(probe.guestErrno(), kEnoent);
}

// bionic's rename(3) is not a plain renameat on this ROM, so the gates issue
// the syscall directly through libvfsraw.so.
int64_t rawRename(VfsProbe &probe, std::string_view old_path, std::string_view new_path)
{
	probe.writePath(old_path);
	probe.writePath2(new_path);
	return probe.raw(38 /* renameat */, kAtFdcwd, probe.path, kAtFdcwd, probe.path2);
}

void checkReadOnlyMounts(VfsProbe &probe)
{
	// /proc, /dev and /dev/__properties__ are read-only mounts even when the
	// root mount has a writable upper.
	auto expectErofs = [&](const char *operation, int64_t result) {
		std::printf("  %s = %lld errno=%d\n", operation, static_cast<long long>(result),
			probe.guestErrno());
		CHECK_EQ(result, -1);
		CHECK_EQ(probe.guestErrno(), kErofs);
	};

	probe.writePath("/proc/newdir");
	expectErofs("mkdir(/proc/newdir)",
		static_cast<int64_t>(callGuest(probe.instance, probe.functions.mkdir,
			{ probe.path, 0700 })));

	probe.writePath("/dev/null");
	expectErofs("unlink(/dev/null)",
		static_cast<int64_t>(callGuest(probe.instance, probe.functions.unlink,
			{ probe.path })));

	// Raw SVCs return the negative errno in x0 instead of setting errno.
	const int64_t rename_result = rawRename(probe, "/dev/null", "/dev/renamed");
	std::printf("  rename(/dev/null, /dev/renamed) = %lld\n",
		static_cast<long long>(rename_result));
	CHECK_EQ(rename_result, -kErofs);

	const int64_t property_write =
		probe.openPath("/dev/__properties__/property_info", kO_WrOnly);
	expectErofs("open(property_info, O_WRONLY)", property_write);

	// A synthetic mount cannot be the destination of a cross-mount rename.
	const int64_t cross = rawRename(probe, "/dev/null", "/dev/__properties__/x");
	std::printf("  rename(/dev/null -> /dev/__properties__/x) = %lld\n",
		static_cast<long long>(cross));
	CHECK_EQ(cross, -kExdev);
}

void checkProcPidMapping(VfsProbe &probe)
{
	struct Case
	{
		const char *path;
		bool exists;
	};
	const Case cases[] = {
		{ "/proc/self/status", true },
		{ "/proc/4242/status", true },
		{ "/proc/thread-self/status", true },
		{ "/proc/4243/status", false },
	};
	for (const Case &pending : cases)
	{
		int64_t fd = -1;
		const std::string content = probe.readWhole(pending.path, fd);
		std::printf("  read(%s) fd=%lld bytes=%zu\n", pending.path,
			static_cast<long long>(fd), content.size());
		if (pending.exists)
		{
			CHECK(fd >= 3);
			CHECK(contains(content, kProcessName));
		}
		else
		{
			CHECK_EQ(fd, -1);
			CHECK_EQ(probe.guestErrno(), kEnoent);
		}
	}
}

void checkNoWriteLayer(const Tree &tree)
{
	auto created = RuntimeInstance::create(baseConfig(tree, false));
	CHECK_RESULT(created);
	if (!created.ok())
	{
		return;
	}
	VfsProbe probe(*created.value());
	if (!prepareVfsProbe(probe, romLibc()) ||
		!prepareRawSyscalls(probe, std::string(DUCKEMU_SO_DIR) + "/libvfsraw.so"))
	{
		return;
	}

	// Reads still see the read-only root.
	int64_t fd = -1;
	CHECK(probe.readWhole("/system/etc/ro.txt", fd) == "ro-data");
	CHECK(fd >= 3);

	const int64_t created_file = probe.openPath("/data/new.txt", kO_WrOnly | kO_Creat, 0600);
	std::printf("  no-layer open(/data/new.txt, O_CREAT) = %lld errno=%d\n",
		static_cast<long long>(created_file), probe.guestErrno());
	CHECK_EQ(created_file, -1);
	CHECK_EQ(probe.guestErrno(), kErofs);

	probe.writePath("/data/newdir");
	CHECK_EQ(static_cast<int64_t>(callGuest(probe.instance, probe.functions.mkdir,
			 { probe.path, 0700 })),
		-1);
	CHECK_EQ(probe.guestErrno(), kErofs);

	// The source only exists in the read-only root: mutations answer EROFS,
	// not ENOENT.
	probe.writePath("/data/preloaded.txt");
	CHECK_EQ(static_cast<int64_t>(callGuest(probe.instance, probe.functions.unlink,
			 { probe.path })),
		-1);
	CHECK_EQ(probe.guestErrno(), kErofs);

	CHECK_EQ(rawRename(probe, "/data/preloaded.txt", "/data/moved.txt"), -kErofs);
}

} // namespace

int main()
{
	Tree tree;
	tree.root = (fs::temp_directory_path() /
		     ("duckemu-vfs-mounts-root-" + std::to_string(::getpid())))
		     .string();
	tree.sandbox = (fs::temp_directory_path() /
			("duckemu-vfs-mounts-box-" + std::to_string(::getpid())))
			.string();
	if (!prepare(tree))
	{
		std::fprintf(stderr, "cannot prepare the mount fixture\n");
		return test::finish("10b_vfs_mounts");
	}

	auto created = RuntimeInstance::create(baseConfig(tree, true));
	CHECK_RESULT(created);
	if (created.ok())
	{
		VfsProbe probe(*created.value());
		if (prepareVfsProbe(probe, romLibc()) &&
			prepareRawSyscalls(probe, std::string(DUCKEMU_SO_DIR) + "/libvfsraw.so"))
		{
			checkSyntheticShadowing(probe);
			checkReadOnlyMounts(probe);
			checkProcPidMapping(probe);
		}
		checkNoWriteLayer(tree);
	}

	std::error_code ignored;
	fs::remove_all(tree.root, ignored);
	fs::remove_all(tree.sandbox, ignored);
	return test::finish("10b_vfs_mounts");
}

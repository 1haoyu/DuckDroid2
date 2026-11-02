// SPDX-License-Identifier: GPL-2.0-only
// M10 S2 gate: identity and open description are separate.
//   - two opens of one path have independent offsets
//   - dup shares the description (and therefore the offset)
//   - pread/pwrite use their own offset and never move the description
//   - O_APPEND survives into fcntl(F_GETFL) and ignores lseek
//   - stdio are real descriptor-table entries (close keeps them, dup works)
//   - open errors keep ENOENT/EISDIR/EROFS/EEXIST instead of collapsing to
//     EACCES; O_CREAT on a lower-only path copies up

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
constexpr uint64_t kOAppendFlag = 0x400;

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
		std::ofstream file(fs::path(tree.root) / "system" / "etc" / "ro.txt");
		file << "ro-data";
	}
	{
		std::ofstream file(fs::path(tree.sandbox) / "data" / "seed.txt");
		file << "0123456789";
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

void expectErrno(VfsProbe &probe, const char *what, int64_t result, int expected)
{
	const int observed = probe.guestErrno();
	std::printf("  %s = %lld errno=%d\n", what, static_cast<long long>(result), observed);
	CHECK_EQ(result, -1);
	CHECK_EQ(observed, expected);
}

void checkIndependentOffsets(VfsProbe &probe)
{
	const int64_t first = probe.openPath("/data/seed.txt", kO_RdOnly);
	const int64_t second = probe.openPath("/data/seed.txt", kO_RdOnly);
	CHECK(first >= 3);
	CHECK(second >= 3);
	if (first < 3 || second < 3)
	{
		return;
	}
	CHECK_EQ(probe.readFd(first, 4), 4);
	CHECK(probe.dataString(4) == "0123");
	// The second open starts at its own offset 0, not at the first's 4.
	CHECK_EQ(probe.readFd(second, 4), 4);
	CHECK(probe.dataString(4) == "0123");

	const int64_t copy = static_cast<int64_t>(
		callGuest(probe.instance, probe.functions.dup, { static_cast<uint64_t>(first) }));
	CHECK(copy >= 3);
	if (copy >= 3)
	{
		// dup shares the description: the next bytes are 4..5 and 6..7.
		CHECK_EQ(probe.readFd(first, 2), 2);
		CHECK(probe.dataString(2) == "45");
		CHECK_EQ(probe.readFd(copy, 2), 2);
		CHECK(probe.dataString(2) == "67");
		// A seek through the copy moves the original too.
		CHECK_EQ(probe.lseekFd(copy, 0, kSeekSet), 0);
		CHECK_EQ(probe.readFd(first, 1), 1);
		CHECK(probe.dataString(1) == "0");
		CHECK_EQ(probe.closeFd(copy), 0);
	}
	CHECK_EQ(probe.closeFd(first), 0);
	CHECK_EQ(probe.closeFd(second), 0);
}

void checkPositionalIo(VfsProbe &probe)
{
	const int64_t fd = probe.openPath("/data/local/io.txt", kO_RdWr | kO_Creat, 0600);
	CHECK(fd >= 3);
	if (fd < 3)
	{
		return;
	}

	CHECK_EQ(probe.pwriteFd(fd, "ABCDEFGH", 8, 4), 8);
	// pwrite leaves the description offset alone.
	CHECK_EQ(probe.lseekFd(fd, 0, kSeekCur), 0);
	CHECK_EQ(probe.preadFd(fd, 4, 8), 8);
	CHECK(probe.dataString(8) == "ABCDEFGH");
	CHECK_EQ(probe.lseekFd(fd, 0, kSeekCur), 0);

	CHECK_EQ(probe.statFd(fd), 0);
	CHECK_EQ(probe.statU64(kStatSizeOffset), 12u);

	// The hole before the first pwrite reads as zeroes.
	CHECK_EQ(probe.preadFd(fd, 0, 4), 4);
	CHECK(probe.dataString(4) == std::string(4, '\0'));

	// A plain write uses the description offset (still 0).
	CHECK_EQ(probe.writeFd(fd, "Z", 1), 1);
	CHECK_EQ(probe.preadFd(fd, 0, 1), 1);
	CHECK(probe.dataString(1) == "Z");

	// pwrite on a read-only description is EBADF, not a read-only mount.
	const int64_t read_only = probe.openPath("/data/seed.txt", kO_RdOnly);
	CHECK(read_only >= 3);
	if (read_only >= 3)
	{
		expectErrno(probe, "pwrite(O_RDONLY fd)", probe.pwriteFd(read_only, "x", 1, 0),
			kEbadf);
		CHECK_EQ(probe.closeFd(read_only), 0);
	}

	// pwrite on a pipe answers ESPIPE.
	CHECK_EQ(callGuest(probe.instance, probe.functions.pipe2, { probe.pair, 0 }), 0);
	uint32_t read_end = 0;
	uint32_t write_end = 0;
	CHECK_RESULT(
		probe.instance.readMemory(GuestVA{ probe.pair }, &read_end, sizeof(read_end)));
	CHECK_RESULT(
		probe.instance.readMemory(GuestVA{ probe.pair + 4 }, &write_end, sizeof(write_end)));
	if (write_end >= 3)
	{
		expectErrno(probe, "pwrite(pipe)",
			probe.pwriteFd(static_cast<int64_t>(write_end), "x", 1, 0), kEspipe);
	}
	if (read_end >= 3)
	{
		CHECK_EQ(probe.closeFd(read_end), 0);
	}
	if (write_end >= 3)
	{
		CHECK_EQ(probe.closeFd(write_end), 0);
	}

	CHECK_EQ(probe.closeFd(fd), 0);
}

void checkAppendAndTruncate(VfsProbe &probe)
{
	const int64_t append = probe.openPath("/data/local/io.txt", kO_WrOnly | kO_Append);
	CHECK(append >= 3);
	if (append < 3)
	{
		return;
	}
	CHECK_EQ(probe.fcntlFd(append, kF_GetFl),
		static_cast<int64_t>(kO_WrOnly | kOAppendFlag));
	// O_APPEND ignores the seek position.
	CHECK_EQ(probe.lseekFd(append, 0, kSeekSet), 0);
	CHECK_EQ(probe.writeFd(append, "XY", 2), 2);
	CHECK_EQ(probe.closeFd(append), 0);

	const int64_t reader = probe.openPath("/data/local/io.txt", kO_RdOnly);
	CHECK(reader >= 3);
	if (reader >= 3)
	{
		CHECK_EQ(probe.preadFd(reader, 12, 2), 2);
		CHECK(probe.dataString(2) == "XY");
		CHECK_EQ(probe.closeFd(reader), 0);
	}

	// O_TRUNC only reaches the writable copy.
	const int64_t truncated =
		probe.openPath("/data/local/io.txt", kO_WrOnly | kO_Trunc);
	CHECK(truncated >= 3);
	if (truncated >= 3)
	{
		CHECK_EQ(probe.statFd(truncated), 0);
		CHECK_EQ(probe.statU64(kStatSizeOffset), 0u);
		CHECK_EQ(probe.closeFd(truncated), 0);
	}
}

void checkAccessFlags(VfsProbe &probe)
{
	const int64_t read_only = probe.openPath("/data/seed.txt", kO_RdOnly);
	CHECK(read_only >= 3);
	if (read_only >= 3)
	{
		CHECK_EQ(probe.fcntlFd(read_only, kF_GetFl), 0);
		CHECK_EQ(probe.closeFd(read_only), 0);
	}

	const int64_t write_only = probe.openPath("/data/local/flags.txt",
		kO_WrOnly | kO_Creat, 0600);
	CHECK(write_only >= 3);
	if (write_only >= 3)
	{
		CHECK_EQ(probe.fcntlFd(write_only, kF_GetFl), 1);
		CHECK_EQ(probe.closeFd(write_only), 0);
	}

	const int64_t read_write = probe.openPath("/data/local/flags.txt", kO_RdWr);
	CHECK(read_write >= 3);
	if (read_write >= 3)
	{
		CHECK_EQ(probe.fcntlFd(read_write, kF_GetFl), 2);
		CHECK_EQ(probe.closeFd(read_write), 0);
	}
}

void checkStdio(VfsProbe &probe)
{
	// close(1) succeeds and stdout stays usable.
	CHECK_EQ(probe.closeFd(1), 0);
	CHECK_EQ(probe.writeFd(1, "s", 1), 1);

	const int64_t copy = static_cast<int64_t>(
		callGuest(probe.instance, probe.functions.dup, { 1 }));
	CHECK(copy >= 3);
	if (copy >= 3)
	{
		CHECK_EQ(probe.fcntlFd(copy, kF_GetFl), 1);
		CHECK_EQ(probe.statFd(copy), 0);
		CHECK_EQ(probe.statU32(kStatModeOffset) & kSIfmt, kSIfchr);
		CHECK_EQ(probe.statU32(kStatModeOffset) & 0777, 0666u);
		// fstat(1) goes through fstatat(AT_EMPTY_PATH) inside bionic.
		CHECK_EQ(probe.statFd(1), 0);
		CHECK_EQ(probe.statU32(kStatModeOffset) & kSIfmt, kSIfchr);
		// fsync(1) is a no-op success; lseek/read are ESPIPE/EBADF.
		CHECK_EQ(callGuest(probe.instance, probe.functions.fsync,
				 { static_cast<uint64_t>(copy) }),
			0);
		expectErrno(probe, "lseek(stdout)",
			probe.lseekFd(copy, 0, kSeekSet), kEspipe);
		CHECK(failed(probe.readFd(copy, 1)));
		CHECK_EQ(probe.guestErrno(), kEbadf);
		CHECK_EQ(probe.closeFd(copy), 0);
	}

	// close(2) is likewise permanent and stderr keeps writing.
	CHECK_EQ(probe.closeFd(2), 0);
	CHECK_EQ(probe.writeFd(2, "e", 1), 1);
}

void checkErrorFidelity(VfsProbe &probe)
{
	// Missing file with a write intent.
	expectErrno(probe, "open(/data/nope.txt, O_WRONLY)",
		probe.openPath("/data/nope.txt", kO_WrOnly), kEnoent);

	// A directory opened for writing is EISDIR, not EACCES.
	expectErrno(probe, "open(/data, O_WRONLY)", probe.openPath("/data", kO_WrOnly),
		kEisdir);

	// Lower-only file: a write intent without O_CREAT is EROFS.
	expectErrno(probe, "open(ro.txt, O_WRONLY)",
		probe.openPath("/system/etc/ro.txt", kO_WrOnly), kErofs);
	expectErrno(probe, "open(ro.txt, O_WRONLY|O_TRUNC)",
		probe.openPath("/system/etc/ro.txt", kO_WrOnly | kO_Trunc), kErofs);

	// O_EXCL also consults the lower layer.
	expectErrno(probe, "open(ro.txt, O_CREAT|O_EXCL)",
		probe.openPath("/system/etc/ro.txt", kO_WrOnly | kO_Creat | kO_Excl, 0600),
		kEexist);

	// O_CREAT copies up: the new upper file shadows the lower tree, and the
	// lower file itself is untouched.
	const int64_t copy_up = probe.openPath("/system/etc/copied.txt",
		kO_WrOnly | kO_Creat, 0600);
	CHECK(copy_up >= 3);
	if (copy_up >= 3)
	{
		CHECK_EQ(probe.writeFd(copy_up, "copy", 4), 4);
		CHECK_EQ(probe.closeFd(copy_up), 0);
	}
	int64_t read_fd = -1;
	CHECK(probe.readWhole("/system/etc/copied.txt", read_fd) == "copy");
	CHECK(probe.readWhole("/system/etc/ro.txt", read_fd) == "ro-data");
}

} // namespace

int main()
{
	Tree tree;
	tree.root = (fs::temp_directory_path() /
		     ("duckemu-vfs-open-root-" + std::to_string(::getpid())))
		     .string();
	tree.sandbox = (fs::temp_directory_path() /
			("duckemu-vfs-open-box-" + std::to_string(::getpid())))
			.string();
	if (!prepare(tree))
	{
		std::fprintf(stderr, "cannot prepare the open-description fixture\n");
		return test::finish("10c_vfs_open_description");
	}

	auto created = RuntimeInstance::create(baseConfig(tree));
	CHECK_RESULT(created);
	if (created.ok())
	{
		VfsProbe probe(*created.value());
		if (prepareVfsProbe(probe, romLibc()))
		{
			checkIndependentOffsets(probe);
			checkPositionalIo(probe);
			checkAppendAndTruncate(probe);
			checkAccessFlags(probe);
			checkStdio(probe);
			checkErrorFidelity(probe);
		}
	}

	std::error_code ignored;
	fs::remove_all(tree.root, ignored);
	fs::remove_all(tree.sandbox, ignored);
	return test::finish("10c_vfs_open_description");
}

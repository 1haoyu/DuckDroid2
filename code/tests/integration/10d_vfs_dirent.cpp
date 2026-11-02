// SPDX-License-Identifier: GPL-2.0-only
// M10 S3 gate: directory enumeration.
//   - every mount answers readdir: sandbox /data, read-only /system, /proc,
//     /dev and /dev/__properties__
//   - d_ino equals fstatat's st_ino; d_type distinguishes dir/reg/chr
//   - partial buffers never consume unwritten entries; an entry that cannot
//     fit alone answers EINVAL; EOF returns 0
//   - lseek(fd, 0, SEEK_SET) rewinds; dup shares the cursor
//   - the overlay de-duplicates upper/lower names and an upper deletion leaves
//     a whiteout that keeps the lower copy hidden

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <string>
#include <unistd.h>
#include <vector>

#include "runtime/instance/runtime_instance.hpp"
#include "support/test_harness.hpp"
#include "support/vfs_probe.hpp"

using namespace duckemu;
using namespace duckemu::runtime;
using namespace duckemu::test;

namespace
{

namespace fs = std::filesystem;

constexpr uint32_t kPid = 777;
constexpr uint32_t kTid = 1;
constexpr uint64_t kDirentHeader = 19;
constexpr uint64_t kBigBuffer = 4096;

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
	fs::create_directories(fs::path(tree.sandbox) / "data", error);
	fs::create_directories(fs::path(tree.sandbox) / "system", error);
	if (error)
	{
		return false;
	}
	{
		std::ofstream ro(fs::path(tree.root) / "system" / "etc" / "ro.txt");
		ro << "ro";
		std::ofstream shared(fs::path(tree.root) / "system" / "shared.txt");
		shared << "lower-shared";
		std::ofstream shadowed(fs::path(tree.root) / "system" / "shadowed.txt");
		shadowed << "lower";
		std::ofstream status(fs::path(tree.root) / "proc" / "self" / "status");
		status << "Name:\tsnapshot\n";
		std::ofstream alpha(fs::path(tree.sandbox) / "data" / "alpha.txt");
		alpha << "a";
		std::ofstream beta(fs::path(tree.sandbox) / "data" / "beta.txt");
		beta << "b";
		std::ofstream upper(fs::path(tree.sandbox) / "system" / "shadowed.txt");
		upper << "upper";
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

struct ParsedEntry
{
	uint64_t ino = 0;
	int64_t off = 0;
	uint16_t reclen = 0;
	uint8_t type = 0;
	std::string name;
};

uint64_t recordLength(std::string_view name)
{
	return (kDirentHeader + name.size() + 1 + 7) & ~uint64_t{ 7 };
}

std::vector<ParsedEntry> parseEntries(VfsProbe &probe, uint64_t bytes)
{
	std::vector<uint8_t> raw(static_cast<size_t>(bytes));
	CHECK_RESULT(probe.instance.readMemory(GuestVA{ probe.data }, raw.data(), bytes));
	std::vector<ParsedEntry> entries;
	uint64_t offset = 0;
	while (offset + kDirentHeader <= bytes)
	{
		ParsedEntry entry;
		std::memcpy(&entry.ino, raw.data() + offset, 8);
		std::memcpy(&entry.off, raw.data() + offset + 8, 8);
		std::memcpy(&entry.reclen, raw.data() + offset + 16, 2);
		entry.type = raw[offset + 18];
		if (entry.reclen == 0 || offset + entry.reclen > bytes)
		{
			break;
		}
		const size_t name_capacity = entry.reclen - kDirentHeader;
		entry.name.assign(reinterpret_cast<const char *>(raw.data() + offset + kDirentHeader),
			strnlen(reinterpret_cast<const char *>(raw.data() + offset + kDirentHeader),
				name_capacity));
		entries.push_back(std::move(entry));
		offset += entry.reclen;
	}
	return entries;
}

// One getdents64 call. Returns the byte count, or the negative errno.
int64_t getdents(VfsProbe &probe, int64_t fd, uint64_t count)
{
	return probe.raw(61 /* getdents64 */, static_cast<uint64_t>(fd), probe.data, count);
}

std::vector<ParsedEntry> readAll(VfsProbe &probe, int64_t fd, size_t limit = 1 << 16)
{
	std::vector<ParsedEntry> all;
	while (all.size() < limit)
	{
		const int64_t bytes = getdents(probe, fd, kBigBuffer);
		CHECK(bytes >= 0);
		if (bytes <= 0)
		{
			break;
		}
		std::vector<ParsedEntry> batch = parseEntries(probe, static_cast<uint64_t>(bytes));
		CHECK(!batch.empty());
		all.insert(all.end(), batch.begin(), batch.end());
	}
	return all;
}

int64_t openDir(VfsProbe &probe, std::string_view path)
{
	return probe.openPath(path, kO_RdOnly | kO_Directory);
}

void checkNames(const std::vector<ParsedEntry> &entries,
	std::string_view what,
	const std::vector<std::string> &expected)
{
	std::vector<std::string> names;
	names.reserve(entries.size());
	for (const ParsedEntry &entry : entries)
	{
		names.push_back(entry.name);
	}
	std::printf("  %s entries:", std::string(what).c_str());
	for (const std::string &name : names)
	{
		std::printf(" %s", name.c_str());
	}
	std::printf("\n");
	std::sort(names.begin(), names.end());
	std::vector<std::string> wanted = expected;
	std::sort(wanted.begin(), wanted.end());
	CHECK(names == wanted);
}

bool hasEntry(const std::vector<ParsedEntry> &entries, std::string_view name)
{
	return std::any_of(entries.begin(), entries.end(),
		[&](const ParsedEntry &entry) { return entry.name == name; });
}

const ParsedEntry *findEntry(const std::vector<ParsedEntry> &entries, std::string_view name)
{
	for (const ParsedEntry &entry : entries)
	{
		if (entry.name == name)
		{
			return &entry;
		}
	}
	return nullptr;
}

void checkDinoMatchesStat(VfsProbe &probe, const std::vector<ParsedEntry> &entries,
	std::string_view directory)
{
	for (const ParsedEntry &entry : entries)
	{
		if (entry.name == "." || entry.name == "..")
		{
			continue;
		}
		const std::string path = std::string(directory) + "/" + entry.name;
		CHECK_EQ(probe.statPath(path), 0);
		const uint64_t inode = probe.statU64(8);
		if (entry.ino != inode)
		{
			std::fprintf(stderr, "  d_ino mismatch for %s: %llu vs %llu\n",
				path.c_str(), static_cast<unsigned long long>(entry.ino),
				static_cast<unsigned long long>(inode));
		}
		CHECK_EQ(entry.ino, inode);
	}
}

void checkDataDirectory(VfsProbe &probe)
{
	const int64_t fd = openDir(probe, "/data");
	CHECK(fd >= 3);
	if (fd < 3)
	{
		return;
	}
	const std::vector<ParsedEntry> entries = readAll(probe, fd);
	checkNames(entries, "/data", { ".", "..", "alpha.txt", "beta.txt" });
	CHECK(entries.size() >= 4);
	if (!entries.empty())
	{
		CHECK_EQ(entries.front().type, kDtDir);
		CHECK(entries.front().name == ".");
	}
	if (entries.size() > 1)
	{
		CHECK(entries[1].name == "..");
		CHECK_EQ(entries[1].type, kDtDir);
	}
	for (const ParsedEntry &entry : entries)
	{
		if (entry.name == "alpha.txt" || entry.name == "beta.txt")
		{
			CHECK_EQ(entry.type, kDtReg);
		}
	}
	// d_off is the index+1 sequence.
	for (size_t index = 0; index < entries.size(); ++index)
	{
		CHECK_EQ(entries[index].off, static_cast<int64_t>(index + 1));
	}
	checkDinoMatchesStat(probe, entries, "/data");
	CHECK_EQ(probe.closeFd(fd), 0);
}

void checkPartialBuffers(VfsProbe &probe)
{
	const int64_t fd = openDir(probe, "/data");
	CHECK(fd >= 3);
	if (fd < 3)
	{
		return;
	}
	const std::vector<ParsedEntry> all = readAll(probe, fd);
	CHECK(all.size() >= 3);
	if (all.size() < 3)
	{
		probe.closeFd(fd);
		return;
	}

	// Rewind and fill a buffer one byte short of three records: exactly two
	// complete entries come back and the third stays for the next call.
	CHECK_EQ(probe.lseekFd(fd, 0, kSeekSet), 0);
	const uint64_t partial = recordLength(all[0].name) + recordLength(all[1].name) +
				 recordLength(all[2].name) - 1;
	const int64_t first = getdents(probe, fd, partial);
	CHECK(first > 0);
	std::vector<ParsedEntry> first_entries;
	if (first > 0)
	{
		first_entries = parseEntries(probe, static_cast<uint64_t>(first));
	}
	CHECK_EQ(first_entries.size(), 2u);
	if (first_entries.size() == 2)
	{
		CHECK(first_entries[0].name == all[0].name);
		CHECK(first_entries[1].name == all[1].name);
	}
	const int64_t second = getdents(probe, fd, kBigBuffer);
	CHECK(second > 0);
	std::vector<ParsedEntry> second_entries;
	if (second > 0)
	{
		second_entries = parseEntries(probe, static_cast<uint64_t>(second));
	}
	CHECK(!second_entries.empty());
	if (!second_entries.empty())
	{
		CHECK(second_entries.front().name == all[2].name);
	}

	// Exact fit returns exactly the requested records.
	CHECK_EQ(probe.lseekFd(fd, 0, kSeekSet), 0);
	const uint64_t exact = recordLength(all[0].name) + recordLength(all[1].name);
	const int64_t exact_bytes = getdents(probe, fd, exact);
	CHECK_EQ(exact_bytes, static_cast<int64_t>(exact));
	if (exact_bytes > 0)
	{
		CHECK_EQ(parseEntries(probe, static_cast<uint64_t>(exact_bytes)).size(), 2u);
	}

	// Not even one record: EINVAL, and the cursor does not move.
	CHECK_EQ(probe.lseekFd(fd, 0, kSeekSet), 0);
	const int64_t too_small = getdents(probe, fd, 8);
	std::printf("  getdents(8) = %lld\n", static_cast<long long>(too_small));
	CHECK_EQ(too_small, -kEinval);
	const int64_t after_einval = getdents(probe, fd, kBigBuffer);
	CHECK(after_einval > 0);
	if (after_einval > 0)
	{
		const std::vector<ParsedEntry> entries =
			parseEntries(probe, static_cast<uint64_t>(after_einval));
		CHECK(!entries.empty());
		if (!entries.empty())
		{
			CHECK(entries.front().name == all[0].name);
		}
	}

	// EOF returns 0; a rewind starts the snapshot again.
	CHECK_EQ(getdents(probe, fd, kBigBuffer), 0);
	CHECK_EQ(probe.lseekFd(fd, 0, kSeekSet), 0);
	CHECK_EQ(readAll(probe, fd).size(), all.size());
	CHECK_EQ(probe.closeFd(fd), 0);
}

void checkRewindAndDup(VfsProbe &probe)
{
	const int64_t fd = openDir(probe, "/data");
	CHECK(fd >= 3);
	if (fd < 3)
	{
		return;
	}
	const std::vector<ParsedEntry> all = readAll(probe, fd);
	CHECK(all.size() >= 2);
	if (all.size() < 2)
	{
		probe.closeFd(fd);
		return;
	}

	// lseek(0) rewinds the snapshot; a buffer holding exactly one record
	// advances the cursor by one.
	CHECK_EQ(probe.lseekFd(fd, 0, kSeekSet), 0);
	const int64_t first = getdents(probe, fd, recordLength(all[0].name));
	CHECK(first > 0);
	if (first > 0)
	{
		const std::vector<ParsedEntry> entries =
			parseEntries(probe, static_cast<uint64_t>(first));
		CHECK_EQ(entries.size(), 1u);
		if (!entries.empty())
		{
			CHECK(entries.front().name == all[0].name);
		}
	}

	// dup shares the directory description, hence the cursor.
	const int64_t copy = static_cast<int64_t>(
		callGuest(probe.instance, probe.functions.dup, { static_cast<uint64_t>(fd) }));
	CHECK(copy >= 3);
	if (copy >= 3)
	{
		const int64_t through_copy = getdents(probe, copy, recordLength(all[1].name));
		CHECK(through_copy > 0);
		const std::vector<ParsedEntry> entries =
			parseEntries(probe, static_cast<uint64_t>(through_copy));
		CHECK_EQ(entries.size(), 1u);
		if (!entries.empty())
		{
			CHECK(entries.front().name == all[1].name);
		}
		// A rewind through either descriptor rewinds both.
		CHECK_EQ(probe.lseekFd(copy, 0, kSeekSet), 0);
		const int64_t after_rewind = getdents(probe, fd, recordLength(all[0].name));
		CHECK(after_rewind > 0);
		if (after_rewind > 0)
		{
			const std::vector<ParsedEntry> rewound =
				parseEntries(probe, static_cast<uint64_t>(after_rewind));
			CHECK(!rewound.empty() && rewound.front().name == all[0].name);
		}
		CHECK_EQ(probe.closeFd(copy), 0);
	}
	// Only SEEK_SET within the snapshot is meaningful.
	CHECK_EQ(probe.lseekFd(fd, static_cast<int64_t>(all.size() + 1), kSeekSet), -1);
	CHECK_EQ(probe.guestErrno(), kEinval);
	CHECK_EQ(probe.lseekFd(fd, 0, kSeekCur), -1);
	CHECK_EQ(probe.guestErrno(), kEinval);
	CHECK_EQ(probe.closeFd(fd), 0);
}

void checkSystemAndWhiteout(VfsProbe &probe)
{
	const int64_t fd = openDir(probe, "/system");
	CHECK(fd >= 3);
	if (fd < 3)
	{
		return;
	}
	std::vector<ParsedEntry> entries = readAll(probe, fd);
	// shared.txt comes only from the lower layer; shadowed.txt exists twice and
	// must appear once (upper wins); etc is a directory.
	checkNames(entries, "/system", { ".", "..", "etc", "shadowed.txt", "shared.txt" });
	const ParsedEntry *etc = findEntry(entries, "etc");
	CHECK(etc != nullptr && etc->type == kDtDir);
	CHECK(!hasEntry(entries, "ro.txt"));
	checkDinoMatchesStat(probe, entries, "/system");
	CHECK_EQ(probe.closeFd(fd), 0);

	// Deleting the upper copy leaves a whiteout: the lower copy must not
	// reappear in a fresh enumeration or through stat.
	probe.writePath("/system/shadowed.txt");
	CHECK_EQ(static_cast<int64_t>(callGuest(probe.instance, probe.functions.unlink,
			 { probe.path })),
		0);
	CHECK_EQ(probe.statPath("/system/shadowed.txt"), -1);
	CHECK_EQ(probe.guestErrno(), kEnoent);

	const int64_t after = openDir(probe, "/system");
	CHECK(after >= 3);
	if (after >= 3)
	{
		entries = readAll(probe, after);
		checkNames(entries, "/system after unlink",
			{ ".", "..", "etc", "shared.txt" });
		CHECK_EQ(probe.closeFd(after), 0);
	}
}

void checkProcDevices(VfsProbe &probe)
{
	// /proc lists the synthesized process entries plus anything the snapshot
	// carries.
	const int64_t proc_fd = openDir(probe, "/proc");
	CHECK(proc_fd >= 3);
	if (proc_fd >= 3)
	{
		const std::vector<ParsedEntry> entries = readAll(probe, proc_fd);
		checkNames(entries, "/proc",
			{ ".", "..", "version", "cpuinfo", "self", std::to_string(kPid),
				"thread-self" });
		const ParsedEntry *self = findEntry(entries, "self");
		CHECK(self != nullptr && self->type == kDtDir);
		checkDinoMatchesStat(probe, entries, "/proc");
		CHECK_EQ(probe.closeFd(proc_fd), 0);
	}

	const int64_t self_fd = openDir(probe, "/proc/self");
	CHECK(self_fd >= 3);
	if (self_fd >= 3)
	{
		const std::vector<ParsedEntry> entries = readAll(probe, self_fd);
		for (const char *name : { "status", "maps", "mem", "auxv", "cmdline", "comm" })
		{
			CHECK(hasEntry(entries, name));
		}
		const ParsedEntry *status = findEntry(entries, "status");
		CHECK(status != nullptr && status->type == kDtReg);
		checkDinoMatchesStat(probe, entries, "/proc/self");
		CHECK_EQ(probe.closeFd(self_fd), 0);
	}

	const int64_t dev_fd = openDir(probe, "/dev");
	CHECK(dev_fd >= 3);
	if (dev_fd >= 3)
	{
		const std::vector<ParsedEntry> entries = readAll(probe, dev_fd);
		checkNames(entries, "/dev",
			{ ".", "..", "null", "zero", "random", "urandom", "__properties__" });
		const ParsedEntry *null_entry = findEntry(entries, "null");
		CHECK(null_entry != nullptr && null_entry->type == kDtChr);
		const ParsedEntry *properties = findEntry(entries, "__properties__");
		CHECK(properties != nullptr && properties->type == kDtDir);
		checkDinoMatchesStat(probe, entries, "/dev");
		CHECK_EQ(probe.closeFd(dev_fd), 0);
	}

	const int64_t property_fd = openDir(probe, "/dev/__properties__");
	CHECK(property_fd >= 3);
	if (property_fd >= 3)
	{
		const std::vector<ParsedEntry> entries = readAll(probe, property_fd);
		CHECK(hasEntry(entries, "property_info"));
		CHECK(hasEntry(entries, "properties_serial"));
		const ParsedEntry *info = findEntry(entries, "property_info");
		CHECK(info != nullptr && info->type == kDtReg);
		for (const ParsedEntry &entry : entries)
		{
			if (entry.name == "." || entry.name == "..")
			{
				continue;
			}
			const std::string path = "/dev/__properties__/" + entry.name;
			CHECK_EQ(probe.statPath(path), 0);
			CHECK_EQ(entry.ino, probe.statU64(8));
		}
		CHECK_EQ(probe.closeFd(property_fd), 0);
	}
}

} // namespace

int main()
{
	Tree tree;
	tree.root = (fs::temp_directory_path() /
		     ("duckemu-vfs-dirent-root-" + std::to_string(::getpid())))
		     .string();
	tree.sandbox = (fs::temp_directory_path() /
			("duckemu-vfs-dirent-box-" + std::to_string(::getpid())))
			.string();
	if (!prepare(tree))
	{
		std::fprintf(stderr, "cannot prepare the dirent fixture\n");
		return test::finish("10d_vfs_dirent");
	}

	auto created = RuntimeInstance::create(baseConfig(tree));
	CHECK_RESULT(created);
	if (created.ok())
	{
		VfsProbe probe(*created.value());
		if (prepareVfsProbe(probe, romLibc()) &&
			prepareRawSyscalls(probe, std::string(DUCKEMU_SO_DIR) + "/libvfsraw.so"))
		{
			checkDataDirectory(probe);
			checkPartialBuffers(probe);
			checkRewindAndDup(probe);
			checkSystemAndWhiteout(probe);
			checkProcDevices(probe);
		}
	}

	std::error_code ignored;
	fs::remove_all(tree.root, ignored);
	fs::remove_all(tree.sandbox, ignored);
	return test::finish("10d_vfs_dirent");
}

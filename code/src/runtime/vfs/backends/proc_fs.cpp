// SPDX-License-Identifier: GPL-2.0-only
#include "runtime/vfs/backends/proc_fs.hpp"

#include <map>
#include <memory>
#include <sys/stat.h>
#include <unistd.h>
#include <utility>
#include <vector>

#include "runtime/vfs/backends/overlay_fs.hpp"
#include "runtime/vfs/vfs_flags.hpp"

namespace duckemu::runtime::vfs
{
namespace
{

FileStat directoryStat(std::string_view guest_path)
{
	FileStat result;
	result.inode = std::hash<std::string>{}(std::string(guest_path));
	result.mode = S_IFDIR | 0555;
	result.link_count = 2;
	result.uid = 0;
	result.gid = 0;
	return result;
}

} // namespace

ProcFs::ProcFs(OverlayFs *snapshot, ContextProvider context)
	: snapshot_(snapshot)
	, context_(std::move(context))
	, pid_(context_().pid)
{
}

std::string ProcFs::mapProcessComponent(std::string_view relative, uint32_t pid)
{
	const size_t slash = relative.find('/');
	const std::string_view first = relative.substr(0, slash);
	if (first == std::to_string(pid) || first == "thread-self")
	{
		std::string mapped = "self";
		if (slash != std::string_view::npos)
		{
			mapped.append(relative.substr(slash));
		}
		return mapped;
	}
	return std::string(relative);
}

Result<std::string> ProcFs::snapshotPath(std::string_view relative) const
{
	// The snapshot lives under the host roots at /proc/<snapshot-relative>.
	// A process-relative file is stored under self/.
	const std::string mapped = mapProcessComponent(relative, pid_);
	const std::string root_relative = mapped.empty() ? "proc" : "proc/" + mapped;
	auto entry = snapshot_->resolveRead(root_relative);
	if (!entry.ok())
	{
		return entry.error();
	}
	return entry.value().path;
}

bool ProcFs::isSyntheticDirectory(std::string_view relative) const
{
	if (relative.empty())
	{
		return true;
	}
	const size_t slash = relative.find('/');
	const std::string_view first = relative.substr(0, slash);
	const bool process_directory = first == "self" || first == "thread-self" ||
				       first == std::to_string(pid_);
	if (!process_directory)
	{
		return false;
	}
	return slash == std::string_view::npos;
}

Result<FileStat> ProcFs::stat(const std::string &guest_path, const std::string &relative) const
{
	auto snapshot = snapshotPath(relative);
	if (snapshot.ok())
	{
		struct stat info = {};
		if (::stat(snapshot.value().c_str(), &info) != 0)
		{
			return Error{ ErrorCode::NotFound, "cannot stat " + guest_path };
		}
		FileStat result;
		result.device = static_cast<uint64_t>(info.st_dev);
		result.inode = static_cast<uint64_t>(info.st_ino);
		result.mode = static_cast<uint32_t>(info.st_mode);
		result.link_count = static_cast<uint32_t>(info.st_nlink);
		result.uid = static_cast<uint32_t>(info.st_uid);
		result.gid = static_cast<uint32_t>(info.st_gid);
		result.size = static_cast<uint64_t>(info.st_size);
		result.blocks = static_cast<uint64_t>(info.st_blocks);
		result.block_size = static_cast<uint32_t>(info.st_blksize);
		result.atime_seconds = info.st_atim.tv_sec;
		result.atime_nanoseconds = info.st_atim.tv_nsec;
		result.mtime_seconds = info.st_mtim.tv_sec;
		result.mtime_nanoseconds = info.st_mtim.tv_nsec;
		result.ctime_seconds = info.st_ctim.tv_sec;
		result.ctime_nanoseconds = info.st_ctim.tv_nsec;
		return result;
	}

	if (isSyntheticDirectory(relative))
	{
		return directoryStat(guest_path);
	}

	auto generator = makeGenerator(guest_path, context_());
	if (!generator.has_value())
	{
		return Error{ ErrorCode::NotFound, "no such proc file: " + guest_path };
	}
	MemoryFile file(guest_path, std::move(generator.value()));
	return file.stat();
}

Result<std::unique_ptr<File> > ProcFs::open(const std::string &guest_path,
	const std::string &relative,
	uint64_t flags,
	uint64_t) const
{
	if (writesRequested(flags))
	{
		return Error{ ErrorCode::ReadOnly, guest_path + " is read-only" };
	}
	auto snapshot = snapshotPath(relative);
	if (snapshot.ok())
	{
		struct stat info = {};
		const bool directory = ::stat(snapshot.value().c_str(), &info) == 0 && S_ISDIR(info.st_mode);
		if (directory)
		{
			return Error{ ErrorCode::IsDirectory, guest_path + " is a directory" };
		}
		if ((flags & kODirectory) != 0)
		{
			return Error{ ErrorCode::NotDirectory, guest_path + " is not a directory" };
		}
		auto opened = HostFile::open(guest_path, snapshot.value());
		if (!opened.ok())
		{
			return opened.error();
		}
		return std::unique_ptr<File>(std::move(opened.value()));
	}

	if (isSyntheticDirectory(relative))
	{
		return Error{ ErrorCode::IsDirectory, guest_path + " is a directory" };
	}

	auto generator = makeGenerator(guest_path, context_());
	if (!generator.has_value())
	{
		return Error{ ErrorCode::NotFound, "no such proc file: " + guest_path };
	}
	if ((flags & kODirectory) != 0)
	{
		return Error{ ErrorCode::NotDirectory, guest_path + " is not a directory" };
	}
	return std::unique_ptr<File>(new MemoryFile(guest_path, std::move(generator.value())));
}

Result<std::vector<DirEntry> > ProcFs::readdir(const std::string &guest_path,
	const std::string &relative) const
{
	std::map<std::string, DirEntry> merged;

	bool snapshot_directory = false;
	auto snapshot = snapshotPath(relative);
	if (snapshot.ok())
	{
		struct stat info = {};
		if (::stat(snapshot.value().c_str(), &info) != 0)
		{
			return Error{ ErrorCode::NotFound, "cannot stat " + guest_path };
		}
		snapshot_directory = S_ISDIR(info.st_mode);
		if (!snapshot_directory && !isSyntheticDirectory(relative))
		{
			return Error{ ErrorCode::NotDirectory, guest_path + " is not a directory" };
		}
		if (snapshot_directory)
		{
			const std::string mapped = mapProcessComponent(relative, pid_);
			const std::string root_relative =
				mapped.empty() ? "proc" : "proc/" + mapped;
			auto entries = snapshot_->readdir(guest_path, root_relative);
			if (entries.ok())
			{
				for (DirEntry &entry : entries.value())
				{
					merged.emplace(entry.name, std::move(entry));
				}
			}
		}
	}

	if (!snapshot_directory && !isSyntheticDirectory(relative))
	{
		return Error{ ErrorCode::NotFound, "no such proc directory: " + guest_path };
	}

	const auto add = [&merged](std::string name, uint8_t type) {
		DirEntry entry;
		entry.name = std::move(name);
		entry.type = type;
		merged.emplace(entry.name, std::move(entry));
	};
	if (relative.empty())
	{
		add("version", kDirTypeRegular);
		add("cpuinfo", kDirTypeRegular);
		add("self", kDirTypeDirectory);
		add(std::to_string(pid_), kDirTypeDirectory);
		add("thread-self", kDirTypeDirectory);
	}
	else if (isSyntheticDirectory(relative))
	{
		add("maps", kDirTypeRegular);
		add("mem", kDirTypeRegular);
		add("status", kDirTypeRegular);
		add("auxv", kDirTypeRegular);
		add("cmdline", kDirTypeRegular);
		add("comm", kDirTypeRegular);
		add("version", kDirTypeRegular);
		add("cpuinfo", kDirTypeRegular);
	}

	std::vector<DirEntry> result;
	result.reserve(merged.size());
	for (auto &entry : merged)
	{
		result.push_back(std::move(entry.second));
	}
	return result;
}

Result<void> ProcFs::access(const std::string &guest_path,
	const std::string &relative,
	uint64_t mode) const
{
	if ((mode & kAccessWrite) != 0)
	{
		return Error{ ErrorCode::PermissionDenied, guest_path + " is read-only" };
	}
	if ((mode & kAccessExecute) != 0)
	{
		return Error{ ErrorCode::PermissionDenied, "execute access is not modelled" };
	}
	auto snapshot = snapshotPath(relative);
	if (snapshot.ok())
	{
		if ((mode & kAccessRead) != 0 && ::access(snapshot.value().c_str(), R_OK) != 0)
		{
			return Error{ ErrorCode::PermissionDenied, "cannot read " + guest_path };
		}
		return {};
	}
	if (isSyntheticDirectory(relative))
	{
		return {};
	}
	if (!makeGenerator(guest_path, context_()).has_value())
	{
		return Error{ ErrorCode::NotFound, "no such proc file: " + guest_path };
	}
	return {};
}

} // namespace duckemu::runtime::vfs

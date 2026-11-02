// SPDX-License-Identifier: GPL-2.0-only
#include "runtime/vfs/backends/host_ro_fs.hpp"

#include <cerrno>
#include <filesystem>
#include <sys/stat.h>
#include <unistd.h>
#include <utility>

#include "runtime/vfs/backends/host_paths.hpp"
#include "runtime/vfs/vfs_error.hpp"
#include "runtime/vfs/vfs_flags.hpp"

namespace duckemu::runtime::vfs
{

HostRoFs::HostRoFs(std::string root)
	: root_(std::move(root))
	, canonical_root_(canonicalRoot(root_))
{
}

Result<HostRoFs::HostEntry> HostRoFs::resolve(std::string_view relative) const
{
	namespace fs = std::filesystem;
	if (canonical_root_.empty())
	{
		return Error{ ErrorCode::Internal, "read-only root is unreadable: " + root_ };
	}
	const fs::path root(canonical_root_);
	const fs::path candidate = relative.empty() ?
					   root :
					   root / fs::path(std::string(relative));
	std::error_code error;
	const fs::file_status status = fs::status(candidate, error);
	if (error || !fs::exists(status))
	{
		return Error{ ErrorCode::NotFound, std::string("/") + std::string(relative) };
	}
	const fs::path canonical = fs::weakly_canonical(candidate, error);
	if (error || !isWithin(canonical, root))
	{
		// A symlink that leaves the mounted tree is not part of the guest
		// namespace.
		return Error{ ErrorCode::NotFound, std::string("/") + std::string(relative) };
	}
	HostEntry entry;
	entry.path = canonical.string();
	entry.directory = fs::is_directory(status);
	return entry;
}

Result<FileStat> HostRoFs::stat(const std::string &guest_path, const std::string &relative) const
{
	auto entry = resolve(relative);
	if (!entry.ok())
	{
		return entry.error();
	}
	struct stat info = {};
	if (::stat(entry.value().path.c_str(), &info) != 0)
	{
		return errnoToError(errno, "cannot stat " + guest_path);
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

Result<std::unique_ptr<File> > HostRoFs::open(const std::string &guest_path,
	const std::string &relative,
	uint64_t flags,
	uint64_t) const
{
	if (writesRequested(flags))
	{
		return Error{ ErrorCode::ReadOnly, guest_path + " is read-only" };
	}
	auto entry = resolve(relative);
	if (!entry.ok())
	{
		return entry.error();
	}
	if (entry.value().directory)
	{
		return Error{ ErrorCode::IsDirectory, guest_path + " is a directory" };
	}
	if ((flags & kODirectory) != 0)
	{
		return Error{ ErrorCode::NotDirectory, guest_path + " is not a directory" };
	}
	auto opened = HostFile::open(guest_path, entry.value().path);
	if (!opened.ok())
	{
		return opened.error();
	}
	return std::unique_ptr<File>(std::move(opened.value()));
}

Result<std::vector<DirEntry> > HostRoFs::readdir(const std::string &guest_path,
	const std::string &relative) const
{
	auto entry = resolve(relative);
	if (!entry.ok())
	{
		return entry.error();
	}
	if (!entry.value().directory)
	{
		return Error{ ErrorCode::NotDirectory, guest_path + " is not a directory" };
	}
	return listHostDirectory(entry.value().path, guest_path);
}

Result<void> HostRoFs::access(const std::string &guest_path,
	const std::string &relative,
	uint64_t mode) const
{
	auto entry = resolve(relative);
	if (!entry.ok())
	{
		return entry.error();
	}
	if ((mode & kAccessRead) != 0 && ::access(entry.value().path.c_str(), R_OK) != 0)
	{
		return Error{ ErrorCode::PermissionDenied, "cannot read " + guest_path };
	}
	if ((mode & kAccessWrite) != 0)
	{
		return Error{ ErrorCode::PermissionDenied, guest_path + " is read-only" };
	}
	if ((mode & kAccessExecute) != 0)
	{
		// Execution is decided by the mapping permissions, not by access(2).
		return Error{ ErrorCode::PermissionDenied, "execute access is not modelled" };
	}
	return {};
}

} // namespace duckemu::runtime::vfs

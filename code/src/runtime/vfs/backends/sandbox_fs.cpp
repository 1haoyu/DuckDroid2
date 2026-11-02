// SPDX-License-Identifier: GPL-2.0-only
#include "runtime/vfs/backends/sandbox_fs.hpp"

#include <cerrno>
#include <fcntl.h>
#include <filesystem>
#include <sys/stat.h>
#include <unistd.h>
#include <utility>

#include "runtime/vfs/backends/host_paths.hpp"
#include "runtime/vfs/vfs_error.hpp"
#include "runtime/vfs/vfs_flags.hpp"

namespace duckemu::runtime::vfs
{

SandboxFs::SandboxFs(std::string root)
	: root_(std::move(root))
	, canonical_root_(canonicalRoot(root_))
{
}

Result<std::string> SandboxFs::resolveWrite(std::string_view relative, bool create_parents) const
{
	namespace fs = std::filesystem;
	if (canonical_root_.empty())
	{
		return Error{ ErrorCode::ReadOnly, "no writable sandbox" };
	}
	// The sandbox root is a directory: it can be read and enumerated, never
	// renamed or unlinked as a leaf.
	if (relative.empty())
	{
		return Error{ ErrorCode::IsDirectory, "/ is a directory" };
	}
	std::error_code error;
	const fs::path root(canonical_root_);
	const fs::path candidate = root / fs::path(std::string(relative));
	if (!relative.empty() && create_parents)
	{
		fs::create_directories(candidate.parent_path(), error);
		if (error)
		{
			return Error{ ErrorCode::NotFound,
				"cannot create the parent of /" + std::string(relative) };
		}
	}
	const fs::path parent = fs::weakly_canonical(candidate.parent_path(), error);
	if (error)
	{
		return Error{ ErrorCode::NotFound,
			"cannot resolve the parent of /" + std::string(relative) };
	}
	const fs::path leaf = candidate.filename();
	if (leaf.empty() || leaf == "." || leaf == "..")
	{
		return Error{ ErrorCode::IsDirectory, "/" + std::string(relative) + " is a directory" };
	}
	const fs::path full = parent / leaf;
	if (!isWithin(full, root))
	{
		return Error{ ErrorCode::PermissionDenied,
			"/" + std::string(relative) + " escapes the sandbox" };
	}
	return full.string();
}

Result<SandboxFs::HostEntry> SandboxFs::resolveExisting(std::string_view relative) const
{
	namespace fs = std::filesystem;
	if (canonical_root_.empty())
	{
		return Error{ ErrorCode::NotFound, "no writable sandbox" };
	}
	const fs::path root(canonical_root_);
	const fs::path candidate =
		relative.empty() ? root : root / fs::path(std::string(relative));
	std::error_code error;
	const fs::file_status status = fs::status(candidate, error);
	if (error || !fs::exists(status))
	{
		return Error{ ErrorCode::NotFound, "/" + std::string(relative) };
	}
	const fs::path canonical = fs::weakly_canonical(candidate, error);
	if (error || !isWithin(canonical, root))
	{
		return Error{ ErrorCode::NotFound, "/" + std::string(relative) };
	}
	HostEntry entry;
	entry.path = canonical.string();
	entry.directory = fs::is_directory(status);
	return entry;
}

Result<FileStat> SandboxFs::stat(const std::string &guest_path, const std::string &relative) const
{
	auto entry = resolveExisting(relative);
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

Result<std::unique_ptr<File> > SandboxFs::open(const std::string &guest_path,
	const std::string &relative,
	uint64_t flags,
	uint64_t mode) const
{
	auto host_path = resolveWrite(relative, (flags & kOCreate) != 0);
	if (!host_path.ok())
	{
		return host_path.error();
	}
	if ((flags & kODirectory) != 0)
	{
		std::error_code error;
		if (!std::filesystem::is_directory(host_path.value(), error))
		{
			return Error{ ErrorCode::NotDirectory, guest_path + " is not a directory" };
		}
		// The VFS turns this into a directory description.
		return Error{ ErrorCode::IsDirectory, guest_path + " is a directory" };
	}

	const uint64_t access = flags & kAccessModeMask;
	int host_flags = (access == 2) ? O_RDWR : (access == 1 ? O_WRONLY : O_RDONLY);
	if ((flags & kOCreate) != 0)
	{
		host_flags |= O_CREAT;
	}
	if ((flags & kOExclusive) != 0)
	{
		host_flags |= O_EXCL;
	}
	if ((flags & kOTruncate) != 0)
	{
		host_flags |= O_TRUNC;
	}
	if ((flags & kOAppend) != 0)
	{
		host_flags |= O_APPEND;
	}

	auto opened = HostFile::openWritable(guest_path,
		host_path.value(),
		host_flags,
		access,
		(flags & kOAppend) != 0,
		mode == 0 ? 0666 : mode);
	if (!opened.ok())
	{
		return opened.error();
	}
	return std::unique_ptr<File>(std::move(opened.value()));
}

Result<std::vector<DirEntry> > SandboxFs::readdir(const std::string &guest_path,
	const std::string &relative) const
{
	auto entry = resolveExisting(relative);
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

Result<void> SandboxFs::access(const std::string &guest_path,
	const std::string &relative,
	uint64_t mode) const
{
	if ((mode & kAccessExecute) != 0)
	{
		return Error{ ErrorCode::PermissionDenied, "execute access is not modelled" };
	}
	if ((mode & kAccessRead) != 0)
	{
		auto entry = resolveExisting(relative);
		if (!entry.ok())
		{
			return entry.error();
		}
		if (::access(entry.value().path.c_str(), R_OK) != 0)
		{
			return Error{ ErrorCode::PermissionDenied, "cannot read " + guest_path };
		}
	}
	if ((mode & kAccessWrite) != 0)
	{
		std::string write_path;
		if (relative.empty())
		{
			// The sandbox root is writable even though it cannot be a leaf.
			write_path = canonical_root_;
		}
		else
		{
			auto resolved = resolveWrite(relative, false);
			if (!resolved.ok())
			{
				return Error{ ErrorCode::PermissionDenied,
					guest_path + " is read-only" };
			}
			write_path = resolved.value();
		}
		if (::access(write_path.c_str(), W_OK) != 0)
		{
			return Error{ ErrorCode::PermissionDenied, "cannot write " + guest_path };
		}
	}
	return {};
}

Result<void> SandboxFs::mkdir(const std::string &guest_path,
	const std::string &relative,
	uint64_t mode)
{
	auto host = resolveWrite(relative, false);
	if (!host.ok())
	{
		return host.error();
	}
	if (::mkdir(host.value().c_str(), static_cast<mode_t>(mode == 0 ? 0777 : mode)) != 0)
	{
		return errnoToError(errno, "cannot create " + guest_path);
	}
	return {};
}

Result<void> SandboxFs::unlink(const std::string &guest_path,
	const std::string &relative,
	bool remove_directory)
{
	auto host = resolveWrite(relative, false);
	if (!host.ok())
	{
		return host.error();
	}
	std::error_code error;
	const bool directory = std::filesystem::is_directory(host.value(), error);
	if (!error && remove_directory && !directory)
	{
		return Error{ ErrorCode::NotDirectory, guest_path + " is not a directory" };
	}
	if (!error && !remove_directory && directory)
	{
		return Error{ ErrorCode::IsDirectory, guest_path + " is a directory" };
	}
	const int result =
		remove_directory ? ::rmdir(host.value().c_str()) : ::unlink(host.value().c_str());
	if (result != 0)
	{
		return errnoToError(errno, "cannot remove " + guest_path);
	}
	return {};
}

Result<void> SandboxFs::rename(const std::string &old_guest_path,
	const std::string &old_relative,
	const std::string &new_guest_path,
	const std::string &new_relative)
{
	auto old_host = resolveWrite(old_relative, false);
	if (!old_host.ok())
	{
		return old_host.error();
	}
	auto new_host = resolveWrite(new_relative, false);
	if (!new_host.ok())
	{
		return new_host.error();
	}
	if (::rename(old_host.value().c_str(), new_host.value().c_str()) != 0)
	{
		return errnoToError(errno, "cannot rename " + old_guest_path + " to " + new_guest_path);
	}
	return {};
}

} // namespace duckemu::runtime::vfs

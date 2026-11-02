// SPDX-License-Identifier: GPL-2.0-only
#include "runtime/vfs/backends/synthetic_mount_fs.hpp"

#include <sys/stat.h>
#include <utility>

#include "runtime/vfs/vfs_flags.hpp"
#include "runtime/vfs/vnode.hpp"

namespace duckemu::runtime::vfs
{

SyntheticMountFs::SyntheticMountFs(std::string prefix,
	const SyntheticFileSystem *files,
	uint32_t mount_id)
	: prefix_(std::move(prefix))
	, files_(files)
	, mount_id_(mount_id)
{
}

std::optional<SyntheticNode> SyntheticMountFs::lookup(std::string_view guest_path) const
{
	return files_ != nullptr ? files_->lookup(guest_path) : std::nullopt;
}

uint32_t SyntheticMountFs::effectiveMode(const SyntheticNode &node)
{
	if (node.mode != 0)
	{
		return node.mode;
	}
	return node.directory ? (S_IFDIR | 0555) : (S_IFREG | 0444);
}

Result<FileStat> SyntheticMountFs::stat(const std::string &guest_path,
	const std::string &) const
{
	auto node = lookup(guest_path);
	if (!node.has_value())
	{
		return Error{ ErrorCode::NotFound, "no such synthetic node: " + guest_path };
	}
	const VnodeIdentity identity = syntheticIdentity(mount_id_, guest_path);
	FileStat result;
	result.device = identity.device;
	result.inode = identity.inode;
	result.mode = effectiveMode(*node);
	result.rdev = node->rdev;
	result.link_count = node->directory ? 2 : 1;
	result.uid = 0;
	result.gid = 0;
	result.size = node->content ? node->content->size() : 0;
	result.blocks = (result.size + 511) / 512;
	return result;
}

Result<std::unique_ptr<File> > SyntheticMountFs::open(const std::string &guest_path,
	const std::string &,
	uint64_t flags,
	uint64_t) const
{
	auto node = lookup(guest_path);
	if (!node.has_value())
	{
		return Error{ ErrorCode::NotFound, "no such synthetic node: " + guest_path };
	}
	if (node->directory)
	{
		return Error{ ErrorCode::IsDirectory, guest_path + " is a directory" };
	}
	if ((flags & kODirectory) != 0)
	{
		return Error{ ErrorCode::NotDirectory, guest_path + " is not a directory" };
	}
	if (writesRequested(flags))
	{
		if (node->create)
		{
			// Character devices accept every access mode (O_CREAT/O_TRUNC are
			// meaningless but legal, as on the kernel).
			return node->create(guest_path, flags);
		}
		// The property service is not modelled; like an app without write
		// access to /dev/__properties__, the open fails.
		return Error{ ErrorCode::ReadOnly, guest_path + " is read-only" };
	}
	if (node->create)
	{
		return node->create(guest_path, flags);
	}
	return std::unique_ptr<File>(new StaticFile(guest_path, node->content));
}

Result<std::vector<DirEntry> > SyntheticMountFs::readdir(const std::string &guest_path,
	const std::string &) const
{
	auto node = lookup(guest_path);
	if (!node.has_value())
	{
		return Error{ ErrorCode::NotFound, "no such synthetic node: " + guest_path };
	}
	if (!node->directory)
	{
		return Error{ ErrorCode::NotDirectory, guest_path + " is not a directory" };
	}
	return files_->list(guest_path);
}

Result<void> SyntheticMountFs::access(const std::string &guest_path,
	const std::string &,
	uint64_t mode) const
{
	auto node = lookup(guest_path);
	if (!node.has_value())
	{
		return Error{ ErrorCode::NotFound, "no such synthetic node: " + guest_path };
	}
	const uint32_t permissions = effectiveMode(*node) & 0777;
	if ((mode & kAccessRead) != 0 && (permissions & 0444) == 0)
	{
		return Error{ ErrorCode::PermissionDenied, guest_path + " is not readable" };
	}
	if ((mode & kAccessWrite) != 0 && (permissions & 0222) == 0)
	{
		return Error{ ErrorCode::PermissionDenied, guest_path + " is read-only" };
	}
	if ((mode & kAccessExecute) != 0 && (permissions & 0111) == 0)
	{
		return Error{ ErrorCode::PermissionDenied, guest_path + " is not executable" };
	}
	return {};
}

} // namespace duckemu::runtime::vfs

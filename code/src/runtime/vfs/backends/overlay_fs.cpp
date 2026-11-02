// SPDX-License-Identifier: GPL-2.0-only
#include "runtime/vfs/backends/overlay_fs.hpp"

#include <map>
#include <utility>
#include <vector>

#include "runtime/vfs/backends/host_ro_fs.hpp"
#include "runtime/vfs/backends/sandbox_fs.hpp"
#include "runtime/vfs/vfs_flags.hpp"

namespace duckemu::runtime::vfs
{

OverlayFs::OverlayFs(SandboxFs *upper, std::vector<HostRoFs *> lowers)
	: upper_(upper)
	, lowers_(std::move(lowers))
{
}

Result<OverlayFs::HostEntry> OverlayFs::resolveLower(std::string_view relative) const
{
	for (HostRoFs *lower : lowers_)
	{
		auto entry = lower->resolve(relative);
		if (entry.ok())
		{
			HostEntry hit;
			hit.backend = lower;
			hit.path = entry.value().path;
			hit.directory = entry.value().directory;
			hit.upper = false;
			return hit;
		}
	}
	return Error{ ErrorCode::NotFound, "/" + std::string(relative) };
}

Result<OverlayFs::HostEntry> OverlayFs::resolveRead(std::string_view relative) const
{
	if (upper_ != nullptr)
	{
		auto entry = upper_->resolveExisting(relative);
		if (entry.ok())
		{
			HostEntry hit;
			hit.backend = upper_;
			hit.path = entry.value().path;
			hit.directory = entry.value().directory;
			hit.upper = true;
			return hit;
		}
	}
	if (isWhiteout(relative))
	{
		return Error{ ErrorCode::NotFound, "/" + std::string(relative) };
	}
	return resolveLower(relative);
}

Result<FileStat> OverlayFs::stat(const std::string &guest_path, const std::string &relative) const
{
	auto entry = resolveRead(relative);
	if (!entry.ok())
	{
		return entry.error();
	}
	return entry.value().backend->stat(guest_path, relative);
}

Result<std::unique_ptr<File> > OverlayFs::open(const std::string &guest_path,
	const std::string &relative,
	uint64_t flags,
	uint64_t mode) const
{
	if (!writesRequested(flags))
	{
		auto entry = resolveRead(relative);
		if (!entry.ok())
		{
			return entry.error();
		}
		return entry.value().backend->open(guest_path, relative, flags, mode);
	}

	if (upper_ == nullptr)
	{
		return Error{ ErrorCode::ReadOnly, guest_path + " is on a read-only mount" };
	}

	const auto upper_entry = upper_->resolveExisting(relative);
	const auto lower_entry = resolveLower(relative);
	const bool in_upper = upper_entry.ok();
	const bool in_lower = lower_entry.ok();

	if (!in_upper && in_lower)
	{
		// A write intent that could only be served by a read-only layer.
		if ((flags & (kOCreate | kOExclusive)) == (kOCreate | kOExclusive))
		{
			return Error{ ErrorCode::AlreadyExists, guest_path + " already exists" };
		}
		if ((flags & kOCreate) == 0)
		{
			return Error{ ErrorCode::ReadOnly, guest_path + " is on a read-only mount" };
		}
		// O_CREAT copies up: the new upper node shadows the lower one.
	}

	return upper_->open(guest_path, relative, flags, mode);
}

Result<void> OverlayFs::access(const std::string &guest_path,
	const std::string &relative,
	uint64_t mode) const
{
	if ((mode & kAccessExecute) != 0)
	{
		return Error{ ErrorCode::PermissionDenied, "execute access is not modelled" };
	}
	if ((mode & kAccessRead) != 0)
	{
		auto entry = resolveRead(relative);
		if (!entry.ok())
		{
			return entry.error();
		}
		if (!entry.value().backend->access(guest_path, relative, kAccessRead).ok())
		{
			return Error{ ErrorCode::PermissionDenied, "cannot read " + guest_path };
		}
	}
	if ((mode & kAccessWrite) != 0)
	{
		if (upper_ == nullptr)
		{
			return Error{ ErrorCode::PermissionDenied, guest_path + " is read-only" };
		}
		if (!upper_->access(guest_path, relative, kAccessWrite & ~kAccessRead).ok())
		{
			return Error{ ErrorCode::PermissionDenied, "cannot write " + guest_path };
		}
	}
	return {};
}

Result<std::vector<DirEntry> > OverlayFs::readdir(const std::string &guest_path,
	const std::string &relative) const
{
	auto self = resolveRead(relative);
	if (!self.ok())
	{
		return self.error();
	}
	if (!self.value().directory)
	{
		return Error{ ErrorCode::NotDirectory, guest_path + " is not a directory" };
	}

	const auto child_key = [&relative](const std::string &name) {
		return relative.empty() ? name : relative + "/" + name;
	};

	// Map iteration sorts by name; insertion order is irrelevant.
	std::map<std::string, DirEntry> merged;
	// Later lower entries do not override earlier lowers; the upper layer
	// then overrides everything.
	for (auto lower = lowers_.rbegin(); lower != lowers_.rend(); ++lower)
	{
		auto entries = (*lower)->readdir(guest_path, relative);
		if (!entries.ok())
		{
			continue;
		}
		for (const DirEntry &entry : entries.value())
		{
			if (isWhiteout(child_key(entry.name)))
			{
				continue;
			}
			merged[entry.name] = entry;
		}
	}
	if (upper_ != nullptr)
	{
		auto entries = upper_->readdir(guest_path, relative);
		if (entries.ok())
		{
			for (const DirEntry &entry : entries.value())
			{
				merged[entry.name] = entry;
			}
		}
	}

	std::vector<DirEntry> result;
	result.reserve(merged.size());
	for (auto &entry : merged)
	{
		result.push_back(std::move(entry.second));
	}
	return result;
}

Result<void> OverlayFs::mkdir(const std::string &guest_path,
	const std::string &relative,
	uint64_t mode)
{
	if (upper_ == nullptr)
	{
		return Error{ ErrorCode::ReadOnly, guest_path + " is on a read-only mount" };
	}
	// A lower entry with the same name is still visible, so the name exists.
	if (resolveLower(relative).ok())
	{
		return Error{ ErrorCode::AlreadyExists, guest_path + " already exists" };
	}
	auto created = upper_->mkdir(guest_path, relative, mode);
	if (created.ok())
	{
		whiteouts_.erase(relative);
	}
	return created;
}

Result<void> OverlayFs::unlink(const std::string &guest_path,
	const std::string &relative,
	bool remove_directory)
{
	if (upper_ == nullptr)
	{
		return Error{ ErrorCode::ReadOnly, guest_path + " is on a read-only mount" };
	}
	const bool in_upper = upper_->resolveExisting(relative).ok();
	const bool in_lower = resolveLower(relative).ok();
	if (!in_upper)
	{
		return in_lower ? Result<void>(Error{ ErrorCode::ReadOnly,
					    guest_path + " is on a read-only mount" }) :
				  Result<void>(Error{ ErrorCode::NotFound, guest_path });
	}
	auto removed = upper_->unlink(guest_path, relative, remove_directory);
	if (!removed.ok())
	{
		return removed;
	}
	// The lower copy must not resurrect the name.
	if (in_lower)
	{
		whiteouts_.insert(relative);
	}
	return {};
}

Result<void> OverlayFs::rename(const std::string &old_guest_path,
	const std::string &old_relative,
	const std::string &new_guest_path,
	const std::string &new_relative)
{
	if (upper_ == nullptr)
	{
		return Error{ ErrorCode::ReadOnly, old_guest_path + " is on a read-only mount" };
	}
	const bool old_in_upper = upper_->resolveExisting(old_relative).ok();
	const bool old_in_lower = resolveLower(old_relative).ok();
	if (!old_in_upper)
	{
		return old_in_lower ? Result<void>(Error{ ErrorCode::ReadOnly,
					    old_guest_path + " is on a read-only mount" }) :
				  Result<void>(Error{ ErrorCode::NotFound, old_guest_path });
	}

	auto renamed = upper_->rename(old_guest_path, old_relative, new_guest_path, new_relative);
	if (!renamed.ok())
	{
		return renamed;
	}
	// The source name must not fall back to a lower copy after the move.
	if (old_in_lower)
	{
		whiteouts_.insert(old_relative);
	}
	// The destination now has an upper node, so any whiteout there is moot.
	whiteouts_.erase(new_relative);
	return {};
}

} // namespace duckemu::runtime::vfs

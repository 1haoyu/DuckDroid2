// SPDX-License-Identifier: GPL-2.0-only
#include "runtime/vfs/mount_table.hpp"

namespace duckemu::runtime::vfs
{

std::string normalizeMountPrefix(std::string_view prefix)
{
	std::string result(prefix);
	while (result.size() > 1 && result.back() == '/')
	{
		result.pop_back();
	}
	if (result == "/")
	{
		result.clear();
	}
	return result;
}

std::string MountTable::join(std::string_view prefix, std::string_view relative)
{
	if (prefix.empty())
	{
		return "/" + std::string(relative);
	}
	if (relative.empty())
	{
		return std::string(prefix);
	}
	return std::string(prefix) + "/" + std::string(relative);
}

void MountTable::add(Mount mount)
{
	mount.prefix = normalizeMountPrefix(mount.prefix);
	mounts_.push_back(std::move(mount));
}

Result<MountPoint> MountTable::resolve(std::string_view guest_path) const
{
	const Mount *best = nullptr;
	size_t best_length = 0;
	for (const Mount &mount : mounts_)
	{
		if (mount.prefix.empty())
		{
			if (best == nullptr)
			{
				best = &mount;
			}
			continue;
		}
		if (guest_path.size() < mount.prefix.size() ||
			guest_path.compare(0, mount.prefix.size(), mount.prefix) != 0)
		{
			continue;
		}
		if (guest_path.size() != mount.prefix.size() && guest_path[mount.prefix.size()] != '/')
		{
			continue;
		}
		// Later mounts win ties, and a longer prefix always wins.
		if (best == nullptr || mount.prefix.size() >= best_length)
		{
			best = &mount;
			best_length = mount.prefix.size();
		}
	}
	if (best == nullptr)
	{
		return Error{ ErrorCode::NotFound, "no mount for " + std::string(guest_path) };
	}

	MountPoint result;
	result.mount = best;
	if (best->prefix.empty())
	{
		result.relative = guest_path.empty() ? std::string() : std::string(guest_path.substr(1));
	}
	else if (guest_path.size() > best->prefix.size())
	{
		result.relative = std::string(guest_path.substr(best->prefix.size() + 1));
	}
	return result;
}

const Mount *MountTable::find(std::string_view prefix) const
{
	const std::string normalized = normalizeMountPrefix(prefix);
	for (const Mount &mount : mounts_)
	{
		if (mount.prefix == normalized)
		{
			return &mount;
		}
	}
	return nullptr;
}

} // namespace duckemu::runtime::vfs

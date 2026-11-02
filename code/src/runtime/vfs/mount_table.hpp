// SPDX-License-Identifier: GPL-2.0-only
#pragma once

#include <string>
#include <string_view>
#include <vector>

#include "common/error/result.hpp"
#include "runtime/vfs/mount.hpp"

namespace duckemu::runtime::vfs
{

struct MountPoint
{
	const Mount *mount = nullptr;
	// Path relative to the mount point ("" when the path is the mount itself).
	std::string relative;
};

// Guest path -> mount, by longest prefix. The root mount ("" prefix) matches
// everything it does not shadow. The table is immutable after construction;
// there is no dynamic mount/umount.
class MountTable
{
    public:
	void add(Mount mount);

	[[nodiscard]] Result<MountPoint> resolve(std::string_view guest_path) const;

	[[nodiscard]] const Mount *find(std::string_view prefix) const;
	[[nodiscard]] const std::vector<Mount> &mounts() const
	{
		return mounts_;
	}

	// Rebuilds the guest path of a mount-relative path (readdir, diagnostics).
	[[nodiscard]] static std::string join(std::string_view prefix, std::string_view relative);

    private:
	std::vector<Mount> mounts_;
};

// "/a/b/" -> "/a/b"; "/" -> "".
[[nodiscard]] std::string normalizeMountPrefix(std::string_view prefix);

} // namespace duckemu::runtime::vfs

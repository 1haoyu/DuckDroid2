// SPDX-License-Identifier: GPL-2.0-only
#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "common/error/result.hpp"
#include "runtime/vfs/dir_entry.hpp"
#include "runtime/vfs/file.hpp"

namespace duckemu::runtime::vfs
{

// One mount's namespace view. Paths reaching a backend are already normalized
// and relative to the mount point (the mount root itself is ""). Backends
// never see descriptors or errno; they speak the VFS error model.
class MountBackend
{
    public:
	virtual ~MountBackend() = default;

	[[nodiscard]] virtual Result<FileStat> stat(const std::string &guest_path,
		const std::string &relative) const = 0;
	[[nodiscard]] virtual Result<std::unique_ptr<File> > open(const std::string &guest_path,
		const std::string &relative,
		uint64_t flags,
		uint64_t mode) const = 0;

	[[nodiscard]] virtual Result<void> access(const std::string &guest_path,
		const std::string &relative,
		uint64_t mode) const;

	virtual Result<void> mkdir(const std::string &guest_path,
		const std::string &relative,
		uint64_t mode);
	virtual Result<void> unlink(const std::string &guest_path,
		const std::string &relative,
		bool remove_directory);
	virtual Result<void> rename(const std::string &old_guest_path,
		const std::string &old_relative,
		const std::string &new_guest_path,
		const std::string &new_relative);
	[[nodiscard]] virtual Result<std::vector<DirEntry> > readdir(const std::string &guest_path,
		const std::string &relative) const;

	// Synthetic mounts (/dev, /dev/__properties__) are root-owned and keep
	// their uid/gid instead of the configured app owner.
	[[nodiscard]] virtual bool systemOwned() const
	{
		return false;
	}
};

} // namespace duckemu::runtime::vfs

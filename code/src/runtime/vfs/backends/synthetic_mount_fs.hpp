// SPDX-License-Identifier: GPL-2.0-only
#pragma once

#include <string>
#include <string_view>

#include "runtime/vfs/backend.hpp"
#include "runtime/vfs/synthetic_file_system.hpp"

namespace duckemu::runtime::vfs
{

// A fixed read-only namespace (/dev, /dev/__properties__) backed by a
// SyntheticFileSystem. Nodes keep their root owner instead of the configured
// app uid/gid.
class SyntheticMountFs final : public MountBackend
{
    public:
	SyntheticMountFs(std::string prefix, const SyntheticFileSystem *files, uint32_t mount_id);

	[[nodiscard]] Result<FileStat> stat(const std::string &guest_path,
		const std::string &relative) const override;
	[[nodiscard]] Result<std::unique_ptr<File> > open(const std::string &guest_path,
		const std::string &relative,
		uint64_t flags,
		uint64_t mode) const override;
	[[nodiscard]] Result<void> access(const std::string &guest_path,
		const std::string &relative,
		uint64_t mode) const override;
	[[nodiscard]] Result<std::vector<DirEntry> > readdir(const std::string &guest_path,
		const std::string &relative) const override;
	[[nodiscard]] bool systemOwned() const override
	{
		return true;
	}

    private:
	[[nodiscard]] std::optional<SyntheticNode> lookup(std::string_view guest_path) const;
	[[nodiscard]] static uint32_t effectiveMode(const SyntheticNode &node);

	std::string prefix_;
	const SyntheticFileSystem *files_ = nullptr;
	uint32_t mount_id_ = 0;
};

} // namespace duckemu::runtime::vfs

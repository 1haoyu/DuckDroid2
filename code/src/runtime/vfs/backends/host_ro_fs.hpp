// SPDX-License-Identifier: GPL-2.0-only
#pragma once

#include <string>
#include <string_view>

#include "runtime/vfs/backend.hpp"

namespace duckemu::runtime::vfs
{

// One read-only host directory standing in for guest "/". Every resolved
// path is canonicalised and must stay inside the root after symlinks.
class HostRoFs final : public MountBackend
{
    public:
	explicit HostRoFs(std::string root);

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

	// Host path of a relative path, after the escape check. The path must
	// exist; this is the snapshot resolver ProcFs borrows.
	struct HostEntry
	{
		std::string path;
		bool directory = false;
	};
	[[nodiscard]] Result<HostEntry> resolve(std::string_view relative) const;

	[[nodiscard]] const std::string &root() const
	{
		return root_;
	}

    private:
	std::string root_;
	std::string canonical_root_;
};

} // namespace duckemu::runtime::vfs

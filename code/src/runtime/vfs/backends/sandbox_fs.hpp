// SPDX-License-Identifier: GPL-2.0-only
#pragma once

#include <string>
#include <string_view>

#include "runtime/vfs/backend.hpp"

namespace duckemu::runtime::vfs
{

// The per-instance writable upper layer. It is a plain host directory; the
// overlay above it decides when reads fall through to the read-only roots.
class SandboxFs final : public MountBackend
{
    public:
	explicit SandboxFs(std::string root);

	struct HostEntry
	{
		std::string path;
		bool directory = false;
	};

	// Path inside the sandbox for a mutation. Only the parent is canonicalised
	// (the leaf may not exist yet) and the result must stay inside the root.
	// `create_parents` preserves the existing O_CREAT behavior of creating
	// intermediate directories.
	[[nodiscard]] Result<std::string> resolveWrite(std::string_view relative,
		bool create_parents) const;
	// Existing path inside the sandbox, symlinks resolved and bounded.
	[[nodiscard]] Result<HostEntry> resolveExisting(std::string_view relative) const;

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

	Result<void> mkdir(const std::string &guest_path,
		const std::string &relative,
		uint64_t mode) override;
	Result<void> unlink(const std::string &guest_path,
		const std::string &relative,
		bool remove_directory) override;
	Result<void> rename(const std::string &old_guest_path,
		const std::string &old_relative,
		const std::string &new_guest_path,
		const std::string &new_relative) override;

	[[nodiscard]] const std::string &root() const
	{
		return root_;
	}

    private:
	std::string root_;
	std::string canonical_root_;
};

} // namespace duckemu::runtime::vfs

// SPDX-License-Identifier: GPL-2.0-only
#pragma once

#include <set>
#include <string>
#include <string_view>
#include <vector>

#include "runtime/vfs/backend.hpp"

namespace duckemu::runtime::vfs
{

class HostRoFs;
class SandboxFs;

// guest "/" as one writable upper over an ordered list of read-only lowers.
//
// This is the only place that decides precedence: upper first, then the
// lowers in registration order. Mutations go to the upper; a mutation that
// only a lower could satisfy answers EROFS. Removing an upper node that also
// exists below records an in-memory whiteout so the lower copy cannot
// reappear for the lifetime of the instance.
class OverlayFs final : public MountBackend
{
    public:
	OverlayFs(SandboxFs *upper, std::vector<HostRoFs *> lowers);

	struct HostEntry
	{
		const MountBackend *backend = nullptr;
		std::string path;
		bool directory = false;
		bool upper = false;
	};

	// Union view: the writable upper first, then each lower, with whiteouts
	// filtering the lower side.
	[[nodiscard]] Result<HostEntry> resolveRead(std::string_view relative) const;

	[[nodiscard]] Result<FileStat> stat(const std::string &guest_path,
		const std::string &relative) const override;
	[[nodiscard]] Result<std::unique_ptr<File> > open(const std::string &guest_path,
		const std::string &relative,
		uint64_t flags,
		uint64_t mode) const override;
	[[nodiscard]] Result<void> access(const std::string &guest_path,
		const std::string &relative,
		uint64_t mode) const override;
	// Merged view: upper wins by name, whiteouts hide lower-only entries.
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

	[[nodiscard]] bool hasUpper() const
	{
		return upper_ != nullptr;
	}
	[[nodiscard]] bool isWhiteout(std::string_view relative) const
	{
		return whiteouts_.find(std::string(relative)) != whiteouts_.end();
	}
	[[nodiscard]] const std::vector<HostRoFs *> &lowers() const
	{
		return lowers_;
	}
	[[nodiscard]] SandboxFs *upper() const
	{
		return upper_;
	}

    private:
	// First lower that has the path, ignoring the upper and whiteouts.
	[[nodiscard]] Result<HostEntry> resolveLower(std::string_view relative) const;

	SandboxFs *upper_ = nullptr;
	std::vector<HostRoFs *> lowers_;
	// Sorted set of mount-relative paths deleted from the upper while a lower
	// copy exists. Instance-lifetime only; instance recycling is process
	// replacement (M7), so nothing persists.
	std::set<std::string> whiteouts_;
};

} // namespace duckemu::runtime::vfs

// SPDX-License-Identifier: GPL-2.0-only
#pragma once

#include <functional>
#include <string>
#include <string_view>

#include "runtime/vfs/backend.hpp"
#include "runtime/vfs/proc_fs.hpp"

namespace duckemu::runtime::vfs
{

class OverlayFs;

// The /proc mount: a device snapshot in the host roots wins, then the
// synthesizer fills in what the snapshot does not carry. The /proc/<pid>/x ->
// /proc/self/x rewrite is kept here, out of the generic namespace layer.
class ProcFs final : public MountBackend
{
    public:
	using ContextProvider = std::function<ProcContext()>;

	ProcFs(OverlayFs *snapshot, ContextProvider context);

	[[nodiscard]] Result<FileStat> stat(const std::string &guest_path,
		const std::string &relative) const override;
	[[nodiscard]] Result<std::unique_ptr<File> > open(const std::string &guest_path,
		const std::string &relative,
		uint64_t flags,
		uint64_t mode) const override;
	[[nodiscard]] Result<void> access(const std::string &guest_path,
		const std::string &relative,
		uint64_t mode) const override;
	// Snapshot entries merged with the synthesized names for that directory.
	[[nodiscard]] Result<std::vector<DirEntry> > readdir(const std::string &guest_path,
		const std::string &relative) const override;

	// Snapshot path for a mount-relative proc path, or nullopt when the
	// snapshot does not carry it.
	[[nodiscard]] Result<std::string> snapshotPath(std::string_view relative) const;

	// /proc itself and the per-process directories the synthesizer models.
	[[nodiscard]] bool isSyntheticDirectory(std::string_view relative) const;

    private:
	[[nodiscard]] static std::string mapProcessComponent(std::string_view relative,
		uint32_t pid);

	OverlayFs *snapshot_;
	ContextProvider context_;
	uint32_t pid_;
};

} // namespace duckemu::runtime::vfs

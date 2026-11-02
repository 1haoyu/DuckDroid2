// SPDX-License-Identifier: GPL-2.0-only
#pragma once

#include <algorithm>
#include <filesystem>
#include <string>
#include <system_error>
#include <sys/stat.h>
#include <vector>

#include "common/error/result.hpp"
#include "runtime/vfs/dir_entry.hpp"
#include "runtime/vfs/vfs_error.hpp"

namespace duckemu::runtime::vfs
{

inline bool isWithin(const std::filesystem::path &path, const std::filesystem::path &root)
{
	const std::string candidate = path.string();
	const std::string parent = root.string();
	if (candidate == parent)
	{
		return true;
	}
	if (candidate.size() <= parent.size() || candidate.compare(0, parent.size(), parent) != 0)
	{
		return false;
	}
	return candidate[parent.size()] == '/' || parent.back() == '/';
}

// Canonical root; empty on failure.
inline std::string canonicalRoot(const std::string &root)
{
	std::error_code error;
	const std::filesystem::path canonical =
		std::filesystem::weakly_canonical(std::filesystem::path(root), error);
	return error ? std::string() : canonical.string();
}

// Snapshot of one host directory, sorted by name for reproducible replay.
// lstat supplies the entry's own inode and type (a symlink stays a symlink).
inline Result<std::vector<DirEntry> > listHostDirectory(const std::string &host_path,
	const std::string &guest_path)
{
	std::error_code error;
	std::filesystem::directory_iterator iterator(host_path, error);
	if (error)
	{
		return errnoToError(error.value(), "cannot enumerate " + guest_path);
	}
	std::vector<DirEntry> entries;
	for (const std::filesystem::directory_entry &child : iterator)
	{
		struct stat info = {};
		const std::string child_path = child.path().string();
		if (::lstat(child_path.c_str(), &info) != 0)
		{
			continue;
		}
		DirEntry entry;
		entry.name = child.path().filename().string();
		entry.type = dirTypeFromMode(static_cast<uint32_t>(info.st_mode));
		entry.ino = static_cast<uint64_t>(info.st_ino);
		entries.push_back(std::move(entry));
	}
	std::sort(entries.begin(), entries.end(),
		[](const DirEntry &left, const DirEntry &right) { return left.name < right.name; });
	return entries;
}

} // namespace duckemu::runtime::vfs

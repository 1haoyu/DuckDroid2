// SPDX-License-Identifier: GPL-2.0-only
#pragma once

#include <cstdint>
#include <vector>

#include "common/error/result.hpp"
#include "runtime/vfs/dir_entry.hpp"

namespace duckemu::runtime::vfs
{

// The directory snapshot an open directory description holds, plus an index
// cursor. Entries are never consumed destructively: a partial buffer leaves
// the un-written entries for the next call, and seek(0) rewinds.
class DirCursor
{
    public:
	explicit DirCursor(std::vector<DirEntry> entries);

	// Fills `buffer` with complete linux_dirent64 records. Returns the byte
	// count (0 at end of directory); EINVAL when the first entry does not fit.
	[[nodiscard]] Result<uint64_t> read(void *buffer, uint64_t count);

	// Only SEEK_SET within [0, size] is meaningful for a directory; anything
	// else answers EINVAL, like the kernel.
	[[nodiscard]] Result<uint64_t> seek(int64_t offset, int whence);

	[[nodiscard]] size_t position() const
	{
		return index_;
	}
	[[nodiscard]] size_t size() const
	{
		return entries_.size();
	}

    private:
	std::vector<DirEntry> entries_;
	size_t index_ = 0;
};

} // namespace duckemu::runtime::vfs

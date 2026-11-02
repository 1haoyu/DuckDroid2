// SPDX-License-Identifier: GPL-2.0-only
#pragma once

#include <string>
#include <vector>

#include "runtime/vfs/dir_cursor.hpp"
#include "runtime/vfs/dir_entry.hpp"
#include "runtime/vfs/file.hpp"

namespace duckemu::runtime::vfs
{

// An open directory: metadata + a snapshot cursor. read(2)/write(2) answer
// EISDIR; getdents64 drains the cursor. dup shares this object, so the
// cursor is shared exactly like the file offset of a regular description.
class DirFile final : public File
{
    public:
	DirFile(std::string guest_path, FileStat stat, std::vector<DirEntry> entries);

	[[nodiscard]] std::string_view path() const override
	{
		return path_;
	}
	[[nodiscard]] bool writable() const override
	{
		return false;
	}
	[[nodiscard]] FileKind kind() const override
	{
		return FileKind::Directory;
	}
	[[nodiscard]] Result<FileStat> stat() override;
	[[nodiscard]] Result<uint64_t> read(void *, uint64_t) override;
	[[nodiscard]] Result<uint64_t> readAt(uint64_t, void *, uint64_t) override;
	[[nodiscard]] Result<uint64_t> write(const void *, uint64_t) override;
	[[nodiscard]] Result<uint64_t> writeAt(uint64_t, const void *, uint64_t) override;
	[[nodiscard]] Result<uint64_t> seek(int64_t offset, int whence) override;

	[[nodiscard]] Result<uint64_t> readEntries(void *buffer, uint64_t count)
	{
		return cursor_.read(buffer, count);
	}
	[[nodiscard]] size_t entryCount() const
	{
		return cursor_.size();
	}

    private:
	std::string path_;
	FileStat stat_;
	DirCursor cursor_;
};

} // namespace duckemu::runtime::vfs

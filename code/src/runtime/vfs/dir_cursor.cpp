// SPDX-License-Identifier: GPL-2.0-only
#include "runtime/vfs/dir_cursor.hpp"

#include <cstring>
#include <utility>

namespace duckemu::runtime::vfs
{
namespace
{

// arm64 struct linux_dirent64: u64 d_ino, s64 d_off, u16 d_reclen, u8 d_type,
// then the NUL-terminated name; records are 8-byte aligned.
constexpr uint64_t kHeaderSize = 19;

constexpr uint64_t alignRecord(uint64_t size)
{
	return (size + 7) & ~uint64_t{ 7 };
}

} // namespace

DirCursor::DirCursor(std::vector<DirEntry> entries)
	: entries_(std::move(entries))
{
}

Result<uint64_t> DirCursor::read(void *buffer, uint64_t count)
{
	auto *bytes = static_cast<uint8_t *>(buffer);
	uint64_t used = 0;
	while (index_ < entries_.size())
	{
		const DirEntry &entry = entries_[index_];
		const uint64_t reclen = alignRecord(kHeaderSize + entry.name.size() + 1);
		if (used + reclen > count)
		{
			// The kernel refuses when not even the first record fits; a later
			// short buffer just stops before the oversized entry.
			if (used == 0)
			{
				return Error{ ErrorCode::InvalidArgument,
					"directory entry does not fit the buffer" };
			}
			break;
		}
		std::memset(bytes + used, 0, static_cast<size_t>(reclen));
		const int64_t offset = static_cast<int64_t>(index_ + 1);
		const uint16_t record_length = static_cast<uint16_t>(reclen);
		std::memcpy(bytes + used, &entry.ino, sizeof(entry.ino));
		std::memcpy(bytes + used + 8, &offset, sizeof(offset));
		std::memcpy(bytes + used + 16, &record_length, sizeof(record_length));
		bytes[used + 18] = entry.type;
		std::memcpy(bytes + used + kHeaderSize, entry.name.data(), entry.name.size());
		used += reclen;
		++index_;
	}
	return used;
}

Result<uint64_t> DirCursor::seek(int64_t offset, int whence)
{
	if (whence != 0 /* SEEK_SET */ || offset < 0 ||
		static_cast<size_t>(offset) > entries_.size())
	{
		return Error{ ErrorCode::InvalidArgument, "invalid directory seek" };
	}
	index_ = static_cast<size_t>(offset);
	return static_cast<uint64_t>(index_);
}

} // namespace duckemu::runtime::vfs

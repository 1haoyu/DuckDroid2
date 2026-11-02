// SPDX-License-Identifier: GPL-2.0-only
#include "runtime/vfs/dir_file.hpp"

#include <utility>

namespace duckemu::runtime::vfs
{

DirFile::DirFile(std::string guest_path, FileStat stat, std::vector<DirEntry> entries)
	: path_(std::move(guest_path))
	, stat_(stat)
	, cursor_(std::move(entries))
{
}

Result<FileStat> DirFile::stat()
{
	return stat_;
}

Result<uint64_t> DirFile::read(void *, uint64_t)
{
	return Error{ ErrorCode::IsDirectory, path_ + " is a directory" };
}

Result<uint64_t> DirFile::readAt(uint64_t, void *, uint64_t)
{
	return Error{ ErrorCode::IsDirectory, path_ + " is a directory" };
}

Result<uint64_t> DirFile::write(const void *, uint64_t)
{
	return Error{ ErrorCode::IsDirectory, path_ + " is a directory" };
}

Result<uint64_t> DirFile::writeAt(uint64_t, const void *, uint64_t)
{
	return Error{ ErrorCode::IsDirectory, path_ + " is a directory" };
}

Result<uint64_t> DirFile::seek(int64_t offset, int whence)
{
	return cursor_.seek(offset, whence);
}

} // namespace duckemu::runtime::vfs

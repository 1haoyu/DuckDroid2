// SPDX-License-Identifier: GPL-2.0-only
#include "runtime/vfs/fd_table.hpp"

#include <utility>

namespace duckemu::runtime::vfs
{

Result<uint64_t> FdTable::insert(std::unique_ptr<File> file)
{
	return insertShared(std::shared_ptr<File>(std::move(file)));
}

Result<uint64_t> FdTable::insertShared(std::shared_ptr<File> file, uint64_t minimum)
{
	if (!file)
	{
		return Error{ ErrorCode::InvalidArgument, "no file description" };
	}
	uint64_t fd = minimum < kFirstGuestFd ? kFirstGuestFd : minimum;
	while (files_.count(fd) != 0)
	{
		++fd;
	}
	files_.emplace(fd, std::move(file));
	return fd;
}

Result<void> FdTable::assign(uint64_t fd, std::shared_ptr<File> file)
{
	if (!file)
	{
		return Error{ ErrorCode::InvalidArgument, "no file description" };
	}
	files_[fd] = std::move(file);
	return {};
}

Result<void> FdTable::install(uint64_t fd, std::shared_ptr<File> file)
{
	return assign(fd, std::move(file));
}

File *FdTable::find(uint64_t fd) const
{
	auto it = files_.find(fd);
	return it == files_.end() ? nullptr : it->second.get();
}

std::shared_ptr<File> FdTable::shared(uint64_t fd) const
{
	auto it = files_.find(fd);
	return it == files_.end() ? nullptr : it->second;
}

Result<void> FdTable::remove(uint64_t fd)
{
	auto it = files_.find(fd);
	if (it == files_.end())
	{
		return Error{ ErrorCode::BadFileDescriptor, "fd is not open" };
	}
	files_.erase(it);
	return {};
}

} // namespace duckemu::runtime::vfs

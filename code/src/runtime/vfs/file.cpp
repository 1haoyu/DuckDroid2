// SPDX-License-Identifier: GPL-2.0-only
#include "runtime/vfs/file.hpp"

#include <algorithm>
#include <cstring>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <utility>

#include "runtime/vfs/vfs_error.hpp"

namespace duckemu::runtime::vfs
{
namespace
{

Error ioError(std::string message)
{
	return Error{ ErrorCode::Internal, std::move(message) };
}

} // namespace

StdioFile::StdioFile(int host_fd)
	: host_fd_(host_fd)
	, path_(host_fd == 0 ? "/dev/stdin" : (host_fd == 1 ? "/dev/stdout" : "/dev/stderr"))
{
}

Result<FileStat> StdioFile::stat()
{
	FileStat result;
	result.inode = static_cast<uint64_t>(host_fd_) + 1;
	result.mode = S_IFCHR | 0666;
	result.link_count = 1;
	result.block_size = 4096;
	return result;
}

Result<uint64_t> StdioFile::read(void *buffer, uint64_t count)
{
	if (host_fd_ != 0)
	{
		return Error{ ErrorCode::BadFileDescriptor, "stdout is not readable" };
	}
	const ssize_t received = ::read(host_fd_, buffer, static_cast<size_t>(count));
	if (received < 0)
	{
		return ioError("host read failed");
	}
	return static_cast<uint64_t>(received);
}

Result<uint64_t> StdioFile::readAt(uint64_t, void *, uint64_t)
{
	return Error{ ErrorCode::NotSeekable, "pread on a standard stream" };
}

Result<uint64_t> StdioFile::write(const void *buffer, uint64_t count)
{
	if (host_fd_ == 0)
	{
		return Error{ ErrorCode::BadFileDescriptor, "stdin is not writable" };
	}
	const ssize_t written = ::write(host_fd_, buffer, static_cast<size_t>(count));
	if (written < 0)
	{
		return ioError("host write failed");
	}
	return static_cast<uint64_t>(written);
}

Result<uint64_t> StdioFile::seek(int64_t, int)
{
	return Error{ ErrorCode::NotSeekable, "lseek on a standard stream" };
}

StaticFile::StaticFile(std::string path, std::shared_ptr<const std::vector<uint8_t> > content)
	: path_(std::move(path))
	, content_(std::move(content))
{
}

Result<FileStat> StaticFile::stat()
{
	FileStat result;
	result.inode = std::hash<std::string>{}(path_);
	result.mode = S_IFREG | 0444;
	result.uid = 0;
	result.gid = 0;
	result.size = content_ ? content_->size() : 0;
	result.blocks = (result.size + 511) / 512;
	return result;
}

Result<uint64_t> StaticFile::read(void *buffer, uint64_t count)
{
	auto result = readAt(offset_, buffer, count);
	if (result.ok())
	{
		offset_ += result.value();
	}
	return result;
}

Result<uint64_t> StaticFile::readAt(uint64_t offset, void *buffer, uint64_t count)
{
	const uint64_t size = content_ ? content_->size() : 0;
	if (offset >= size || count == 0)
	{
		return uint64_t{ 0 };
	}
	const uint64_t take = std::min(count, size - offset);
	std::memcpy(buffer, content_->data() + offset, static_cast<size_t>(take));
	return take;
}

Result<uint64_t> StaticFile::write(const void *, uint64_t)
{
	return Error{ ErrorCode::Unsupported, path_ + " is read-only" };
}

Result<uint64_t> StaticFile::seek(int64_t offset, int whence)
{
	const int64_t size = content_ ? static_cast<int64_t>(content_->size()) : 0;
	int64_t base = 0;
	switch (whence)
	{
	case 0: // SEEK_SET
		break;
	case 1: // SEEK_CUR
		base = static_cast<int64_t>(offset_);
		break;
	case 2: // SEEK_END
		base = size;
		break;
	default:
		return Error{ ErrorCode::InvalidArgument, "invalid whence" };
	}
	const int64_t target = base + offset;
	if (target < 0)
	{
		return Error{ ErrorCode::InvalidArgument, "negative file offset" };
	}
	offset_ = static_cast<uint64_t>(target);
	return offset_;
}

MemoryFile::MemoryFile(std::string path, Generator generator)
	: path_(std::move(path))
	, generator_(std::move(generator))
{
}

const std::string &MemoryFile::materialize()
{
	if (!content_.has_value())
	{
		content_ = generator_ ? generator_() : std::string();
	}
	return *content_;
}

Result<FileStat> MemoryFile::stat()
{
	FileStat result;
	result.inode = std::hash<std::string>{}(path_);
	result.mode = S_IFREG | 0444;
	result.size = materialize().size();
	result.blocks = (result.size + 511) / 512;
	return result;
}

Result<uint64_t> MemoryFile::read(void *buffer, uint64_t count)
{
	auto result = readAt(offset_, buffer, count);
	if (result.ok())
	{
		offset_ += result.value();
	}
	return result;
}

Result<uint64_t> MemoryFile::readAt(uint64_t offset, void *buffer, uint64_t count)
{
	const std::string &content = materialize();
	if (offset >= content.size() || count == 0)
	{
		return uint64_t{ 0 };
	}
	const uint64_t available = content.size() - offset;
	const uint64_t take = std::min(count, available);
	std::memcpy(buffer, content.data() + offset, static_cast<size_t>(take));
	return take;
}

Result<uint64_t> MemoryFile::write(const void *, uint64_t)
{
	return Error{ ErrorCode::Unsupported, path_ + " is read-only" };
}

Result<uint64_t> MemoryFile::seek(int64_t offset, int whence)
{
	int64_t base = 0;
	switch (whence)
	{
	case 0: // SEEK_SET
		break;
	case 1: // SEEK_CUR
		base = static_cast<int64_t>(offset_);
		break;
	case 2: // SEEK_END
		base = static_cast<int64_t>(materialize().size());
		break;
	default:
		return Error{ ErrorCode::InvalidArgument, "invalid whence" };
	}
	const int64_t target = base + offset;
	if (target < 0)
	{
		return Error{ ErrorCode::InvalidArgument, "negative file offset" };
	}
	offset_ = static_cast<uint64_t>(target);
	return offset_;
}

HostFile::~HostFile()
{
	if (fd_ >= 0)
	{
		::close(fd_);
	}
}

HostFile::HostFile(std::string guest_path, int fd, uint64_t size, bool writable, bool append)
	: guest_path_(std::move(guest_path))
	, fd_(fd)
	, size_(size)
	, writable_(writable)
	, append_(append)
{
}

Result<std::unique_ptr<HostFile> > HostFile::open(std::string guest_path, std::string host_path)
{
	const int fd = ::open(host_path.c_str(), O_RDONLY | O_CLOEXEC);
	if (fd < 0)
	{
		return errnoToError(errno, "cannot open " + host_path);
	}
	struct stat info = {};
	if (::fstat(fd, &info) != 0)
	{
		const int error_number = errno;
		::close(fd);
		return errnoToError(error_number, "cannot stat " + host_path);
	}
	if (!S_ISREG(info.st_mode))
	{
		::close(fd);
		return Error{ S_ISDIR(info.st_mode) ? ErrorCode::IsDirectory : ErrorCode::Internal,
			host_path + " is not a regular file" };
	}
	return std::unique_ptr<HostFile>(new HostFile(std::move(guest_path), fd,
		static_cast<uint64_t>(info.st_size), false, false));
}

Result<std::unique_ptr<HostFile> > HostFile::openWritable(std::string guest_path,
	std::string host_path,
	int host_flags,
	uint64_t access,
	bool append,
	uint64_t mode)
{
	const int fd = ::open(host_path.c_str(), host_flags | O_CLOEXEC, static_cast<mode_t>(mode));
	if (fd < 0)
	{
		return errnoToError(errno, "cannot open " + host_path);
	}
	struct stat info = {};
	if (::fstat(fd, &info) != 0)
	{
		const int error_number = errno;
		::close(fd);
		return errnoToError(error_number, "cannot stat " + host_path);
	}
	if (!S_ISREG(info.st_mode))
	{
		::close(fd);
		return Error{ S_ISDIR(info.st_mode) ? ErrorCode::IsDirectory : ErrorCode::Internal,
			host_path + " is not a regular file" };
	}
	return std::unique_ptr<HostFile>(new HostFile(std::move(guest_path),
		fd,
		static_cast<uint64_t>(info.st_size),
		access != 0,
		append));
}

Result<FileStat> HostFile::stat()
{
	struct stat info = {};
	if (::fstat(fd_, &info) != 0)
	{
		return ioError("fstat failed");
	}
	FileStat result;
	result.device = static_cast<uint64_t>(info.st_dev);
	result.inode = static_cast<uint64_t>(info.st_ino);
	result.mode = static_cast<uint32_t>(info.st_mode);
	result.link_count = static_cast<uint32_t>(info.st_nlink);
	result.uid = static_cast<uint32_t>(info.st_uid);
	result.gid = static_cast<uint32_t>(info.st_gid);
	result.size = static_cast<uint64_t>(info.st_size);
	result.blocks = static_cast<uint64_t>(info.st_blocks);
	result.block_size = static_cast<uint32_t>(info.st_blksize);
	result.atime_seconds = info.st_atim.tv_sec;
	result.atime_nanoseconds = info.st_atim.tv_nsec;
	result.mtime_seconds = info.st_mtim.tv_sec;
	result.mtime_nanoseconds = info.st_mtim.tv_nsec;
	result.ctime_seconds = info.st_ctim.tv_sec;
	result.ctime_nanoseconds = info.st_ctim.tv_nsec;
	return result;
}

Result<uint64_t> HostFile::read(void *buffer, uint64_t count)
{
	auto result = readAt(offset_, buffer, count);
	if (result.ok())
	{
		offset_ += result.value();
	}
	return result;
}

Result<uint64_t> HostFile::readAt(uint64_t offset, void *buffer, uint64_t count)
{
	if (count == 0)
	{
		return uint64_t{ 0 };
	}
	const ssize_t received = ::pread(fd_, buffer, static_cast<size_t>(count),
		static_cast<off_t>(offset));
	if (received < 0)
	{
		return errnoToError(errno, "pread failed");
	}
	return static_cast<uint64_t>(received);
}

Result<uint64_t> HostFile::write(const void *buffer, uint64_t count)
{
	if (!writable_)
	{
		return Error{ ErrorCode::BadFileDescriptor, guest_path_ + " is not writable" };
	}
	if (count == 0)
	{
		return uint64_t{ 0 };
	}
	// O_APPEND keeps appending through the host descriptor; otherwise the
	// guest-visible offset decides where pwrite lands.
	const ssize_t written = append_ ?
					::write(fd_, buffer, static_cast<size_t>(count)) :
					::pwrite(fd_, buffer, static_cast<size_t>(count),
						static_cast<off_t>(offset_));
	if (written < 0)
	{
		return errnoToError(errno, "write failed on " + guest_path_);
	}
	offset_ += static_cast<uint64_t>(written);
	size_ = std::max(size_, offset_);
	return static_cast<uint64_t>(written);
}

Result<uint64_t> HostFile::writeAt(uint64_t offset, const void *buffer, uint64_t count)
{
	if (!writable_)
	{
		return Error{ ErrorCode::BadFileDescriptor, guest_path_ + " is not writable" };
	}
	if (count == 0)
	{
		return uint64_t{ 0 };
	}
	const ssize_t written = ::pwrite(fd_, buffer, static_cast<size_t>(count),
		static_cast<off_t>(offset));
	if (written < 0)
	{
		return errnoToError(errno, "pwrite failed on " + guest_path_);
	}
	size_ = std::max(size_, offset + static_cast<uint64_t>(written));
	return static_cast<uint64_t>(written);
}

Result<void> HostFile::truncate(uint64_t size)
{
	if (!writable_)
	{
		return Error{ ErrorCode::Unsupported, guest_path_ + " is read-only" };
	}
	if (::ftruncate(fd_, static_cast<off_t>(size)) != 0)
	{
		return ioError("ftruncate failed on " + guest_path_);
	}
	size_ = size;
	if (offset_ > size_)
	{
		offset_ = size_;
	}
	return {};
}

Result<void> HostFile::sync()
{
	if (::fsync(fd_) != 0)
	{
		return ioError("fsync failed on " + guest_path_);
	}
	return {};
}

Result<uint64_t> HostFile::seek(int64_t offset, int whence)
{
	int64_t base = 0;
	switch (whence)
	{
	case 0: // SEEK_SET
		break;
	case 1: // SEEK_CUR
		base = static_cast<int64_t>(offset_);
		break;
	case 2: // SEEK_END
		base = static_cast<int64_t>(size_);
		break;
	default:
		return Error{ ErrorCode::InvalidArgument, "invalid whence" };
	}
	const int64_t target = base + offset;
	if (target < 0)
	{
		return Error{ ErrorCode::InvalidArgument, "negative file offset" };
	}
	offset_ = static_cast<uint64_t>(target);
	return offset_;
}

} // namespace duckemu::runtime::vfs

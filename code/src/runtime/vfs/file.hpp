// SPDX-License-Identifier: GPL-2.0-only
#pragma once

#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "common/error/result.hpp"
#include "runtime/vfs/open_file.hpp"
#include "runtime/vfs/vfs_flags.hpp"
#include "runtime/vfs/vnode.hpp"

namespace duckemu::runtime::vfs
{

// poll(2) bits. The guest-visible values match EPOLLIN/EPOLLOUT/EPOLLERR/
// EPOLLHUP, so epoll_ctl can pass them through unchanged.
inline constexpr uint32_t kPollIn = 0x001;
inline constexpr uint32_t kPollOut = 0x004;
inline constexpr uint32_t kPollErr = 0x008;
inline constexpr uint32_t kPollHup = 0x010;

enum class FileKind : uint8_t
{
	Regular = 0,
	Directory,
	Memory,
	Static, // immutable synthetic mount entry (/dev/__properties__)
	Device, // character device (/dev/null, /dev/zero, /dev/urandom)
	Stdio,
	Host,
	Event, // eventfd
	Timer, // timerfd
	Epoll,
	Pipe,
};

// File metadata in guest-neutral terms. fs_handlers encodes it into the arm64
// kernel `struct stat` layout.
struct FileStat
{
	uint64_t device = 0;
	uint64_t inode = 0;
	uint32_t mode = 0; // S_IF* | permission bits
	uint64_t rdev = 0; // st_rdev for character devices (arm64 st_rdev offset 32)
	uint32_t link_count = 1;
	uint32_t uid = 1000;
	uint32_t gid = 1000;
	uint64_t size = 0;
	uint64_t blocks = 0;
	uint32_t block_size = 4096;
	int64_t atime_seconds = 0;
	int64_t atime_nanoseconds = 0;
	int64_t mtime_seconds = 0;
	int64_t mtime_nanoseconds = 0;
	int64_t ctime_seconds = 0;
	int64_t ctime_nanoseconds = 0;
};

// One open file description. The read offset lives here, so dup'ed
// descriptors share it: the descriptor table holds shared_ptr<File>.
class File
{
    public:
	virtual ~File() = default;

	[[nodiscard]] virtual std::string_view path() const = 0;
	[[nodiscard]] virtual bool writable() const = 0;

	[[nodiscard]] virtual Result<FileStat> stat() = 0;
	[[nodiscard]] virtual Result<uint64_t> read(void *buffer, uint64_t count) = 0;
	[[nodiscard]] virtual Result<uint64_t> readAt(uint64_t offset, void *buffer, uint64_t count) = 0;
	[[nodiscard]] virtual Result<uint64_t> write(const void *buffer, uint64_t count) = 0;
	// pwrite(2): the offset does not move the description and is independent
	// of O_APPEND. Non-seekable descriptions answer ESPIPE.
	[[nodiscard]] virtual Result<uint64_t> writeAt(uint64_t offset,
		const void *buffer,
		uint64_t count)
	{
		(void)offset;
		(void)buffer;
		(void)count;
		return Error{ ErrorCode::NotSeekable, "pwrite on a non-seekable description" };
	}
	[[nodiscard]] virtual Result<uint64_t> seek(int64_t offset, int whence) = 0;

	// ftruncate(2). Read-only and memory-backed descriptions answer
	// Unsupported.
	[[nodiscard]] virtual Result<void> truncate(uint64_t size)
	{
		(void)size;
		return Error{ ErrorCode::Unsupported, "not truncatable" };
	}
	// fsync(2)/fdatasync(2). Open file descriptions are host-backed; synthetic
	// ones are already durable.
	[[nodiscard]] virtual Result<void> sync()
	{
		return {};
	}

	// Ownership that must survive statFd's device-owner stamping. Synthetic
	// mount entries are root-owned on Android; bionic's property reader
	// rejects a prop_area whose stat uid/gid is not 0.
	[[nodiscard]] virtual bool systemOwned() const
	{
		return false;
	}

	[[nodiscard]] virtual FileKind kind() const
	{
		return FileKind::Regular;
	}
	// Readiness for poll(2)/epoll: a subset of kPoll*. Regular files and
	// /proc entries are always readable.
	[[nodiscard]] virtual uint32_t pollEvents() const
	{
		return kPollIn;
	}

	// Open description state. The access mode and O_APPEND survive into
	// fcntl(F_GETFL); O_CREAT/O_EXCL/O_TRUNC do not, like the kernel.
	void setOpenFlags(uint64_t flags)
	{
		open_flags_ = statusFlags(flags);
	}
	[[nodiscard]] uint64_t openFlags() const
	{
		return open_flags_;
	}
	// Standard descriptors are permanently installed: close(0/1/2) succeeds
	// without discarding them.
	void setCloseable(bool closeable)
	{
		closeable_ = closeable;
	}
	[[nodiscard]] bool closeable() const
	{
		return closeable_;
	}
	// Synthetic nodes have no host inode; the VFS stamps the identity derived
	// from (mount, guest path) so path stat and descriptor stat agree.
	void setIdentity(VnodeIdentity identity)
	{
		identity_ = identity;
		has_identity_ = true;
	}
	[[nodiscard]] bool hasIdentity() const
	{
		return has_identity_;
	}
	[[nodiscard]] VnodeIdentity identity() const
	{
		return identity_;
	}

    protected:
	uint64_t open_flags_ = 0;

    private:
	bool closeable_ = true;
	bool has_identity_ = false;
	VnodeIdentity identity_;
};

// Host stdio (fd 0/1/2) as a descriptor-table entry. The guest-visible 0/1/2
// keep the fast path in the syscall handlers; this type only backs the copies
// dup()/dup2()/F_DUPFD hand out, so `write(dup(1), ...)` still reaches the
// host.
class StdioFile final : public File
{
    public:
	explicit StdioFile(int host_fd);

	[[nodiscard]] std::string_view path() const override
	{
		return path_;
	}
	[[nodiscard]] bool writable() const override
	{
		return host_fd_ != 0;
	}
	[[nodiscard]] FileKind kind() const override
	{
		return FileKind::Stdio;
	}
	[[nodiscard]] uint32_t pollEvents() const override
	{
		return host_fd_ == 0 ? kPollIn : kPollOut;
	}
	[[nodiscard]] Result<FileStat> stat() override;
	[[nodiscard]] Result<uint64_t> read(void *buffer, uint64_t count) override;
	[[nodiscard]] Result<uint64_t> readAt(uint64_t offset, void *buffer, uint64_t count) override;
	[[nodiscard]] Result<uint64_t> write(const void *buffer, uint64_t count) override;
	[[nodiscard]] Result<uint64_t> seek(int64_t offset, int whence) override;

    private:
	int host_fd_ = 0;
	std::string path_;
};

// Generated read-only file (/proc). The content is produced on first use and
// then frozen for the lifetime of the open description, like a seq_file that
// captured its snapshot when reading started.
class MemoryFile final : public File
{
    public:
	using Generator = std::function<std::string()>;

	MemoryFile(std::string path, Generator generator);

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
		return FileKind::Memory;
	}
	[[nodiscard]] Result<FileStat> stat() override;
	[[nodiscard]] Result<uint64_t> read(void *buffer, uint64_t count) override;
	[[nodiscard]] Result<uint64_t> readAt(uint64_t offset, void *buffer, uint64_t count) override;
	[[nodiscard]] Result<uint64_t> write(const void *buffer, uint64_t count) override;
	[[nodiscard]] Result<uint64_t> seek(int64_t offset, int whence) override;

    private:
	const std::string &materialize();

	std::string path_;
	Generator generator_;
	std::optional<std::string> content_;
	uint64_t offset_ = 0;
};

// Immutable content from a synthetic mount (/dev/__properties__). Root-owned
// and 0444 like the real files, so bionic's ownership checks pass unchanged.
class StaticFile final : public File
{
    public:
	StaticFile(std::string path, std::shared_ptr<const std::vector<uint8_t> > content);

	[[nodiscard]] std::string_view path() const override
	{
		return path_;
	}
	[[nodiscard]] bool writable() const override
	{
		return false;
	}
	[[nodiscard]] bool systemOwned() const override
	{
		return true;
	}
	[[nodiscard]] FileKind kind() const override
	{
		return FileKind::Static;
	}
	[[nodiscard]] Result<FileStat> stat() override;
	[[nodiscard]] Result<uint64_t> read(void *buffer, uint64_t count) override;
	[[nodiscard]] Result<uint64_t> readAt(uint64_t offset, void *buffer, uint64_t count) override;
	[[nodiscard]] Result<uint64_t> write(const void *buffer, uint64_t count) override;
	[[nodiscard]] Result<uint64_t> seek(int64_t offset, int whence) override;

    private:
	std::string path_;
	std::shared_ptr<const std::vector<uint8_t> > content_;
	uint64_t offset_ = 0;
};

// One host file. The read-only open backs the read-only roots; the writable
// open backs the per-instance sandbox and implements write/ftruncate/fsync.
class HostFile final : public File
{
    public:
	static Result<std::unique_ptr<HostFile> > open(std::string guest_path, std::string host_path);

	// `host_flags` is the translated O_* set (including O_CREAT/O_TRUNC/
	// O_APPEND/O_EXCL); `access` is 0/1/2 and decides writable().
	static Result<std::unique_ptr<HostFile> > openWritable(std::string guest_path,
		std::string host_path,
		int host_flags,
		uint64_t access,
		bool append,
		uint64_t mode);

	~HostFile() override;
	HostFile(const HostFile &) = delete;
	HostFile &operator=(const HostFile &) = delete;

	[[nodiscard]] std::string_view path() const override
	{
		return guest_path_;
	}
	[[nodiscard]] bool writable() const override
	{
		return writable_;
	}
	[[nodiscard]] FileKind kind() const override
	{
		return FileKind::Host;
	}
	[[nodiscard]] uint32_t pollEvents() const override
	{
		return kPollIn | (writable_ ? kPollOut : 0);
	}
	[[nodiscard]] Result<FileStat> stat() override;
	[[nodiscard]] Result<uint64_t> read(void *buffer, uint64_t count) override;
	[[nodiscard]] Result<uint64_t> readAt(uint64_t offset, void *buffer, uint64_t count) override;
	[[nodiscard]] Result<uint64_t> write(const void *buffer, uint64_t count) override;
	[[nodiscard]] Result<uint64_t> writeAt(uint64_t offset,
		const void *buffer,
		uint64_t count) override;
	[[nodiscard]] Result<uint64_t> seek(int64_t offset, int whence) override;
	[[nodiscard]] Result<void> truncate(uint64_t size) override;
	[[nodiscard]] Result<void> sync() override;

    private:
	HostFile(std::string guest_path, int fd, uint64_t size, bool writable, bool append);

	std::string guest_path_;
	int fd_ = -1;
	uint64_t size_ = 0;
	uint64_t offset_ = 0;
	bool writable_ = false;
	bool append_ = false;
};

} // namespace duckemu::runtime::vfs

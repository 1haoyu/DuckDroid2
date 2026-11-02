// SPDX-License-Identifier: GPL-2.0-only
#include "runtime/vfs/virtual_file_system.hpp"

#include <algorithm>
#include <memory>
#include <mutex>
#include <string>
#include <sys/stat.h>
#include <unordered_map>
#include <utility>
#include <vector>

#include "runtime/vfs/dir_file.hpp"

#include "runtime/clock/runtime_clock.hpp"
#include "runtime/device/device_profile.hpp"
#include "runtime/vfs/backends/host_ro_fs.hpp"
#include "runtime/vfs/backends/overlay_fs.hpp"
#include "runtime/vfs/backends/proc_fs.hpp"
#include "runtime/vfs/backends/sandbox_fs.hpp"
#include "runtime/vfs/backends/synthetic_mount_fs.hpp"

namespace duckemu::runtime::vfs
{
namespace
{

constexpr int64_t kAtFdcwd = -100;
constexpr uint32_t kRootMountId = 1;
constexpr uint32_t kProcMountId = 2;
constexpr uint32_t kFirstSyntheticMountId = 3;

Result<std::string> normalizePath(std::string_view path)
{
	std::vector<std::string_view> parts;
	size_t begin = 0;
	while (begin <= path.size())
	{
		size_t end = path.find('/', begin);
		if (end == std::string_view::npos)
		{
			end = path.size();
		}
		const std::string_view part = path.substr(begin, end - begin);
		if (!part.empty() && part != ".")
		{
			if (part == "..")
			{
				// The parent of "/" is "/"; above-root components are dropped.
				if (!parts.empty())
				{
					parts.pop_back();
				}
			}
			else
			{
				parts.push_back(part);
			}
		}
		if (end == path.size())
		{
			break;
		}
		begin = end + 1;
	}

	std::string result;
	for (const std::string_view part : parts)
	{
		result += '/';
		result += part;
	}
	return result.empty() ? std::string("/") : result;
}

} // namespace

VirtualFileSystem::VirtualFileSystem(RuntimeMemory &memory, VfsConfig config)
	: memory_(memory)
	, config_(std::move(config))
{
	std::vector<HostRoFs *> lowers;
	host_roots_.reserve(config_.host_roots.size());
	for (const std::string &root : config_.host_roots)
	{
		if (root.empty())
		{
			continue;
		}
		host_roots_.push_back(std::make_unique<HostRoFs>(root));
		lowers.push_back(host_roots_.back().get());
	}
	if (!config_.write_root.empty())
	{
		sandbox_ = std::make_unique<SandboxFs>(config_.write_root);
	}
	overlay_ = std::make_unique<OverlayFs>(sandbox_.get(), std::move(lowers));
	proc_ = std::make_unique<ProcFs>(overlay_.get(), [this] { return procContext(); });

	mounts_ = std::make_unique<MountTable>();
	mounts_->add(Mount{ "", overlay_.get(), sandbox_ == nullptr, kRootMountId, false });
	mounts_->add(Mount{ "/proc", proc_.get(), true, kProcMountId, true });

	uint32_t next_mount_id = kFirstSyntheticMountId;
	synthetic_.reserve(config_.synthetic_mounts.size());
	for (const SyntheticMountConfig &entry : config_.synthetic_mounts)
	{
		if (entry.files == nullptr)
		{
			continue;
		}
		auto backend =
			std::make_unique<SyntheticMountFs>(entry.prefix, entry.files, next_mount_id++);
		mounts_->add(Mount{ entry.prefix, backend.get(), true,
			static_cast<uint32_t>(next_mount_id - 1), true });
		synthetic_.push_back(std::move(backend));
	}

	// 0/1/2 are real entries in the descriptor table; only the runtime's
	// host-side stdio objects are permanent.
	for (uint64_t fd = 0; fd < 3; ++fd)
	{
		auto file = std::make_shared<StdioFile>(static_cast<int>(fd));
		file->setOpenFlags(fd == 0 ? 0 : 1);
		file->setCloseable(false);
		(void)fds_.install(fd, std::move(file));
	}
}

VirtualFileSystem::~VirtualFileSystem() = default;

Result<std::string> VirtualFileSystem::resolvePath(uint64_t dirfd, std::string_view path) const
{
	if (path.empty())
	{
		return Error{ ErrorCode::NotFound, "empty path" };
	}
	if (path.front() == '/')
	{
		return normalizePath(path);
	}
	std::string combined;
	if (static_cast<int64_t>(dirfd) != kAtFdcwd)
	{
		File *directory = fds_.find(dirfd);
		if (directory == nullptr)
		{
			return Error{ ErrorCode::BadFileDescriptor, "dirfd is not open" };
		}
		if (directory->kind() != FileKind::Directory)
		{
			return Error{ ErrorCode::NotDirectory, "dirfd is not a directory" };
		}
		combined = std::string(directory->path());
	}
	else
	{
		combined = "/";
	}
	combined += '/';
	combined.append(path);
	// ".." is clamped at the namespace root by normalizePath.
	return normalizePath(combined);
}

Result<MountPoint> VirtualFileSystem::resolveMount(const std::string &guest_path) const
{
	return mounts_->resolve(guest_path);
}

void VirtualFileSystem::applyOwner(FileStat &stat) const
{
	stat.uid = config_.uid;
	stat.gid = config_.gid;
	// An injected wall clock makes every timestamp replay-identical; host mode
	// keeps the real file times.
	if (config_.clock != nullptr && config_.clock->wallTimeInjected())
	{
		const uint64_t ns = config_.clock->wallTimeNs();
		const int64_t seconds = static_cast<int64_t>(ns / 1000000000ULL);
		const int64_t nanoseconds = static_cast<int64_t>(ns % 1000000000ULL);
		stat.atime_seconds = seconds;
		stat.atime_nanoseconds = nanoseconds;
		stat.mtime_seconds = seconds;
		stat.mtime_nanoseconds = nanoseconds;
		stat.ctime_seconds = seconds;
		stat.ctime_nanoseconds = nanoseconds;
	}
}

ProcContext VirtualFileSystem::procContext() const
{
	ProcContext context;
	context.pid = config_.pid;
	context.tid = config_.tid;
	context.progname = config_.progname;
	context.memory = &memory_;
	context.resolve_region_name = region_names_;
	context.thread_count = thread_count_;
	context.auxv = auxv_;
	context.device = config_.device;
	return context;
}

Result<uint64_t> VirtualFileSystem::open(uint64_t dirfd,
	std::string_view path,
	uint64_t flags,
	uint64_t mode)
{
	auto resolved = resolvePath(dirfd, path);
	if (!resolved.ok())
	{
		return resolved.error();
	}
	const std::string &guest_path = resolved.value();
	auto mount = resolveMount(guest_path);
	if (!mount.ok())
	{
		return mount.error();
	}
	auto file = mount.value().mount->backend->open(guest_path, mount.value().relative, flags, mode);
	if (!file.ok())
	{
		// The backends answer EISDIR for a directory; a read-only open turns
		// that into a snapshot descriptor. A write intent keeps the error.
		if (file.error().code == ErrorCode::IsDirectory && !writesRequested(flags))
		{
			return openDirectory(guest_path, mount.value(), flags);
		}
		return file.error();
	}
	file.value()->setOpenFlags(flags);
	if (mount.value().mount->synthetic_identity)
	{
		file.value()->setIdentity(
			syntheticIdentity(mount.value().mount->id, guest_path));
	}
	return fds_.insert(std::move(file.value()));
}

Result<uint64_t> VirtualFileSystem::openDirectory(const std::string &guest_path,
	const MountPoint &mount_point,
	uint64_t flags)
{
	const Mount &mount = *mount_point.mount;
	auto status = mount.backend->stat(guest_path, mount_point.relative);
	if (!status.ok())
	{
		return status.error();
	}
	auto entries = mount.backend->readdir(guest_path, mount_point.relative);
	if (!entries.ok())
	{
		return entries.error();
	}

	FileStat metadata = status.value();
	VnodeIdentity self{ metadata.device, metadata.inode };
	if (mount.synthetic_identity)
	{
		self = syntheticIdentity(mount.id, guest_path);
		metadata.device = self.device;
		metadata.inode = self.inode;
	}

	// Child mounts are visible in their parent's listing. The name belongs to
	// the parent mount, but its identity belongs to the child mount.
	for (const Mount &child_mount : mounts_->mounts())
	{
		if (child_mount.prefix.empty())
		{
			continue;
		}
		const size_t slash = child_mount.prefix.find_last_of('/');
		const std::string parent = slash == 0 ? "/" : child_mount.prefix.substr(0, slash);
		if (parent != guest_path)
		{
			continue;
		}
		const std::string name = child_mount.prefix.substr(slash + 1);
		auto existing = std::find_if(entries.value().begin(), entries.value().end(),
			[&name](const DirEntry &entry) { return entry.name == name; });
		if (existing != entries.value().end())
		{
			existing->type = kDirTypeDirectory;
			continue;
		}
		DirEntry entry;
		entry.name = name;
		entry.type = kDirTypeDirectory;
		entries.value().push_back(std::move(entry));
	}

	// Every entry's inode comes from the mount that would answer a stat of
	// that path, so getdents64 and fstatat always agree.
	for (DirEntry &entry : entries.value())
	{
		const std::string child_relative = mount_point.relative.empty() ?
							 entry.name :
							 mount_point.relative + "/" + entry.name;
		const std::string child_guest = MountTable::join(mount.prefix, child_relative);
		auto child = mounts_->resolve(child_guest);
		if (child.ok() && child.value().mount->synthetic_identity)
		{
			entry.ino = syntheticIdentity(child.value().mount->id, child_guest).inode;
		}
	}

	std::string parent_guest = "/";
	if (guest_path != "/")
	{
		const size_t slash = guest_path.find_last_of('/');
		parent_guest = slash == 0 ? "/" : guest_path.substr(0, slash);
	}
	uint64_t parent_inode = self.inode;
	if (parent_guest != guest_path)
	{
		auto parent = stat(static_cast<uint64_t>(kAtFdcwd), parent_guest);
		if (parent.ok())
		{
			parent_inode = parent.value().inode;
		}
	}

	std::vector<DirEntry> snapshot;
	snapshot.reserve(entries.value().size() + 2);
	snapshot.push_back(DirEntry{ ".", kDirTypeDirectory, self.inode });
	snapshot.push_back(DirEntry{ "..", kDirTypeDirectory, parent_inode });
	for (DirEntry &entry : entries.value())
	{
		snapshot.push_back(std::move(entry));
	}

	auto file = std::make_unique<DirFile>(guest_path, metadata, std::move(snapshot));
	file->setOpenFlags(flags);
	if (mount.synthetic_identity)
	{
		file->setIdentity(self);
	}
	return fds_.insert(std::move(file));
}

Result<void> VirtualFileSystem::close(uint64_t fd)
{
	std::shared_ptr<File> file = fds_.shared(fd);
	if (!file)
	{
		return Error{ ErrorCode::BadFileDescriptor, "fd is not open" };
	}
	if (!file->closeable())
	{
		return {};
	}
	return fds_.remove(fd);
}

Result<void> VirtualFileSystem::mkdir(uint64_t dirfd, std::string_view path, uint64_t mode)
{
	auto resolved = resolvePath(dirfd, path);
	if (!resolved.ok())
	{
		return resolved.error();
	}
	auto mount = resolveMount(resolved.value());
	if (!mount.ok())
	{
		return mount.error();
	}
	return mount.value().mount->backend->mkdir(resolved.value(), mount.value().relative, mode);
}

Result<void> VirtualFileSystem::unlink(uint64_t dirfd,
	std::string_view path,
	bool remove_directory)
{
	auto resolved = resolvePath(dirfd, path);
	if (!resolved.ok())
	{
		return resolved.error();
	}
	auto mount = resolveMount(resolved.value());
	if (!mount.ok())
	{
		return mount.error();
	}
	return mount.value().mount->backend->unlink(resolved.value(), mount.value().relative,
		remove_directory);
}

Result<void> VirtualFileSystem::rename(uint64_t old_dirfd,
	std::string_view old_path,
	uint64_t new_dirfd,
	std::string_view new_path)
{
	auto old_resolved = resolvePath(old_dirfd, old_path);
	if (!old_resolved.ok())
	{
		return old_resolved.error();
	}
	auto new_resolved = resolvePath(new_dirfd, new_path);
	if (!new_resolved.ok())
	{
		return new_resolved.error();
	}
	auto old_mount = resolveMount(old_resolved.value());
	if (!old_mount.ok())
	{
		return old_mount.error();
	}
	auto new_mount = resolveMount(new_resolved.value());
	if (!new_mount.ok())
	{
		return new_mount.error();
	}
	if (old_mount.value().mount != new_mount.value().mount)
	{
		return Error{ ErrorCode::CrossDevice,
			old_resolved.value() + " and " + new_resolved.value() + " are on different mounts" };
	}
	return old_mount.value().mount->backend->rename(old_resolved.value(),
		old_mount.value().relative, new_resolved.value(), new_mount.value().relative);
}

Result<void> VirtualFileSystem::truncateFd(uint64_t fd, uint64_t size)
{
	std::shared_ptr<File> file = fds_.shared(fd);
	if (!file)
	{
		return Error{ ErrorCode::BadFileDescriptor, "fd is not open" };
	}
	return file->truncate(size);
}

Result<void> VirtualFileSystem::syncFd(uint64_t fd)
{
	std::shared_ptr<File> file = fds_.shared(fd);
	if (!file)
	{
		return Error{ ErrorCode::BadFileDescriptor, "fd is not open" };
	}
	return file->sync();
}

Result<std::string> VirtualFileSystem::readLink(uint64_t dirfd, std::string_view path)
{
	auto resolved = resolvePath(dirfd, path);
	if (!resolved.ok())
	{
		return resolved.error();
	}
	const std::string &guest_path = resolved.value();

	// /proc/self is itself a magic link; both spellings name this process.
	const std::string self = "/proc/self";
	const std::string by_pid = "/proc/" + std::to_string(config_.pid);
	if (guest_path == self || guest_path == by_pid)
	{
		return std::to_string(config_.pid);
	}

	std::string_view rest;
	if (guest_path.rfind(self + "/", 0) == 0)
	{
		rest = std::string_view(guest_path).substr(self.size() + 1);
	}
	else if (guest_path.rfind(by_pid + "/", 0) == 0)
	{
		rest = std::string_view(guest_path).substr(by_pid.size() + 1);
	}

	if (rest == "exe")
	{
		return config_.device != nullptr ? config_.device->executable_path :
						   std::string("/system/bin/app_process64");
	}
	if (rest == "cwd" || rest == "root")
	{
		return std::string("/");
	}
	if (rest.rfind("fd/", 0) == 0)
	{
		const std::string_view number = rest.substr(3);
		uint64_t fd = 0;
		if (number.empty())
		{
			return Error{ ErrorCode::NotFound, "no such descriptor" };
		}
		for (char digit : number)
		{
			if (digit < '0' || digit > '9')
			{
				return Error{ ErrorCode::NotFound, "no such descriptor" };
			}
			fd = fd * 10 + static_cast<uint64_t>(digit - '0');
		}
		File *file = fds_.find(fd);
		if (file == nullptr)
		{
			return Error{ ErrorCode::NotFound, guest_path };
		}
		return fileLink(*file);
	}

	// Everything that exists is a regular file or directory in this model:
	// readlink(2) answers EINVAL for those.
	auto status = stat(dirfd, path);
	if (status.ok())
	{
		return Error{ ErrorCode::InvalidArgument, guest_path + " is not a symlink" };
	}
	return status.error();
}

Result<std::string> VirtualFileSystem::fileLink(File &file)
{
	auto status = file.stat();
	const std::string inode =
		status.ok() ? std::to_string(status.value().inode) : std::string("0");
	switch (file.kind())
	{
	case FileKind::Pipe:
		return "pipe:[" + inode + "]";
	case FileKind::Event:
		return std::string("anon_inode:[eventfd]");
	case FileKind::Timer:
		return std::string("anon_inode:[timerfd]");
	case FileKind::Epoll:
		return std::string("anon_inode:[eventpoll]");
	default:
		return std::string(file.path());
	}
}

FileSystemStats VirtualFileSystem::fileSystemForPath(const std::string &guest_path) const
{
	// Kernel magic numbers (linux/magic.h).
	constexpr uint64_t kF2fsMagic = 0xF2F52010;
	constexpr uint64_t kErofsMagic = 0xE0F5E1E2;
	constexpr uint64_t kTmpfsMagic = 0x01021994;
	constexpr uint64_t kProcMagic = 0x9fa0;
	constexpr uint64_t kBlockSize = 4096;

	FileSystemStats stats;
	stats.block_size = kBlockSize;
	stats.fragment_size = kBlockSize;

	const auto under = [](const std::string &path, std::string_view prefix) {
		return path == prefix || path.rfind(std::string(prefix) + "/", 0) == 0;
	};

	if (under(guest_path, "/proc"))
	{
		stats.type = kProcMagic;
		return stats;
	}
	if (under(guest_path, "/dev"))
	{
		stats.type = kTmpfsMagic;
		stats.blocks = (256ull << 20) / kBlockSize;
		stats.blocks_free = stats.blocks_available = stats.blocks;
		stats.files = stats.blocks / 2;
		stats.files_free = stats.files;
		return stats;
	}
	if (under(guest_path, "/data"))
	{
		const uint64_t total = config_.device != nullptr ? config_.device->data_total_bytes :
								   (64ull << 30);
		const uint64_t available = config_.device != nullptr ? config_.device->data_free_bytes :
								       (32ull << 30);
		stats.type = config_.device != nullptr ? config_.device->data_file_system_type :
							 kF2fsMagic;
		stats.blocks = total / kBlockSize;
		stats.blocks_free = std::min(available / kBlockSize, stats.blocks);
		stats.blocks_available = stats.blocks_free;
		stats.files = stats.blocks / 4;
		stats.files_free = stats.files / 2;
		return stats;
	}

	// The system images and anything else the host roots stand in for are
	// read-only (erofs on Android 13+).
	stats.type = kErofsMagic;
	stats.blocks = (2ull << 30) / kBlockSize;
	stats.flags = kMountReadOnly;
	return stats;
}

Result<FileSystemStats> VirtualFileSystem::statfs(uint64_t dirfd, std::string_view path)
{
	auto resolved = resolvePath(dirfd, path);
	if (!resolved.ok())
	{
		return resolved.error();
	}
	return fileSystemForPath(resolved.value());
}

Result<FileSystemStats> VirtualFileSystem::statfsFd(uint64_t fd)
{
	File *file = fds_.find(fd);
	if (file == nullptr)
	{
		return Error{ ErrorCode::BadFileDescriptor, "fd is not open" };
	}

	constexpr uint64_t kPipefsMagic = 0x50495045;
	constexpr uint64_t kAnonInodeMagic = 0x09041934;
	switch (file->kind())
	{
	case FileKind::Pipe:
	case FileKind::Event:
	case FileKind::Timer:
	case FileKind::Epoll:
	{
		FileSystemStats stats;
		stats.type = file->kind() == FileKind::Pipe ? kPipefsMagic : kAnonInodeMagic;
		return stats;
	}
	default:
		return fileSystemForPath(std::string(file->path()));
	}
}

Result<FileStat> VirtualFileSystem::stat(uint64_t dirfd, std::string_view path)
{
	auto resolved = resolvePath(dirfd, path);
	if (!resolved.ok())
	{
		return resolved.error();
	}
	const std::string &guest_path = resolved.value();
	auto mount = resolveMount(guest_path);
	if (!mount.ok())
	{
		return mount.error();
	}
	auto stat = mount.value().mount->backend->stat(guest_path, mount.value().relative);
	if (stat.ok())
	{
		if (mount.value().mount->synthetic_identity)
		{
			const VnodeIdentity identity =
				syntheticIdentity(mount.value().mount->id, guest_path);
			stat.value().device = identity.device;
			stat.value().inode = identity.inode;
		}
		if (!mount.value().mount->backend->systemOwned())
		{
			applyOwner(stat.value());
		}
	}
	return stat;
}

Result<FileStat> VirtualFileSystem::statFd(uint64_t fd)
{
	File *file = fds_.find(fd);
	if (file == nullptr)
	{
		return Error{ ErrorCode::BadFileDescriptor, "fd is not open" };
	}
	auto stat = file->stat();
	if (stat.ok())
	{
		if (file->hasIdentity())
		{
			const VnodeIdentity identity = file->identity();
			stat.value().device = identity.device;
			stat.value().inode = identity.inode;
		}
		if (!file->systemOwned())
		{
			applyOwner(stat.value());
		}
	}
	return stat;
}

Result<std::shared_ptr<File> > VirtualFileSystem::describe(uint64_t fd)
{
	std::shared_ptr<File> file = fds_.shared(fd);
	if (!file)
	{
		return Error{ ErrorCode::BadFileDescriptor, "fd is not open" };
	}
	return file;
}

uint64_t VirtualFileSystem::addActivityWaiter(std::function<void()> callback)
{
	std::lock_guard<std::mutex> lock(waiters_mutex_);
	const uint64_t id = next_waiter_id_++;
	activity_waiters_.emplace(id, std::move(callback));
	return id;
}

void VirtualFileSystem::removeActivityWaiter(uint64_t id)
{
	std::lock_guard<std::mutex> lock(waiters_mutex_);
	activity_waiters_.erase(id);
}

void VirtualFileSystem::notifyActivity()
{
	// Callbacks may complete a parked syscall, which can in turn remove
	// themselves; copy first so the map is not mutated mid-iteration.
	std::vector<std::function<void()> > callbacks;
	{
		std::lock_guard<std::mutex> lock(waiters_mutex_);
		callbacks.reserve(activity_waiters_.size());
		for (const auto &entry : activity_waiters_)
		{
			callbacks.push_back(entry.second);
		}
	}
	for (const auto &callback : callbacks)
	{
		if (callback)
		{
			callback();
		}
	}
}

Result<uint64_t> VirtualFileSystem::duplicate(uint64_t fd, uint64_t minimum)
{
	auto file = describe(fd);
	if (!file.ok())
	{
		return file.error();
	}
	return fds_.insertShared(file.value(), minimum);
}

Result<void> VirtualFileSystem::duplicateTo(uint64_t fd, uint64_t target)
{
	if (fd == target)
	{
		// dup2 on an open descriptor is a successful no-op; validate the
		// source so a closed fd still reports EBADF.
		auto source = describe(fd);
		if (!source.ok())
		{
			return source.error();
		}
		return {};
	}
	auto file = describe(fd);
	if (!file.ok())
	{
		return file.error();
	}
	return fds_.assign(target, file.value());
}

Result<void> VirtualFileSystem::access(uint64_t dirfd, std::string_view path, uint64_t mode)
{
	auto resolved = resolvePath(dirfd, path);
	if (!resolved.ok())
	{
		return resolved.error();
	}
	auto mount = resolveMount(resolved.value());
	if (!mount.ok())
	{
		return mount.error();
	}
	return mount.value().mount->backend->access(resolved.value(), mount.value().relative, mode);
}

} // namespace duckemu::runtime::vfs

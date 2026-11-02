// SPDX-License-Identifier: GPL-2.0-only
#include "runtime/vfs/dev_file_system.hpp"

#include <algorithm>
#include <cstring>
#include <sys/stat.h>
#include <utility>
#include <vector>

#include "runtime/random/random_source.hpp"
#include "runtime/vfs/file.hpp"

namespace duckemu::runtime::vfs
{
namespace
{

constexpr uint32_t kDeviceMode = S_IFCHR | 0666;

// Linux dev_t encoding for the small major/minor pairs used here.
constexpr uint64_t deviceNumber(uint32_t major, uint32_t minor)
{
	return (static_cast<uint64_t>(major & 0xfffu) << 8) | (minor & 0xffu);
}

constexpr uint64_t kNullDevice = deviceNumber(1, 3);
constexpr uint64_t kZeroDevice = deviceNumber(1, 5);
constexpr uint64_t kRandomDevice = deviceNumber(1, 8);
constexpr uint64_t kUrandomDevice = deviceNumber(1, 9);

enum class DeviceKind
{
	Null,   // reads EOF, swallows writes
	Zero,   // reads zeroes, swallows writes
	Random, // reads from the instance entropy stream
};

// One open description of a character device. Offsets are tracked but have no
// meaning, like the kernel's char devices.
class DeviceFile final : public File
{
    public:
	DeviceFile(std::string path, uint64_t flags, DeviceKind kind, uint64_t rdev,
		RandomSource &random)
		: path_(std::move(path))
		, kind_(kind)
		, rdev_(rdev)
		, random_(random)
		, writable_((flags & 3) != 0) // O_WRONLY / O_RDWR
		, readable_((flags & 3) != 1) // not O_WRONLY
	{
	}

	[[nodiscard]] std::string_view path() const override
	{
		return path_;
	}
	[[nodiscard]] bool writable() const override
	{
		return writable_;
	}
	[[nodiscard]] bool systemOwned() const override
	{
		return true;
	}
	[[nodiscard]] FileKind kind() const override
	{
		return FileKind::Device;
	}
	[[nodiscard]] uint32_t pollEvents() const override
	{
		return kPollIn | kPollOut;
	}

	[[nodiscard]] Result<FileStat> stat() override
	{
		FileStat result;
		result.inode = std::hash<std::string>{}(path_);
		result.mode = kDeviceMode;
		result.rdev = rdev_;
		result.uid = 0;
		result.gid = 0;
		return result;
	}

	[[nodiscard]] Result<uint64_t> read(void *buffer, uint64_t count) override
	{
		if (!readable_)
		{
			return Error{ ErrorCode::BadFileDescriptor, "descriptor is write-only" };
		}
		const uint64_t produced = produce(buffer, count);
		offset_ += produced;
		return produced;
	}

	[[nodiscard]] Result<uint64_t> readAt(uint64_t, void *buffer, uint64_t count) override
	{
		// A file mapping of /dev/zero or /dev/urandom reads from the start;
		// /dev/null has no bytes at any offset.
		return produce(buffer, count);
	}

	[[nodiscard]] Result<uint64_t> write(const void *, uint64_t count) override
	{
		// The kernel accepts (and mostly discards) writes to all four nodes.
		return count;
	}

	[[nodiscard]] Result<uint64_t> seek(int64_t offset, int whence) override
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

    private:
	uint64_t produce(void *buffer, uint64_t count)
	{
		switch (kind_)
		{
		case DeviceKind::Null:
			return 0;
		case DeviceKind::Zero:
			std::memset(buffer, 0, static_cast<size_t>(count));
			return count;
		case DeviceKind::Random:
			random_.fill(buffer, count);
			return count;
		}
		return 0;
	}

	std::string path_;
	DeviceKind kind_;
	uint64_t rdev_;
	RandomSource &random_;
	bool writable_;
	bool readable_;
	uint64_t offset_ = 0;
};

} // namespace

DevFileSystem::DevFileSystem(RandomSource &random)
	: random_(&random)
{
	SyntheticNode directory;
	directory.directory = true;
	nodes_.emplace("/dev", directory);

	const auto add = [this](std::string path, DeviceKind kind, uint64_t rdev) {
		SyntheticNode node;
		node.mode = kDeviceMode;
		node.rdev = rdev;
		RandomSource *source = random_;
		node.create = [kind, rdev, source](std::string open_path, uint64_t flags) {
			return std::unique_ptr<File>(
				new DeviceFile(std::move(open_path), flags, kind, rdev, *source));
		};
		nodes_.emplace(std::move(path), std::move(node));
	};
	add("/dev/null", DeviceKind::Null, kNullDevice);
	add("/dev/zero", DeviceKind::Zero, kZeroDevice);
	add("/dev/random", DeviceKind::Random, kRandomDevice);
	add("/dev/urandom", DeviceKind::Random, kUrandomDevice);
}

std::optional<SyntheticNode> DevFileSystem::lookup(std::string_view guest_path) const
{
	const auto found = nodes_.find(std::string(guest_path));
	if (found == nodes_.end())
	{
		return std::nullopt;
	}
	return found->second;
}

std::vector<DirEntry> DevFileSystem::list(std::string_view guest_dir) const
{
	const std::string prefix = std::string(guest_dir) + "/";
	std::vector<DirEntry> entries;
	for (const auto &[path, node] : nodes_)
	{
		if (path.size() <= prefix.size() || path.compare(0, prefix.size(), prefix) != 0)
		{
			continue;
		}
		const std::string_view name = std::string_view(path).substr(prefix.size());
		if (name.find('/') != std::string_view::npos)
		{
			continue;
		}
		DirEntry entry;
		entry.name = std::string(name);
		if (node.directory)
		{
			entry.type = kDirTypeDirectory;
		}
		else if ((node.mode & S_IFMT) == S_IFCHR)
		{
			entry.type = kDirTypeChar;
		}
		else
		{
			entry.type = kDirTypeRegular;
		}
		entries.push_back(std::move(entry));
	}
	std::sort(entries.begin(), entries.end(),
		[](const DirEntry &left, const DirEntry &right) { return left.name < right.name; });
	return entries;
}

} // namespace duckemu::runtime::vfs

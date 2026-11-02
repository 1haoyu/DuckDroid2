// SPDX-License-Identifier: GPL-2.0-only
#pragma once

#include <cstdint>
#include <map>
#include <memory>

#include "common/error/result.hpp"
#include "runtime/vfs/file.hpp"

namespace duckemu::runtime::vfs
{

// Process-wide descriptor table. 0/1/2 are the host stdio and are not stored
// here; the first guest descriptor is 3, matching Linux.
//
// Entries are shared_ptr so dup()/dup2()/F_DUPFD can point a second descriptor
// at the same open file description (shared offset), as Linux does.
class FdTable
{
    public:
	static constexpr uint64_t kFirstGuestFd = 3;

	[[nodiscard]] Result<uint64_t> insert(std::unique_ptr<File> file);

	// Lowest free descriptor >= `minimum`.
	[[nodiscard]] Result<uint64_t> insertShared(std::shared_ptr<File> file,
		uint64_t minimum = kFirstGuestFd);

	// Places `file` at exactly `fd`, closing whatever was there (dup2).
	[[nodiscard]] Result<void> assign(uint64_t fd, std::shared_ptr<File> file);

	// Bootstrap installation (standard descriptors). Unlike insert(), it does
	// not skip the host-reserved 0/1/2 range.
	[[nodiscard]] Result<void> install(uint64_t fd, std::shared_ptr<File> file);

	[[nodiscard]] File *find(uint64_t fd) const;
	[[nodiscard]] std::shared_ptr<File> shared(uint64_t fd) const;
	Result<void> remove(uint64_t fd);

	[[nodiscard]] size_t size() const
	{
		return files_.size();
	}

    private:
	std::map<uint64_t, std::shared_ptr<File> > files_;
};

} // namespace duckemu::runtime::vfs

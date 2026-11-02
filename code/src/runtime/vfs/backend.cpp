// SPDX-License-Identifier: GPL-2.0-only
#include "runtime/vfs/backend.hpp"

namespace duckemu::runtime::vfs
{

Result<void> MountBackend::access(const std::string &guest_path,
	const std::string &,
	uint64_t) const
{
	return Error{ ErrorCode::PermissionDenied, guest_path + " is not accessible" };
}

Result<void> MountBackend::mkdir(const std::string &guest_path, const std::string &, uint64_t)
{
	return Error{ ErrorCode::ReadOnly, guest_path + " is on a read-only mount" };
}

Result<void> MountBackend::unlink(const std::string &guest_path, const std::string &, bool)
{
	return Error{ ErrorCode::ReadOnly, guest_path + " is on a read-only mount" };
}

Result<void> MountBackend::rename(const std::string &old_guest_path,
	const std::string &,
	const std::string &,
	const std::string &)
{
	return Error{ ErrorCode::ReadOnly, old_guest_path + " is on a read-only mount" };
}

Result<std::vector<DirEntry> > MountBackend::readdir(const std::string &guest_path, const std::string &) const
{
	return Error{ ErrorCode::Unsupported, guest_path + " cannot be enumerated" };
}

} // namespace duckemu::runtime::vfs

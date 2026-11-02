// SPDX-License-Identifier: GPL-2.0-only
#pragma once

#include <cerrno>
#include <string>
#include <utility>

#include "common/error/result.hpp"

namespace duckemu::runtime::vfs
{

// Translation happens once, at the backend boundary: host errno keeps its
// meaning instead of being folded into a generic permission failure.
inline Error errnoToError(int error_number, std::string message)
{
	switch (error_number)
	{
	case ENOENT:
		return Error{ ErrorCode::NotFound, std::move(message) };
	case EACCES:
	case EPERM:
		return Error{ ErrorCode::PermissionDenied, std::move(message) };
	case EROFS:
		return Error{ ErrorCode::ReadOnly, std::move(message) };
	case EISDIR:
		return Error{ ErrorCode::IsDirectory, std::move(message) };
	case ENOTDIR:
		return Error{ ErrorCode::NotDirectory, std::move(message) };
	case EEXIST:
	case ENOTEMPTY:
		return Error{ ErrorCode::AlreadyExists, std::move(message) };
	case EINVAL:
	case ENAMETOOLONG:
		return Error{ ErrorCode::InvalidArgument, std::move(message) };
	case EBADF:
		return Error{ ErrorCode::BadFileDescriptor, std::move(message) };
	case ESPIPE:
		return Error{ ErrorCode::NotSeekable, std::move(message) };
	default:
		return Error{ ErrorCode::Internal, std::move(message) };
	}
}

} // namespace duckemu::runtime::vfs

// SPDX-License-Identifier: GPL-2.0-only
#pragma once

#include <cstdint>

#include "runtime/vfs/vfs_flags.hpp"

namespace duckemu::runtime::vfs
{

// The flags an open description remembers. The access mode and O_APPEND are
// visible through fcntl(F_GETFL); O_CREAT/O_EXCL/O_TRUNC are creation-time
// inputs and are not reported, matching the kernel.
inline constexpr uint64_t kStatusFlagMask = kAccessModeMask | kOAppend;

[[nodiscard]] constexpr uint64_t statusFlags(uint64_t open_flags)
{
	return open_flags & kStatusFlagMask;
}

} // namespace duckemu::runtime::vfs

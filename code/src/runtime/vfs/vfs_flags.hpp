// SPDX-License-Identifier: GPL-2.0-only
#pragma once

#include <cstdint>

namespace duckemu::runtime::vfs
{

// Guest-visible open(2)/access(2) constants (Linux arm64). The host's values
// match, but spelling them out keeps the guest ABI independent of the build
// host.
inline constexpr uint64_t kAccessModeMask = 3;
inline constexpr uint64_t kOfdCread = 0x80000;
inline constexpr uint64_t kODirectory = 0x10000;
inline constexpr uint64_t kOCreate = 0x40;
inline constexpr uint64_t kOExclusive = 0x80;
inline constexpr uint64_t kOTruncate = 0x200;
inline constexpr uint64_t kOAppend = 0x400;

inline constexpr uint64_t kAccessExecute = 1;
inline constexpr uint64_t kAccessWrite = 2;
inline constexpr uint64_t kAccessRead = 4;

// access(2) mode bits are not the same as O_* access modes.
inline constexpr bool writesRequested(uint64_t flags)
{
	return (flags & kAccessModeMask) != 0 ||
	       (flags & (kOCreate | kOTruncate | kOAppend)) != 0;
}

} // namespace duckemu::runtime::vfs

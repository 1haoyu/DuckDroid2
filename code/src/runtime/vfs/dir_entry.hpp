// SPDX-License-Identifier: GPL-2.0-only
#pragma once

#include <cstdint>
#include <string>

namespace duckemu::runtime::vfs
{

// DT_* values for getdents64. Numerically identical to the kernel's.
inline constexpr uint8_t kDirTypeUnknown = 0;
inline constexpr uint8_t kDirTypeFifo = 1;
inline constexpr uint8_t kDirTypeChar = 2;
inline constexpr uint8_t kDirTypeDirectory = 4;
inline constexpr uint8_t kDirTypeBlock = 6;
inline constexpr uint8_t kDirTypeRegular = 8;
inline constexpr uint8_t kDirTypeSymlink = 10;
inline constexpr uint8_t kDirTypeSocket = 12;

// One entry produced by a backend's readdir, before the VFS adds "."/".." or
// rewrites synthetic inodes.
struct DirEntry
{
	std::string name;
	uint8_t type = kDirTypeUnknown;
	uint64_t ino = 0;
};

[[nodiscard]] constexpr uint8_t dirTypeFromMode(uint32_t mode)
{
	switch (mode & 0170000)
	{
	case 0010000:
		return kDirTypeFifo;
	case 0020000:
		return kDirTypeChar;
	case 0040000:
		return kDirTypeDirectory;
	case 0060000:
		return kDirTypeBlock;
	case 0100000:
		return kDirTypeRegular;
	case 0120000:
		return kDirTypeSymlink;
	case 0140000:
		return kDirTypeSocket;
	default:
		return kDirTypeUnknown;
	}
}

} // namespace duckemu::runtime::vfs

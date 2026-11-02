// SPDX-License-Identifier: GPL-2.0-only
#pragma once

#include <cstdint>
#include <string_view>

namespace duckemu::runtime::vfs
{

// Identity of a node as the guest sees it. Host-backed nodes use the host
// st_dev/st_ino (rename does not change them). Synthetic nodes derive a
// stable pair from the mount and the guest path, so a Vnode can be rebuilt at
// any time and every open description still agrees.
struct VnodeIdentity
{
	uint64_t device = 0;
	uint64_t inode = 0;
};

// splitmix64 finalizer: cheap, well-distributed, no state.
[[nodiscard]] constexpr uint64_t hash64(uint64_t value)
{
	value += 0x9e3779b97f4a7c15ULL;
	value = (value ^ (value >> 30)) * 0xbf58476d1ce4e5b9ULL;
	value = (value ^ (value >> 27)) * 0x94d049bb133111ebULL;
	return value ^ (value >> 31);
}

[[nodiscard]] inline uint64_t hashPath(std::string_view path)
{
	// FNV-1a over the guest path, then the splitmix finalizer.
	uint64_t hash = 1469598103934665603ULL;
	for (char character : path)
	{
		hash ^= static_cast<uint64_t>(static_cast<unsigned char>(character));
		hash *= 1099511628211ULL;
	}
	return hash64(hash);
}

[[nodiscard]] inline VnodeIdentity syntheticIdentity(uint32_t mount_id, std::string_view guest_path)
{
	VnodeIdentity identity;
	identity.device = mount_id;
	identity.inode = hash64(static_cast<uint64_t>(mount_id) * 0x100000001b3ULL ^
				hashPath(guest_path));
	return identity;
}

} // namespace duckemu::runtime::vfs

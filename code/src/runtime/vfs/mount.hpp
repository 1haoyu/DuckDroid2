// SPDX-License-Identifier: GPL-2.0-only
#pragma once

#include <cstdint>
#include <string>

namespace duckemu::runtime::vfs
{

class MountBackend;

// One entry of the instance's fixed namespace. `prefix` is the normalized
// guest path without a trailing slash ("" for the root mount).
struct Mount
{
	std::string prefix;
	MountBackend *backend = nullptr;
	bool readonly = true;
	// Stable identity for synthetic nodes and the statfs fsid.
	uint32_t id = 0;
	// Nodes on this mount have no host inode: dev/ino are derived from
	// (id, guest path). Applies to /proc and the synthetic mounts.
	bool synthetic_identity = false;
};

} // namespace duckemu::runtime::vfs

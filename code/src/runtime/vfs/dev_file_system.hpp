// SPDX-License-Identifier: GPL-2.0-only
#pragma once

#include <map>
#include <optional>
#include <string>
#include <string_view>

#include "runtime/vfs/synthetic_file_system.hpp"

namespace duckemu::runtime
{
class RandomSource;
}

namespace duckemu::runtime::vfs
{

// The /dev character nodes libc and crypto libraries open by path:
// /dev/null, /dev/zero, /dev/random, /dev/urandom, plus the /dev directory
// itself. getrandom(2) and /dev/{u,}random share one RandomSource.
class DevFileSystem final : public SyntheticFileSystem
{
    public:
	explicit DevFileSystem(RandomSource &random);

	[[nodiscard]] std::optional<SyntheticNode> lookup(
		std::string_view guest_path) const override;
	[[nodiscard]] std::vector<DirEntry> list(std::string_view guest_dir) const override;

    private:
	RandomSource *random_;
	std::map<std::string, SyntheticNode> nodes_;
};

} // namespace duckemu::runtime::vfs

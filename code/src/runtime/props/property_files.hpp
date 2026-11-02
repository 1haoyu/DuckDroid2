// SPDX-License-Identifier: GPL-2.0-only
#pragma once

#include <map>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "common/error/result.hpp"
#include "runtime/props/property_table.hpp"
#include "runtime/vfs/synthetic_file_system.hpp"

namespace duckemu::runtime::props
{

// The /dev/__properties__ namespace bionic's property reader opens. A pure
// read-only synthetic mount: the property service is not modelled, so writes
// answer EROFS exactly as they would for an app without permission.
class PropertyFiles final : public vfs::SyntheticFileSystem
{
    public:
	static Result<std::unique_ptr<PropertyFiles> > build(const PropertyTable &table);

	[[nodiscard]] std::optional<vfs::SyntheticNode> lookup(
		std::string_view guest_path) const override;
	[[nodiscard]] std::vector<vfs::DirEntry> list(std::string_view guest_dir) const override;

	[[nodiscard]] const std::string &context() const
	{
		return context_;
	}

    private:
	PropertyFiles() = default;

	std::string context_;
	std::map<std::string, vfs::SyntheticNode> nodes_;
};

} // namespace duckemu::runtime::props

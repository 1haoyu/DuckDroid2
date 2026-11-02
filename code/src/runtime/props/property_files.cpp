// SPDX-License-Identifier: GPL-2.0-only
#include "runtime/props/property_files.hpp"

#include <algorithm>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "runtime/props/property_image.hpp"

namespace duckemu::runtime::props
{
namespace
{

std::shared_ptr<const std::vector<uint8_t> > share(std::vector<uint8_t> bytes)
{
	return std::make_shared<const std::vector<uint8_t> >(std::move(bytes));
}

} // namespace

Result<std::unique_ptr<PropertyFiles> > PropertyFiles::build(const PropertyTable &table)
{
	auto images = buildImages(table);
	if (!images.ok())
	{
		return images.error();
	}

	auto blob = [](std::vector<uint8_t> bytes) {
		vfs::SyntheticNode node;
		node.content = share(std::move(bytes));
		return node;
	};

	std::unique_ptr<PropertyFiles> files(new PropertyFiles());
	files->context_ = images.value().context;
	vfs::SyntheticNode directory;
	directory.directory = true;
	files->nodes_.emplace("/dev/__properties__", directory);
	files->nodes_.emplace("/dev/__properties__/property_info",
		blob(std::move(images.value().property_info)));
	files->nodes_.emplace("/dev/__properties__/properties_serial",
		blob(std::move(images.value().serial_area)));
	files->nodes_.emplace("/dev/__properties__/" + files->context_,
		blob(std::move(images.value().context_area)));
	return files;
}

std::optional<vfs::SyntheticNode> PropertyFiles::lookup(std::string_view guest_path) const
{
	const auto found = nodes_.find(std::string(guest_path));
	if (found == nodes_.end())
	{
		return std::nullopt;
	}
	return found->second;
}

std::vector<vfs::DirEntry> PropertyFiles::list(std::string_view guest_dir) const
{
	const std::string prefix = std::string(guest_dir) + "/";
	std::vector<vfs::DirEntry> entries;
	for (const auto &[path, node] : nodes_)
	{
		if (path.size() <= prefix.size() || path.compare(0, prefix.size(), prefix) != 0)
		{
			continue;
		}
		const std::string_view name = std::string_view(path).substr(prefix.size());
		if (name.find('/') != std::string_view::npos)
		{
			continue;
		}
		vfs::DirEntry entry;
		entry.name = std::string(name);
		entry.type = node.directory ? vfs::kDirTypeDirectory : vfs::kDirTypeRegular;
		entries.push_back(std::move(entry));
	}
	std::sort(entries.begin(), entries.end(),
		[](const vfs::DirEntry &left, const vfs::DirEntry &right) {
			return left.name < right.name;
		});
	return entries;
}

} // namespace duckemu::runtime::props

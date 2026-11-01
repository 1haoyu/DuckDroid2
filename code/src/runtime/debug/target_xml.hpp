// SPDX-License-Identifier: GPL-2.0-only
#pragma once

#include <string>

namespace duckemu::runtime::debug
{

// `qXfer:features:read:target.xml`: aarch64 core only (x0-x30, sp, pc, cpsr).
// Binary Ninja / gdb derive the 268-byte `g` layout from this description.
std::string aarch64TargetXml();

} // namespace duckemu::runtime::debug

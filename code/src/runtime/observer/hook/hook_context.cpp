// SPDX-License-Identifier: GPL-2.0-only
#include "runtime/observer/hook/hook_context.hpp"

#include <unicorn/unicorn.h>

#include <algorithm>
#include <cstring>
#include <string>

#include "runtime/memory/address_space.hpp"
#include "runtime/memory/region.hpp"

namespace duckemu::runtime::observer
{
namespace
{

Result<void> checkRange(const RuntimeMemory &memory, uint64_t address, size_t size, uint32_t required)
{
	if (size == 0)
	{
		return {};
	}
	uint64_t cursor = untagAddress(address);
	if (cursor > UINT64_MAX - size)
	{
		return Error{ ErrorCode::InvalidArgument, "hook memory range overflows" };
	}
	const uint64_t end = cursor + size;
	while (cursor < end)
	{
		const auto region = memory.regionAt(GuestVA{ cursor });
		if (!region.has_value())
		{
			return Error{ ErrorCode::Unmapped, "hook memory range is not mapped" };
		}
		if ((region->perms & required) != required)
		{
			return Error{ ErrorCode::PermissionDenied, "hook memory range lacks the required permission" };
		}
		const uint64_t chunk = std::min<uint64_t>(end - cursor, region->end() - cursor);
		cursor += chunk;
	}
	return {};
}

uc_engine *engineOf(void *engine) noexcept
{
	return static_cast<uc_engine *>(engine);
}

} // namespace

uint64_t HookContext::x(int index) const noexcept
{
	if (index < 0 || index >= static_cast<int>(x_.size()))
	{
		return 0;
	}
	return x_[static_cast<size_t>(index)];
}

namespace
{

int xRegister(int index) noexcept
{
	if (index >= 0 && index <= 28)
	{
		return static_cast<int>(UC_ARM64_REG_X0) + index;
	}
	if (index == 29)
	{
		return UC_ARM64_REG_FP;
	}
	if (index == 30)
	{
		return UC_ARM64_REG_LR;
	}
	return -1;
}

} // namespace

uint64_t HookContext::readX(int index) const
{
	const int reg = xRegister(index);
	if (reg < 0)
	{
		return 0;
	}
	uint64_t value = 0;
	if (uc_reg_read(engineOf(engine_), reg, &value) != UC_ERR_OK)
	{
		return 0;
	}
	return value;
}

void HookContext::writeX(int index, uint64_t value)
{
	const int reg = xRegister(index);
	if (reg < 0)
	{
		return;
	}
	(void)uc_reg_write(engineOf(engine_), reg, &value);
}

uint64_t HookContext::readSp() const
{
	uint64_t value = 0;
	if (uc_reg_read(engineOf(engine_), UC_ARM64_REG_SP, &value) != UC_ERR_OK)
	{
		return 0;
	}
	return value;
}

void HookContext::writeSp(uint64_t value)
{
	(void)uc_reg_write(engineOf(engine_), UC_ARM64_REG_SP, &value);
}

uint32_t HookContext::readW(int index) const
{
	if (index < 0 || index > 30)
	{
		return 0;
	}
	uint32_t value = 0;
	if (uc_reg_read(engineOf(engine_), UC_ARM64_REG_W0 + index, &value) != UC_ERR_OK)
	{
		return 0;
	}
	return value;
}

void HookContext::writeW(int index, uint32_t value)
{
	if (index < 0 || index > 30)
	{
		return;
	}
	(void)uc_reg_write(engineOf(engine_), UC_ARM64_REG_W0 + index, &value);
}

Result<std::vector<uint8_t> > HookContext::readMemory(uint64_t address, size_t size) const
{
	std::vector<uint8_t> output(size);
	if (memory_ == nullptr)
	{
		return Error{ ErrorCode::Internal, "hook context has no memory" };
	}
	const auto checked = checkRange(*memory_, address, size, PermRead);
	if (!checked.ok())
	{
		return checked.error();
	}
	const auto read = memory_->read(GuestVA{ address }, output.data(), size);
	if (!read.ok())
	{
		return read.error();
	}
	return output;
}

Result<void> HookContext::writeMemory(uint64_t address, const void *data, size_t size)
{
	if (memory_ == nullptr)
	{
		return Error{ ErrorCode::Internal, "hook context has no memory" };
	}
	const auto checked = checkRange(*memory_, address, size, PermWrite);
	if (!checked.ok())
	{
		return checked.error();
	}
	return memory_->write(GuestVA{ address }, data, size);
}

Result<void> HookContext::forceWriteMemory(uint64_t address, const void *data, size_t size)
{
	if (memory_ == nullptr)
	{
		return Error{ ErrorCode::Internal, "hook context has no memory" };
	}
	const auto checked = checkRange(*memory_, address, size, 0);
	if (!checked.ok())
	{
		return checked.error();
	}
	return memory_->write(GuestVA{ address }, data, size);
}

Result<void> HookContext::setPc(uint64_t address)
{
	const uc_err err = uc_reg_write(engineOf(engine_), UC_ARM64_REG_PC, &address);
	if (err != UC_ERR_OK)
	{
		return Error{ ErrorCode::EmulationFault, std::string("uc_reg_write(PC): ") + uc_strerror(err) };
	}
	return {};
}

void HookContext::requestStop()
{
	uc_emu_stop(engineOf(engine_));
}

} // namespace duckemu::runtime::observer

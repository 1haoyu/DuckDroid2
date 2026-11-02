// SPDX-License-Identifier: GPL-2.0-only
#include "runtime/jni/refs/ref_table.hpp"

#include <algorithm>

#include "runtime/jni/world/java_world.hpp"
#include "runtime/memory/address_space.hpp"

namespace duckemu::runtime::jni
{

RefTable::RefTable(RuntimeMemory &memory, JniArena &arena)
	: memory_(memory)
	, arena_(arena)
{
}

RefTable::ThreadState *RefTable::findThread(uint64_t thread_key)
{
	const auto found = threads_.find(thread_key);
	return found == threads_.end() ? nullptr : &found->second;
}

const RefTable::ThreadState *RefTable::findThread(uint64_t thread_key) const
{
	const auto found = threads_.find(thread_key);
	return found == threads_.end() ? nullptr : &found->second;
}

Result<uint64_t> RefTable::store(uint64_t object)
{
	uint64_t cell = 0;
	if (!free_cells_.empty())
	{
		cell = free_cells_.back();
		free_cells_.pop_back();
	}
	else
	{
		auto allocated = arena_.allocate(sizeof(uint64_t), 8);
		if (!allocated.ok())
		{
			return allocated.error();
		}
		cell = allocated.value();
	}
	auto written = memory_.write(GuestVA{ cell }, &object, sizeof(object));
	if (!written.ok())
	{
		free_cells_.push_back(cell);
		return written.error();
	}
	return cell;
}

void RefTable::releaseCell(uint64_t handle)
{
	const uint64_t zero = 0;
	(void)memory_.write(GuestVA{ handle }, &zero, sizeof(zero));
	free_cells_.push_back(handle);
}

Result<uint64_t> RefTable::newLocal(uint64_t thread_key, uint64_t object)
{
	if (object == 0)
	{
		return uint64_t{ 0 };
	}
	ThreadState &state = threads_[thread_key];

	size_t slot = 0;
	if (!state.reusable_slots.empty())
	{
		slot = state.reusable_slots.back();
		state.reusable_slots.pop_back();
	}
	else
	{
		if (state.handles.size() >= kMaxLocalRefs)
		{
			return Error{ ErrorCode::OutOfMemory, "local reference table is full" };
		}
		slot = state.handles.size();
		state.handles.push_back(0);
	}

	auto cell = store(object);
	if (!cell.ok())
	{
		state.reusable_slots.push_back(slot);
		return cell.error();
	}
	state.handles[slot] = cell.value();
	state.slot_of[cell.value()] = slot;
	++state.live;
	return cell.value();
}

Result<uint64_t> RefTable::newGlobal(uint64_t object)
{
	if (object == 0)
	{
		return uint64_t{ 0 };
	}
	auto cell = store(object);
	if (!cell.ok())
	{
		return cell.error();
	}
	globals_.insert(cell.value());
	return cell.value();
}

Result<uint64_t> RefTable::newWeakGlobal(uint64_t object)
{
	if (object == 0)
	{
		return uint64_t{ 0 };
	}
	auto cell = store(object);
	if (!cell.ok())
	{
		return cell.error();
	}
	weak_globals_.insert(cell.value());
	return cell.value();
}

uint64_t RefTable::resolve(uint64_t handle) const
{
	if (handle == 0)
	{
		return 0;
	}
	uint64_t object = 0;
	auto read = memory_.read(GuestVA{ handle }, &object, sizeof(object));
	return read.ok() ? object : 0;
}

RefType RefTable::typeOf(uint64_t handle) const
{
	if (resolve(handle) == 0)
	{
		return RefType::Invalid;
	}
	for (const auto &entry : threads_)
	{
		if (entry.second.slot_of.find(handle) != entry.second.slot_of.end())
		{
			return RefType::Local;
		}
	}
	if (globals_.find(handle) != globals_.end())
	{
		return RefType::Global;
	}
	if (weak_globals_.find(handle) != weak_globals_.end())
	{
		return RefType::WeakGlobal;
	}
	return RefType::Invalid;
}

bool RefTable::deleteLocal(uint64_t thread_key, uint64_t handle)
{
	if (handle == 0)
	{
		return true;
	}
	ThreadState *state = findThread(thread_key);
	if (state == nullptr)
	{
		return false;
	}
	const auto found = state->slot_of.find(handle);
	if (found == state->slot_of.end())
	{
		return false;
	}
	const size_t slot = found->second;
	if (slot >= state->handles.size() || state->handles[slot] != handle)
	{
		return false;
	}

	state->slot_of.erase(found);
	state->handles[slot] = 0;
	--state->live;
	releaseCell(handle);

	const size_t top = state->frames.empty() ? 0 : state->frames.back();
	if (slot + 1 == state->handles.size() && slot >= top)
	{
		// LIFO delete: drop the slot instead of leaving a hole. Stop at the
		// current frame mark so the mark can never point past the vector.
		state->handles.pop_back();
		while (state->handles.size() > top && state->handles.back() == 0)
		{
			state->handles.pop_back();
		}
		state->reusable_slots.erase(
			std::remove_if(state->reusable_slots.begin(), state->reusable_slots.end(),
				[state](size_t index) { return index >= state->handles.size(); }),
			state->reusable_slots.end());
	}
	else if (slot >= top)
	{
		state->reusable_slots.push_back(slot);
	}
	else
	{
		state->pending_slots.push_back(slot);
	}
	return true;
}

bool RefTable::deleteGlobal(uint64_t handle)
{
	if (handle == 0)
	{
		return true;
	}
	const auto found = globals_.find(handle);
	if (found == globals_.end())
	{
		return false;
	}
	globals_.erase(found);
	releaseCell(handle);
	return true;
}

bool RefTable::deleteWeakGlobal(uint64_t handle)
{
	if (handle == 0)
	{
		return true;
	}
	const auto found = weak_globals_.find(handle);
	if (found == weak_globals_.end())
	{
		return false;
	}
	weak_globals_.erase(found);
	releaseCell(handle);
	return true;
}

void RefTable::pushFrame(uint64_t thread_key)
{
	ThreadState &state = threads_[thread_key];
	// Everything currently reusable is below the new frame base, so it cannot
	// be handed out until this frame pops.
	state.pending_slots.insert(state.pending_slots.end(),
		state.reusable_slots.begin(), state.reusable_slots.end());
	state.reusable_slots.clear();
	state.frames.push_back(state.handles.size());
}

Result<uint64_t> RefTable::popFrame(uint64_t thread_key, uint64_t result)
{
	ThreadState *state = findThread(thread_key);
	if (state == nullptr || state->frames.empty())
	{
		return Error{ ErrorCode::InvalidArgument, "PopLocalFrame without PushLocalFrame" };
	}
	const size_t mark = state->frames.back();
	state->frames.pop_back();

	// The survivor may live inside the frame being popped: resolve it before
	// its cell is recycled.
	const uint64_t survivor = result == 0 ? 0 : resolve(result);

	for (size_t index = mark; index < state->handles.size(); ++index)
	{
		const uint64_t handle = state->handles[index];
		if (handle == 0)
		{
			continue;
		}
		releaseCell(handle);
		state->slot_of.erase(handle);
		--state->live;
	}
	state->handles.resize(mark);
	// Every reusable hole was at or above the popped frame's base.
	state->reusable_slots.clear();

	// Holes freed below the old mark can now belong to the enclosing frame.
	const size_t top = state->frames.empty() ? 0 : state->frames.back();
	std::vector<size_t> still_pending;
	still_pending.reserve(state->pending_slots.size());
	for (const size_t slot : state->pending_slots)
	{
		if (slot >= top)
		{
			state->reusable_slots.push_back(slot);
		}
		else
		{
			still_pending.push_back(slot);
		}
	}
	state->pending_slots = std::move(still_pending);

	if (survivor == 0)
	{
		return uint64_t{ 0 };
	}
	return newLocal(thread_key, survivor);
}

bool RefTable::ensureLocalCapacity(uint64_t thread_key, size_t capacity) const
{
	if (capacity > kMaxLocalRefs)
	{
		return false;
	}
	const ThreadState *state = findThread(thread_key);
	const size_t used = state == nullptr ? 0 : state->handles.size();
	return capacity <= kMaxLocalRefs - used;
}

size_t RefTable::releaseThread(uint64_t thread_key)
{
	const auto found = threads_.find(thread_key);
	if (found == threads_.end())
	{
		return 0;
	}
	size_t released = 0;
	for (const uint64_t handle : found->second.handles)
	{
		if (handle == 0)
		{
			continue;
		}
		releaseCell(handle);
		++released;
	}
	threads_.erase(found);
	return released;
}

size_t RefTable::liveLocalCount(uint64_t thread_key) const
{
	const ThreadState *state = findThread(thread_key);
	return state == nullptr ? 0 : state->live;
}

} // namespace duckemu::runtime::jni

// SPDX-License-Identifier: GPL-2.0-only
#pragma once

#include <cstddef>
#include <cstdint>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "common/error/result.hpp"

namespace duckemu::runtime
{
class RuntimeMemory;
}

namespace duckemu::runtime::jni
{

class JniArena;

// GetObjectRefType's answer. The values are part of the JNI contract
// (jobjectRefType); invalid covers deleted and unknown handles.
enum class RefType : uint32_t
{
	Invalid = 0,
	Local = 1,
	Global = 2,
	WeakGlobal = 3,
};

// JNI references. A handle is the guest address of an 8-byte cell holding the
// object address; the cell is the guest-visible value, the object table stays
// host-side. Local references belong to one guest thread (keyed by TPIDR_EL0);
// global references live until the instance is destroyed.
//
// Cells are recycled: DeleteLocalRef/DeleteGlobalRef/DeleteWeakGlobalRef zero
// the cell and return it to the free list, and a thread that detaches (or
// exits) returns every cell it still owns. The slot vector follows ART's local
// reference table: pushing a frame records the top index, popping it releases
// every entry above the mark, and holes below the top mark are reused only once
// that frame is gone so a pop can never leave a live reference behind.
//
// Callers hold the instance execution lock, so no internal locking here.
class RefTable
{
    public:
	// ART's LocalReferenceTable caps at 128 MiB of 8-byte entries. The same
	// bound keeps EnsureLocalCapacity honest without imposing a limit real
	// targets can reach.
	static constexpr size_t kMaxLocalRefs = (128u * 1024u * 1024u) / sizeof(uint64_t);

	RefTable(RuntimeMemory &memory, JniArena &arena);

	Result<uint64_t> newLocal(uint64_t thread_key, uint64_t object);
	Result<uint64_t> newGlobal(uint64_t object);
	// There is no GC in this runtime, so a weak global never clears; it
	// differs from a global only in GetObjectRefType and which delete call
	// accepts it.
	Result<uint64_t> newWeakGlobal(uint64_t object);

	// Object address behind a handle, or 0 for null/deleted/unknown handles.
	[[nodiscard]] uint64_t resolve(uint64_t handle) const;

	// Which kind of reference a live handle is (GetObjectRefType).
	[[nodiscard]] RefType typeOf(uint64_t handle) const;

	// False when |handle| is not a live local reference owned by |thread_key|;
	// the JNI layer turns that into a warning (DeleteLocalRef returns void).
	bool deleteLocal(uint64_t thread_key, uint64_t handle);
	bool deleteGlobal(uint64_t handle);
	bool deleteWeakGlobal(uint64_t handle);

	// PushLocalFrame / PopLocalFrame. Pop with a non-null |result| re-creates
	// that reference in the enclosing frame and returns the new handle; a
	// deleted or foreign survivor yields null.
	void pushFrame(uint64_t thread_key);
	Result<uint64_t> popFrame(uint64_t thread_key, uint64_t result);

	// EnsureLocalCapacity: true when |capacity| more entries fit in the
	// current frame (negative capacities are rejected by the caller).
	[[nodiscard]] bool ensureLocalCapacity(uint64_t thread_key, size_t capacity) const;

	// Thread detach/exit: releases every local reference owned by the thread,
	// zeroing its cells and forgetting its frames. Returns the count released.
	size_t releaseThread(uint64_t thread_key);

	// Live local references owned by a thread (diagnostics and tests).
	[[nodiscard]] size_t liveLocalCount(uint64_t thread_key) const;

    private:
	struct ThreadState
	{
		// Slot index -> cell address; 0 marks a hole.
		std::vector<uint64_t> handles;
		// Frame marks into |handles|; the top mark is the current frame base.
		std::vector<size_t> frames;
		// Holes at or above the top frame mark: reusable right now.
		std::vector<size_t> reusable_slots;
		// Holes below the top frame mark: reusable only after the enclosing
		// frame pops, otherwise a pop would miss a reference placed there.
		std::vector<size_t> pending_slots;
		std::unordered_map<uint64_t, size_t> slot_of;
		size_t live = 0;
	};

	[[nodiscard]] ThreadState *findThread(uint64_t thread_key);
	[[nodiscard]] const ThreadState *findThread(uint64_t thread_key) const;

	// Takes a cell from the free list (or allocates one) and writes |object|.
	Result<uint64_t> store(uint64_t object);
	void releaseCell(uint64_t handle);

	RuntimeMemory &memory_;
	JniArena &arena_;
	std::unordered_map<uint64_t, ThreadState> threads_;
	std::unordered_set<uint64_t> globals_;
	std::unordered_set<uint64_t> weak_globals_;
	std::vector<uint64_t> free_cells_;
};

} // namespace duckemu::runtime::jni

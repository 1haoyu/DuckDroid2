// SPDX-License-Identifier: GPL-2.0-only
// Unit tests for the JNI reference table: cell recycling, local frames,
// per-thread ownership, weak globals, capacity and thread teardown. No engine
// and no guest code.

#include <cstdint>
#include <limits>

#include "runtime/jni/refs/ref_table.hpp"
#include "runtime/jni/world/java_world.hpp"
#include "runtime/memory/address_space.hpp"
#include "support/test_harness.hpp"

using namespace duckemu;
using namespace duckemu::runtime;
using namespace duckemu::runtime::jni;

namespace
{

constexpr uint64_t kThreadA = 0x1000;
constexpr uint64_t kThreadB = 0x2000;
constexpr uint64_t kObject1 = 0xaaaa;
constexpr uint64_t kObject2 = 0xbbbb;
constexpr uint64_t kObject3 = 0xcccc;

uint64_t local(RefTable &refs, uint64_t thread, uint64_t object)
{
	auto handle = refs.newLocal(thread, object);
	CHECK(handle.ok());
	return handle.ok() ? handle.value() : 0;
}

uint64_t pop(RefTable &refs, uint64_t thread, uint64_t survivor)
{
	auto popped = refs.popFrame(thread, survivor);
	CHECK(popped.ok());
	return popped.ok() ? popped.value() : 0;
}

} // namespace

int main()
{
	RuntimeMemory memory;
	JniArena arena(memory);
	CHECK_RESULT(arena.initialize());
	RefTable refs(memory, arena);

	// -- Local references and ownership ------------------------------------
	const uint64_t first = local(refs, kThreadA, kObject1);
	CHECK(first != 0);
	CHECK_EQ(refs.resolve(first), kObject1);
	CHECK_EQ(static_cast<uint32_t>(refs.typeOf(first)), static_cast<uint32_t>(RefType::Local));
	CHECK_EQ(refs.liveLocalCount(kThreadA), 1);

	// A handle belongs to the thread that created it.
	CHECK(!refs.deleteLocal(kThreadB, first));
	CHECK_EQ(refs.resolve(first), kObject1);
	CHECK(refs.deleteLocal(kThreadA, first));
	CHECK_EQ(refs.resolve(first), 0);
	CHECK_EQ(static_cast<uint32_t>(refs.typeOf(first)), static_cast<uint32_t>(RefType::Invalid));
	CHECK_EQ(refs.liveLocalCount(kThreadA), 0);
	// A second delete is a no-op, not an error.
	CHECK(!refs.deleteLocal(kThreadA, first));
	// Null is always accepted by the JNI contract.
	CHECK(refs.deleteLocal(kThreadA, 0));

	// -- Cell recycling -----------------------------------------------------
	// The just-freed cell is the first one handed out again.
	const uint64_t recycled = local(refs, kThreadA, kObject2);
	CHECK_EQ(recycled, first);
	CHECK_EQ(refs.resolve(recycled), kObject2);
	CHECK(refs.deleteLocal(kThreadA, recycled));

	// -- Local frames -------------------------------------------------------
	refs.pushFrame(kThreadA);
	const uint64_t outer1 = local(refs, kThreadA, kObject1);
	const uint64_t outer2 = local(refs, kThreadA, kObject2);
	refs.pushFrame(kThreadA);
	const uint64_t inner = local(refs, kThreadA, kObject3);
	CHECK_EQ(refs.liveLocalCount(kThreadA), 3);

	const uint64_t promoted = pop(refs, kThreadA, inner);
	CHECK(promoted != 0);
	CHECK_EQ(refs.resolve(promoted), kObject3);
	// The old handle is invalid after the pop. Its cell may be the one the
	// promoted reference reuses, so only the object identity is asserted.
	CHECK_EQ(refs.resolve(outer1), kObject1);
	CHECK_EQ(refs.resolve(outer2), kObject2);
	CHECK_EQ(refs.liveLocalCount(kThreadA), 3);

	// A deleted survivor promotes nothing: PopLocalFrame must not return a
	// handle whose cell is already zero.
	refs.pushFrame(kThreadA);
	const uint64_t doomed = local(refs, kThreadA, kObject3);
	CHECK(refs.deleteLocal(kThreadA, doomed));
	CHECK_EQ(pop(refs, kThreadA, doomed), 0);

	pop(refs, kThreadA, 0);
	CHECK_EQ(refs.resolve(outer1), 0);
	CHECK_EQ(refs.resolve(outer2), 0);
	CHECK_EQ(refs.resolve(promoted), 0);
	CHECK_EQ(refs.liveLocalCount(kThreadA), 0);
	CHECK(!refs.popFrame(kThreadA, 0).ok());

	// Holes below a frame mark are deferred until that frame pops, but the
	// frame still releases everything created inside it.
	const uint64_t before = local(refs, kThreadA, kObject1);
	refs.pushFrame(kThreadA);
	CHECK(refs.deleteLocal(kThreadA, before));
	const uint64_t hole = local(refs, kThreadA, kObject2);
	const uint64_t hole2 = local(refs, kThreadA, kObject3);
	pop(refs, kThreadA, 0);
	CHECK_EQ(refs.resolve(before), 0);
	CHECK_EQ(refs.resolve(hole), 0);
	CHECK_EQ(refs.resolve(hole2), 0);
	CHECK_EQ(refs.liveLocalCount(kThreadA), 0);

	// -- EnsureLocalCapacity ------------------------------------------------
	// Capacity is counted against the table top, holes included (ART's
	// conservative accounting), so use a fresh thread for the exact bound.
	constexpr uint64_t kThreadC = 0x3000;
	CHECK(refs.ensureLocalCapacity(kThreadC, 0));
	CHECK(refs.ensureLocalCapacity(kThreadC, 64));
	CHECK(!refs.ensureLocalCapacity(kThreadC, std::numeric_limits<size_t>::max()));
	CHECK(refs.ensureLocalCapacity(kThreadC, RefTable::kMaxLocalRefs));
	const uint64_t capped = local(refs, kThreadC, kObject1);
	CHECK(!refs.ensureLocalCapacity(kThreadC, RefTable::kMaxLocalRefs));
	CHECK(refs.deleteLocal(kThreadC, capped));
	CHECK(refs.ensureLocalCapacity(kThreadC, RefTable::kMaxLocalRefs));

	// -- Global and weak global references ---------------------------------
	const uint64_t strong = refs.newGlobal(kObject1).value();
	CHECK(strong != 0);
	CHECK_EQ(refs.resolve(strong), kObject1);
	CHECK_EQ(static_cast<uint32_t>(refs.typeOf(strong)), static_cast<uint32_t>(RefType::Global));

	const uint64_t weak = refs.newWeakGlobal(kObject2).value();
	CHECK(weak != 0);
	CHECK_EQ(refs.resolve(weak), kObject2);
	CHECK_EQ(static_cast<uint32_t>(refs.typeOf(weak)),
		static_cast<uint32_t>(RefType::WeakGlobal));

	// The two kinds are not interchangeable.
	CHECK(!refs.deleteGlobal(weak));
	CHECK_EQ(static_cast<uint32_t>(refs.typeOf(weak)),
		static_cast<uint32_t>(RefType::WeakGlobal));
	CHECK(!refs.deleteWeakGlobal(strong));
	CHECK_EQ(static_cast<uint32_t>(refs.typeOf(strong)), static_cast<uint32_t>(RefType::Global));

	CHECK(refs.deleteWeakGlobal(weak));
	CHECK_EQ(refs.resolve(weak), 0);
	CHECK(!refs.deleteWeakGlobal(weak));
	CHECK(refs.deleteGlobal(strong));
	CHECK_EQ(refs.resolve(strong), 0);
	CHECK(!refs.deleteGlobal(strong));

	// A freed global cell can come back as a local reference; the handle is
	// the same guest address but no longer reports as global.
	const uint64_t revived = local(refs, kThreadA, kObject3);
	CHECK_EQ(revived, strong);
	CHECK_EQ(static_cast<uint32_t>(refs.typeOf(revived)), static_cast<uint32_t>(RefType::Local));
	CHECK(refs.deleteLocal(kThreadA, revived));

	// -- Thread teardown ----------------------------------------------------
	const uint64_t a1 = local(refs, kThreadA, kObject1);
	const uint64_t a2 = local(refs, kThreadA, kObject2);
	const uint64_t b1 = local(refs, kThreadB, kObject3);
	refs.pushFrame(kThreadA);
	const uint64_t a3 = local(refs, kThreadA, kObject3);
	CHECK_EQ(refs.liveLocalCount(kThreadA), 3);
	CHECK_EQ(refs.liveLocalCount(kThreadB), 1);

	CHECK_EQ(refs.releaseThread(kThreadA), 3);
	CHECK_EQ(refs.resolve(a1), 0);
	CHECK_EQ(refs.resolve(a2), 0);
	CHECK_EQ(refs.resolve(a3), 0);
	CHECK_EQ(refs.typeOf(a1), RefType::Invalid);
	CHECK_EQ(refs.liveLocalCount(kThreadA), 0);
	// Frames are gone with the thread.
	CHECK(!refs.popFrame(kThreadA, 0).ok());
	// Other threads are untouched.
	CHECK_EQ(refs.resolve(b1), kObject3);
	CHECK_EQ(refs.liveLocalCount(kThreadB), 1);
	CHECK_EQ(refs.releaseThread(kThreadA), 0);
	// A detached thread can attach again and reuse the released cells.
	const uint64_t fresh = local(refs, kThreadA, kObject1);
	CHECK_EQ(refs.resolve(fresh), kObject1);
	CHECK(refs.deleteLocal(kThreadA, fresh));
	CHECK(refs.deleteLocal(kThreadB, b1));

	return test::finish("ref_table_test");
}

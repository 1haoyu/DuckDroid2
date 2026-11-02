// SPDX-License-Identifier: GPL-2.0-only
#pragma once

#include <array>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include "common/error/result.hpp"
#include "common/id/ids.hpp"
#include "runtime/jni/refs/ref_table.hpp"
#include "runtime/memory/thunk/thunk_table.hpp"
#include "runtime/observer/semantic/jni_event.hpp"

namespace duckemu::runtime
{
class RuntimeMemory;
class ThunkTable;

namespace observer
{
class EventBus;
}

namespace threads
{
class ThreadScheduler;
}
} // namespace duckemu::runtime

namespace duckemu::runtime::jni
{

class JavaWorld;

// One instance-wide JNI environment: the guest-visible JNIEnv/JavaVM function
// tables, per-thread JNIEnv slots and the dispatch from table slots to the
// Java world. Every table entry is an ordinary thunk; the JNI layer adds no
// second trap mechanism.
class JniState
{
    public:
	static Result<std::unique_ptr<JniState> > create(RuntimeMemory &memory,
		ThunkTable &thunks,
		observer::EventBus *events,
		std::unique_ptr<JavaWorld> world);

	~JniState();
	JniState(const JniState &) = delete;
	JniState &operator=(const JniState &) = delete;

	[[nodiscard]] JavaWorld &world()
	{
		return *world_;
	}

	// JavaVM* value handed to JNI_OnLoad. A JavaVM is a pointer to a slot that
	// points at the invoke table, mirroring JNIEnv.
	[[nodiscard]] uint64_t javaVm() const
	{
		return vm_value_.value();
	}

	int64_t invokeEnv(uint32_t slot, HostCallArgs &args);
	int64_t invokeVm(uint32_t slot, HostCallArgs &args);

	// Thread detach/exit: releases the thread's JNIEnv slot and every local
	// reference it owns. DebugServers and the scheduler's thread-exit hook call
	// this with the thread's final TPIDR_EL0.
	void releaseThread(uint64_t thread_key);

	// Host-facing: calls a native registered through RegisterNatives with
	// (env, jclass, args...). Must not be called from a guest thread.
	Result<uint64_t> callRegisteredNative(threads::ThreadScheduler &scheduler,
		std::string_view class_descriptor,
		std::string_view name,
		std::string_view signature,
		const std::array<uint64_t, 8> &args);
	Result<GuestVA> lookupRegisteredNative(std::string_view class_descriptor,
		std::string_view name,
		std::string_view signature) const;
	// Decodes a jstring handle (object results of registered natives).
	Result<std::string> stringUtf8(uint64_t handle) const;
	// Object address behind a live reference (local or global). Host callers
	// use it to inspect an object returned by callRegisteredNative.
	Result<uint64_t> resolveHandle(uint64_t handle) const;

    private:
	JniState(RuntimeMemory &memory,
		ThunkTable &thunks,
		observer::EventBus *events,
		std::unique_ptr<JavaWorld> world);

	Result<void> createTables();
	Result<uint64_t> ensureEnvSlot(uint64_t thread_key);
	Result<uint64_t> newLocal(uint64_t thread_key, uint64_t object);
	Result<std::string> readUtf8(uint64_t address);
	int64_t callMethod(uint32_t slot, HostCallArgs &args);
	int64_t accessField(uint32_t slot, HostCallArgs &args);
	int64_t accessArray(uint32_t slot, HostCallArgs &args);
	int64_t newObject(uint32_t slot, HostCallArgs &args);
	void publishMissing(observer::JniEventKind kind,
		std::string class_descriptor,
		std::string name,
		std::string signature,
		uint32_t slot,
		uint32_t tid);
	void publishUnsupported(uint32_t slot, uint32_t tid);

	RuntimeMemory &memory_;
	ThunkTable &thunks_;
	observer::EventBus *events_;
	std::unique_ptr<JavaWorld> world_;
	RefTable refs_;

	GuestVA env_table_;
	GuestVA vm_table_;
	GuestVA vm_value_;
	std::unordered_map<uint64_t, uint64_t> env_slots_;
	// Cells from detached threads, reused by the next ensureEnvSlot.
	std::vector<uint64_t> free_env_slots_;
};

} // namespace duckemu::runtime::jni

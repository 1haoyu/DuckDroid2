// SPDX-License-Identifier: GPL-2.0-only
#pragma once

#include <array>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <thread>

#include "common/error/result.hpp"
#include "common/id/ids.hpp"
#include "runtime/observer/diagnostic/diagnostic_event.hpp"
#include "runtime/observer/diagnostic/ring_buffer.hpp"
#include "runtime/observer/semantic/svc_event.hpp"

namespace duckemu::runtime
{

class UnicornEngine;

namespace svc
{
class SvcDispatcher;
}

namespace threads
{

class PendingSyscall;

enum class ThreadState : uint8_t
{
	Created = 0,
	// Main thread between callFunction calls.
	Idle,
	Runnable,
	Executing,
	Blocked,
	Exited,
};

constexpr const char *threadStateName(ThreadState state) noexcept
{
	switch (state)
	{
	case ThreadState::Created:
		return "created";
	case ThreadState::Idle:
		return "idle";
	case ThreadState::Runnable:
		return "runnable";
	case ThreadState::Executing:
		return "executing";
	case ThreadState::Blocked:
		return "blocked";
	case ThreadState::Exited:
		return "exited";
	}
	return "?";
}

struct CallResult
{
	uint64_t return_value = 0;
	std::optional<int32_t> exit_code;
};

struct CallRequest
{
	bool requested = false;
	GuestVA entry;
	std::array<uint64_t, 8> args{};
};

// One guest thread of an instance: a host thread plus its own engine, TLS
// pointer and pending blocking syscall. The address space and everything else
// process-wide lives in RuntimeInstance.
struct RuntimeThread
{
	uint32_t tid = 0;
	uint32_t parent_tid = 0;
	// Only recorded; the guest's libc owns the TLS block (M3 decision: adopt).
	uint64_t tls_tp = 0;
	uint64_t clear_child_tid = 0;
	bool is_main = false;
	ThreadState state = ThreadState::Created;

	std::thread host;
	std::mutex mutex;
	std::condition_variable cv;

	std::unique_ptr<UnicornEngine> engine;
	std::unique_ptr<svc::SvcDispatcher> dispatcher;
	GuestVA next_pc;

	// One blocking syscall at a time (decision 02 §3.4). The event travels with
	// the pending op so it is published when the syscall actually completes.
	std::unique_ptr<PendingSyscall> pending;
	std::optional<observer::SvcEvent> pending_event;
	int64_t pending_result = 0;
	bool pending_completed = false;

	// Timed blocking syscalls (futex with a timeout, poll/epoll waits). The
	// deadline is host steady time; `deadline_expired` is set by the wait loop
	// and consumed once the thread holds the execution lock again, so the
	// completion callback never touches guest memory concurrently.
	bool has_deadline = false;
	bool deadline_expired = false;
	std::chrono::steady_clock::time_point deadline;
	// The relative timeout that armed the deadline. On expiry an injected
	// clock moves forward by exactly this much, so the guest observes the
	// timeout it asked for instead of a frozen clock.
	uint64_t pending_timeout_us = 0;
	// Non-zero while this thread sits in the futex wait queue.
	uint64_t futex_key = 0;

	// Set by sched_yield(2) inside the SVC hook; the host loop consumes it
	// after releasing the execution lock.
	bool yield_requested = false;
	// >0 while a host stub runs a nested guest call on this thread. A yield
	// cannot leave the engine there: the nested uc_emu_start is owned by the
	// host stub, not by the scheduler loop.
	int nested_call_depth = 0;

	bool exit_requested = false;
	int32_t exit_code = 0;

	// Main-thread call machinery. The request is posted by callFunction and
	// consumed by the main host thread; call_done guards the reply.
	CallRequest request;
	bool call_active = false;
	bool call_done = false;
	CallResult call_result;
	std::optional<Error> call_error;

	// One SPSC ring per thread: the producer is this thread's memory hooks.
	std::unique_ptr<observer::RingBuffer<observer::DiagnosticEvent> > diagnostics;
};

} // namespace threads
} // namespace duckemu::runtime

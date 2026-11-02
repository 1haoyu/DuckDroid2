// SPDX-License-Identifier: GPL-2.0-only
// Event loop surface: eventfd, timerfd, poll/ppoll, epoll and pselect6.
//
// Readiness is evaluated against the descriptor table at the moment of the
// call. A wait that finds nothing ready parks the thread through
// ThreadSystem::parkThread; a deadline or any later guest read/write wakes it
// (VirtualFileSystem::addActivityWaiter) and the pending syscall re-evaluates.
// A wake without progress is reported as spurious (nullopt) and the thread
// keeps sleeping.

#include <algorithm>
#include <array>
#include <cstring>
#include <memory>
#include <optional>
#include <vector>

#include "runtime/memory/address_space.hpp"
#include "runtime/svc/handler.hpp"
#include "runtime/svc/syscall_numbers.hpp"
#include "runtime/threads/pending_syscall.hpp"
#include "runtime/threads/runtime_thread.hpp"
#include "runtime/threads/thread_system.hpp"
#include "runtime/vfs/event_file.hpp"
#include "runtime/vfs/virtual_file_system.hpp"

namespace duckemu::runtime::svc
{
namespace
{

using threads::WakeReason;

constexpr uint32_t kPollNval = 0x020;
constexpr uint32_t kPollInteresting = vfs::kPollIn | vfs::kPollOut | vfs::kPollErr | vfs::kPollHup;
constexpr size_t kPollFdSize = 8; // { i32 fd; i16 events; i16 revents; }
constexpr size_t kEpollEventSize = 12; // packed { u32 events; u64 data; }
constexpr size_t kFdSetSize = 128; // 1024 bits
constexpr uint64_t kMaxDescriptors = 1024;

constexpr uint64_t kEfdSemaphore = 1;
constexpr uint64_t kEfdNonblock = 0x800;
constexpr uint64_t kEfdCloexec = 0x80000;
constexpr uint64_t kTfdTimerAbstime = 1;

int64_t toErrno(const Error &error)
{
	switch (error.code)
	{
	case ErrorCode::NotFound:
		return kError(kEnoent);
	case ErrorCode::PermissionDenied:
		return kError(kEacces);
	case ErrorCode::InvalidArgument:
		return kError(kEinval);
	case ErrorCode::BadFileDescriptor:
		return kError(kEbadf);
	case ErrorCode::WouldBlock:
		return kError(kEagain);
	case ErrorCode::NotSeekable:
		return kError(kEspipe);
	case ErrorCode::Unsupported:
		return kError(kErofs);
	case ErrorCode::OutOfMemory:
		return kError(kEnomem);
	default:
		return kError(kEio);
	}
}

uint32_t readiness(vfs::VirtualFileSystem &vfs, uint64_t fd)
{
	vfs::File *file = vfs.find(fd);
	return file == nullptr ? 0 : file->pollEvents();
}

bool descriptorOpen(vfs::VirtualFileSystem &vfs, uint64_t fd)
{
	return vfs.find(fd) != nullptr;
}

bool fdSetTest(const std::array<uint8_t, kFdSetSize> &bits, int fd)
{
	return ((bits[static_cast<size_t>(fd) / 8] >> (fd % 8)) & 1U) != 0;
}

void fdSetPut(std::array<uint8_t, kFdSetSize> &bits, int fd)
{
	bits[static_cast<size_t>(fd) / 8] |= static_cast<uint8_t>(1U << (fd % 8));
}

// Keeps a VirtualFileSystem wake registration alive exactly as long as the
// pending syscall that owns it.
struct ActivityRegistration
{
	vfs::VirtualFileSystem &vfs;
	uint64_t id;

	~ActivityRegistration()
	{
		vfs.removeActivityWaiter(id);
	}
};

std::shared_ptr<ActivityRegistration> registerWake(SyscallContext &ctx)
{
	threads::RuntimeThread *thread = &ctx.thread;
	threads::ThreadSystem *threads = &ctx.threads;
	const uint64_t id = ctx.vfs.addActivityWaiter([thread, threads] {
		(void)threads->wakeThread(*thread, WakeReason::PollWoke);
	});
	return std::make_shared<ActivityRegistration>(ActivityRegistration{ ctx.vfs, id });
}

// Reads the relative timeout of ppoll/pselect6. `infinite` is set when the
// caller passed a null pointer; returns a negative errno on a bad timespec.
int64_t readTimespecTimeout(RuntimeMemory &memory, uint64_t address, bool &infinite, uint64_t &micros)
{
	infinite = address == 0;
	if (infinite)
	{
		micros = 0;
		return 0;
	}
	int64_t seconds = 0;
	int64_t nanoseconds = 0;
	if (!memory.read(GuestVA{ address }, &seconds, sizeof(seconds)).ok() ||
	    !memory.read(GuestVA{ address + 8 }, &nanoseconds, sizeof(nanoseconds)).ok())
	{
		return kError(kEfault);
	}
	if (seconds < 0 || nanoseconds < 0 || nanoseconds >= 1000000000LL)
	{
		return kError(kEinval);
	}
	micros = static_cast<uint64_t>(seconds) * 1000000ULL +
		 static_cast<uint64_t>((nanoseconds + 999) / 1000);
	return 0;
}

// Caps a wait deadline with the nearest watched timerfd. Without this a
// timerfd only becomes ready when some other read/write wakes the waiter, so
// poll(timerfd) would sleep until the caller's own timeout.
uint64_t capWithTimer(vfs::VirtualFileSystem &vfs, uint64_t fd, uint64_t timeout_us)
{
	vfs::File *file = vfs.find(fd);
	if (file == nullptr || file->kind() != vfs::FileKind::Timer)
	{
		return timeout_us;
	}
	const uint64_t remaining = static_cast<vfs::TimerFile *>(file)->remainingNs();
	if (remaining == 0)
	{
		return timeout_us;
	}
	const uint64_t candidate = std::max<uint64_t>(1, (remaining + 999) / 1000);
	return timeout_us == 0 ? candidate : std::min(timeout_us, candidate);
}

// ---------------------------------------------------------------------------
// poll/ppoll
// ---------------------------------------------------------------------------

class PollWait final : public threads::PendingSyscall
{
    public:
	PollWait(RuntimeMemory &memory, vfs::VirtualFileSystem &vfs, GuestVA fds, uint64_t count)
		: memory_(memory)
		, vfs_(vfs)
		, fds_(fds)
		, count_(count)
	{
	}

	void attach(std::shared_ptr<ActivityRegistration> registration)
	{
		registration_ = std::move(registration);
	}

	int64_t evaluate()
	{
		int64_t ready = 0;
		for (uint64_t i = 0; i < count_; ++i)
		{
			const GuestVA slot = GuestVA{ fds_.value() + i * kPollFdSize };
			int32_t fd = 0;
			uint16_t events = 0;
			if (!memory_.read(slot, &fd, sizeof(fd)).ok() ||
			    !memory_.read(GuestVA{ slot.value() + 4 }, &events, sizeof(events)).ok())
			{
				return kError(kEfault);
			}
			uint16_t revents = 0;
			if (fd >= 0 && !descriptorOpen(vfs_, static_cast<uint64_t>(fd)))
			{
				revents = kPollNval;
			}
			else if (fd >= 0)
			{
				const uint32_t mask = readiness(vfs_, static_cast<uint64_t>(fd));
				revents = static_cast<uint16_t>(mask & (events | vfs::kPollErr | vfs::kPollHup) &
								kPollInteresting);
			}
			if (!memory_.write(GuestVA{ slot.value() + 6 }, &revents, sizeof(revents)).ok())
			{
				return kError(kEfault);
			}
			if (revents != 0)
			{
				++ready;
			}
		}
		return ready;
	}

	void clearRevents()
	{
		for (uint64_t i = 0; i < count_; ++i)
		{
			const uint16_t zero = 0;
			(void)memory_.write(GuestVA{ fds_.value() + i * kPollFdSize + 6 }, &zero, sizeof(zero));
		}
	}

	std::optional<int64_t> complete(WakeReason reason) override
	{
		if (reason == WakeReason::ThreadExited)
		{
			return std::nullopt;
		}
		if (reason == WakeReason::TimerExpired)
		{
			// The deadline may be a watched timerfd firing rather than the
			// caller's own timeout.
			const int64_t ready = evaluate();
			if (ready != 0)
			{
				return ready;
			}
			clearRevents();
			return int64_t{ 0 };
		}
		const int64_t ready = evaluate();
		if (ready < 0)
		{
			return ready;
		}
		if (ready == 0)
		{
			return std::nullopt; // spurious: nothing became ready
		}
		return ready;
	}

    private:
	RuntimeMemory &memory_;
	vfs::VirtualFileSystem &vfs_;
	GuestVA fds_;
	uint64_t count_;
	std::shared_ptr<ActivityRegistration> registration_;
};

// ---------------------------------------------------------------------------
// epoll
// ---------------------------------------------------------------------------

class EpollWait final : public threads::PendingSyscall
{
    public:
	EpollWait(RuntimeMemory &memory,
		vfs::VirtualFileSystem &vfs,
		vfs::EpollFile &epoll,
		GuestVA events,
		uint64_t max_events)
		: memory_(memory)
		, vfs_(vfs)
		, epoll_(epoll)
		, events_(events)
		, max_events_(max_events)
	{
	}

	void attach(std::shared_ptr<ActivityRegistration> registration)
	{
		registration_ = std::move(registration);
	}

	int64_t evaluate()
	{
		int64_t ready = 0;
		for (const vfs::EpollRegistration &entry : epoll_.registrations())
		{
			if (static_cast<uint64_t>(ready) >= max_events_)
			{
				break;
			}
			const uint32_t mask = readiness(vfs_, entry.fd) &
					      (entry.events | vfs::kPollErr | vfs::kPollHup) & kPollInteresting;
			if (mask == 0)
			{
				continue;
			}
			// struct epoll_event is packed: u32 events at +0, u64 data at +4.
			const GuestVA slot = GuestVA{ events_.value() + static_cast<uint64_t>(ready) * kEpollEventSize };
			if (!memory_.write(slot, &mask, sizeof(mask)).ok() ||
			    !memory_.write(GuestVA{ slot.value() + 4 }, &entry.data, sizeof(entry.data)).ok())
			{
				return kError(kEfault);
			}
			++ready;
		}
		return ready;
	}

	std::optional<int64_t> complete(WakeReason reason) override
	{
		if (reason == WakeReason::ThreadExited)
		{
			return std::nullopt;
		}
		if (reason == WakeReason::TimerExpired)
		{
			return evaluate(); // a watched timerfd may have fired
		}
		const int64_t ready = evaluate();
		if (ready < 0)
		{
			return ready;
		}
		if (ready == 0)
		{
			return std::nullopt;
		}
		return ready;
	}

    private:
	RuntimeMemory &memory_;
	vfs::VirtualFileSystem &vfs_;
	vfs::EpollFile &epoll_;
	GuestVA events_;
	uint64_t max_events_;
	std::shared_ptr<ActivityRegistration> registration_;
};

// ---------------------------------------------------------------------------
// pselect6
// ---------------------------------------------------------------------------

class SelectWait final : public threads::PendingSyscall
{
    public:
	SelectWait(RuntimeMemory &memory,
		vfs::VirtualFileSystem &vfs,
		uint64_t nfds,
		uint64_t read_set,
		uint64_t write_set,
		uint64_t except_set)
		: memory_(memory)
		, vfs_(vfs)
		, nfds_(nfds)
		, read_set_(read_set)
		, write_set_(write_set)
		, except_set_(except_set)
	{
		// Snapshot the requested sets: only bits the caller asked about are
		// reported back, the rest of the set stays clear.
		readRequested_ = load(read_set_);
		writeRequested_ = load(write_set_);
		exceptRequested_ = load(except_set_);
	}

	void attach(std::shared_ptr<ActivityRegistration> registration)
	{
		registration_ = std::move(registration);
	}

	int64_t evaluate()
	{
		std::array<uint8_t, kFdSetSize> read_ready{};
		std::array<uint8_t, kFdSetSize> write_ready{};
		std::array<uint8_t, kFdSetSize> except_ready{};
		int64_t ready = 0;
		for (uint64_t fd = 0; fd < nfds_; ++fd)
		{
			const int index = static_cast<int>(fd);
			bool hit = false;
			if (read_set_.value() != 0 && fdSetTest(readRequested_, index))
			{
				if ((readiness(vfs_, fd) & (vfs::kPollIn | vfs::kPollHup)) != 0)
				{
					fdSetPut(read_ready, index);
					hit = true;
				}
			}
			if (write_set_.value() != 0 && fdSetTest(writeRequested_, index))
			{
				if ((readiness(vfs_, fd) & vfs::kPollOut) != 0)
				{
					fdSetPut(write_ready, index);
					hit = true;
				}
			}
			if (except_set_.value() != 0 && fdSetTest(exceptRequested_, index))
			{
				if ((readiness(vfs_, fd) & vfs::kPollErr) != 0)
				{
					fdSetPut(except_ready, index);
					hit = true;
				}
			}
			if (hit)
			{
				++ready;
			}
		}
		if (ready == 0)
		{
			return 0;
		}
		if (!store(read_set_, read_ready) || !store(write_set_, write_ready) ||
		    !store(except_set_, except_ready))
		{
			return kError(kEfault);
		}
		return ready;
	}

	std::optional<int64_t> complete(WakeReason reason) override
	{
		if (reason == WakeReason::ThreadExited)
		{
			return std::nullopt;
		}
		if (reason == WakeReason::TimerExpired)
		{
			if (!store(read_set_, {}) || !store(write_set_, {}) || !store(except_set_, {}))
			{
				return kError(kEfault);
			}
			return int64_t{ 0 };
		}
		const int64_t ready = evaluate();
		if (ready < 0)
		{
			return ready;
		}
		if (ready == 0)
		{
			return std::nullopt;
		}
		return ready;
	}

    private:
	std::array<uint8_t, kFdSetSize> load(GuestVA address) const
	{
		std::array<uint8_t, kFdSetSize> bits{};
		if (address.value() != 0)
		{
			(void)memory_.read(address, bits.data(), bits.size());
		}
		return bits;
	}

	bool store(GuestVA address, const std::array<uint8_t, kFdSetSize> &bits) const
	{
		if (address.value() == 0)
		{
			return true;
		}
		return memory_.write(address, bits.data(), bits.size()).ok();
	}

	RuntimeMemory &memory_;
	vfs::VirtualFileSystem &vfs_;
	uint64_t nfds_ = 0;
	GuestVA read_set_;
	GuestVA write_set_;
	GuestVA except_set_;
	std::array<uint8_t, kFdSetSize> readRequested_{};
	std::array<uint8_t, kFdSetSize> writeRequested_{};
	std::array<uint8_t, kFdSetSize> exceptRequested_{};
	std::shared_ptr<ActivityRegistration> registration_;
};

// ---------------------------------------------------------------------------
// Syscalls
// ---------------------------------------------------------------------------

int64_t sysEventfd2(SyscallContext &ctx)
{
	const uint64_t flags = ctx.args[1];
	if ((flags & ~(kEfdSemaphore | kEfdNonblock | kEfdCloexec)) != 0)
	{
		return kError(kEinval);
	}
	auto file = std::make_unique<vfs::EventFile>(static_cast<uint32_t>(ctx.args[0]),
		(flags & kEfdSemaphore) != 0);
	file->setOpenFlags(2); // O_RDWR
	auto added = ctx.vfs.add(std::move(file));
	return added.ok() ? static_cast<int64_t>(added.value()) : kError(kEnomem);
}

int64_t sysTimerfdCreate(SyscallContext &ctx)
{
	const int64_t clock_id = static_cast<int64_t>(ctx.args[0]);
	const uint64_t flags = ctx.args[1];
	constexpr uint64_t kTfdNonblock = 0x800;
	constexpr uint64_t kTfdCloexec = 0x80000;
	// CLOCK_REALTIME, CLOCK_MONOTONIC and CLOCK_BOOTTIME are accepted; the
	// instance runs on the host steady clock either way.
	if (clock_id != 0 && clock_id != 1 && clock_id != 7)
	{
		return kError(kEinval);
	}
	if ((flags & ~(kTfdNonblock | kTfdCloexec)) != 0)
	{
		return kError(kEinval);
	}
	auto file = std::make_unique<vfs::TimerFile>();
	file->setOpenFlags(0); // O_RDONLY
	auto added = ctx.vfs.add(std::move(file));
	return added.ok() ? static_cast<int64_t>(added.value()) : kError(kEnomem);
}

vfs::TimerFile *timerFile(vfs::VirtualFileSystem &vfs, uint64_t fd)
{
	vfs::File *file = vfs.find(fd);
	if (file == nullptr || file->kind() != vfs::FileKind::Timer)
	{
		return nullptr;
	}
	return static_cast<vfs::TimerFile *>(file);
}

// struct itimerspec: interval at +0, value at +16, each { i64 sec; i64 nsec; }.
int64_t writeItimerspec(RuntimeMemory &memory, uint64_t address, vfs::TimerFile &timer)
{
	uint64_t value_seconds = 0;
	uint64_t value_nanoseconds = 0;
	uint64_t interval_seconds = 0;
	uint64_t interval_nanoseconds = 0;
	timer.getTimer(value_seconds, value_nanoseconds, interval_seconds, interval_nanoseconds);
	const uint64_t fields[4] = { interval_seconds,
		interval_nanoseconds,
		value_seconds,
		value_nanoseconds };
	if (!memory.write(GuestVA{ address }, fields, sizeof(fields)).ok())
	{
		return kError(kEfault);
	}
	return 0;
}

int64_t sysTimerfdSettime(SyscallContext &ctx)
{
	vfs::TimerFile *timer = timerFile(ctx.vfs, ctx.args[0]);
	if (timer == nullptr)
	{
		return kError(kEbadf);
	}
	const uint64_t flags = ctx.args[1];
	if ((flags & ~kTfdTimerAbstime) != 0)
	{
		return kError(kEinval);
	}
	uint64_t fields[4] = {};
	if (!ctx.memory.read(GuestVA{ ctx.args[2] }, fields, sizeof(fields)).ok())
	{
		return kError(kEfault);
	}
	// fields = { interval_sec, interval_nsec, value_sec, value_nsec }.
	auto set = timer->setTimer(fields[2], fields[3], fields[0], fields[1], (flags & kTfdTimerAbstime) != 0);
	if (!set.ok())
	{
		return toErrno(set.error());
	}
	if (ctx.args[3] != 0)
	{
		return writeItimerspec(ctx.memory, ctx.args[3], *timer);
	}
	return 0;
}

int64_t sysTimerfdGettime(SyscallContext &ctx)
{
	vfs::TimerFile *timer = timerFile(ctx.vfs, ctx.args[0]);
	if (timer == nullptr)
	{
		return kError(kEbadf);
	}
	return writeItimerspec(ctx.memory, ctx.args[1], *timer);
}

int64_t sysPipe2(SyscallContext &ctx)
{
	constexpr uint64_t kOCloexec = 0x80000;
	constexpr uint64_t kONonblock = 0x800;
	if ((ctx.args[1] & ~(kOCloexec | kONonblock)) != 0)
	{
		return kError(kEinval);
	}
	if (ctx.args[0] == 0)
	{
		return kError(kEfault);
	}
	auto buffer = std::make_shared<vfs::PipeBuffer>();
	auto read_file = std::make_unique<vfs::PipeFile>(buffer, true);
	read_file->setOpenFlags(0); // O_RDONLY
	auto read_end = ctx.vfs.add(std::move(read_file));
	if (!read_end.ok())
	{
		return kError(kEnomem);
	}
	auto write_file = std::make_unique<vfs::PipeFile>(buffer, false);
	write_file->setOpenFlags(1); // O_WRONLY
	auto write_end = ctx.vfs.add(std::move(write_file));
	if (!write_end.ok())
	{
		(void)ctx.vfs.close(read_end.value());
		return kError(kEnomem);
	}
	const int32_t fds[2] = { static_cast<int32_t>(read_end.value()),
		static_cast<int32_t>(write_end.value()) };
	if (!ctx.memory.write(GuestVA{ ctx.args[0] }, fds, sizeof(fds)).ok())
	{
		(void)ctx.vfs.close(read_end.value());
		(void)ctx.vfs.close(write_end.value());
		return kError(kEfault);
	}
	return 0;
}

int64_t sysPpoll(SyscallContext &ctx)
{
	const uint64_t nfds = ctx.args[1];
	if (nfds > kMaxDescriptors)
	{
		return kError(kEinval);
	}
	bool infinite = false;
	uint64_t micros = 0;
	const int64_t timeout_error = readTimespecTimeout(ctx.memory, ctx.args[2], infinite, micros);
	if (timeout_error != 0)
	{
		return timeout_error;
	}

	auto op = std::make_unique<PollWait>(ctx.memory, ctx.vfs, GuestVA{ ctx.args[0] }, nfds);
	const int64_t ready = op->evaluate();
	if (ready < 0)
	{
		return ready;
	}
	if (ready > 0)
	{
		return ready;
	}
	if (!infinite && micros == 0)
	{
		return 0;
	}

	uint64_t park_us = infinite ? 0 : (micros == 0 ? 1 : micros);
	for (uint64_t i = 0; i < nfds; ++i)
	{
		int32_t fd = -1;
		if (!ctx.memory
			     .read(GuestVA{ ctx.args[0] + i * kPollFdSize }, &fd, sizeof(fd))
			     .ok())
		{
			return kError(kEfault);
		}
		if (fd >= 0)
		{
			park_us = capWithTimer(ctx.vfs, static_cast<uint64_t>(fd), park_us);
		}
	}
	op->attach(registerWake(ctx));
	const int64_t parked = ctx.threads.parkThread(ctx.thread, std::move(op), park_us);
	return parked < 0 ? parked : 0;
}

int64_t sysPselect6(SyscallContext &ctx)
{
	const uint64_t nfds = ctx.args[0];
	if (nfds > kMaxDescriptors)
	{
		return kError(kEinval);
	}
	bool infinite = false;
	uint64_t micros = 0;
	const int64_t timeout_error = readTimespecTimeout(ctx.memory, ctx.args[4], infinite, micros);
	if (timeout_error != 0)
	{
		return timeout_error;
	}

	auto op = std::make_unique<SelectWait>(ctx.memory,
		ctx.vfs,
		nfds,
		ctx.args[1],
		ctx.args[2],
		ctx.args[3]);
	const int64_t ready = op->evaluate();
	if (ready < 0)
	{
		return ready;
	}
	if (ready > 0 || (!infinite && micros == 0))
	{
		return ready;
	}

	uint64_t park_us = infinite ? 0 : (micros == 0 ? 1 : micros);
	for (uint64_t fd = 0; fd < nfds; ++fd)
	{
		park_us = capWithTimer(ctx.vfs, fd, park_us);
	}
	op->attach(registerWake(ctx));
	const int64_t parked = ctx.threads.parkThread(ctx.thread, std::move(op), park_us);
	return parked < 0 ? parked : 0;
}

vfs::EpollFile *epollFile(vfs::VirtualFileSystem &vfs, uint64_t fd)
{
	vfs::File *file = vfs.find(fd);
	if (file == nullptr || file->kind() != vfs::FileKind::Epoll)
	{
		return nullptr;
	}
	return static_cast<vfs::EpollFile *>(file);
}

int64_t sysEpollCreate1(SyscallContext &ctx)
{
	constexpr uint64_t kEpollCloexec = 0x80000;
	if ((ctx.args[0] & ~kEpollCloexec) != 0)
	{
		return kError(kEinval);
	}
	auto file = std::make_unique<vfs::EpollFile>();
	file->setOpenFlags(0);
	auto added = ctx.vfs.add(std::move(file));
	return added.ok() ? static_cast<int64_t>(added.value()) : kError(kEnomem);
}

int64_t sysEpollCtl(SyscallContext &ctx)
{
	vfs::EpollFile *epoll = epollFile(ctx.vfs, ctx.args[0]);
	if (epoll == nullptr)
	{
		return kError(kEbadf);
	}
	const int64_t op = static_cast<int64_t>(ctx.args[1]);
	const uint64_t fd = ctx.args[2];
	if (!descriptorOpen(ctx.vfs, fd) || fd == ctx.args[0])
	{
		return kError(kEbadf);
	}
	uint32_t events = 0;
	uint64_t data = 0;
	if (ctx.args[3] != 0)
	{
		// struct epoll_event is packed: u32 events, then u64 data.
		if (!ctx.memory.read(GuestVA{ ctx.args[3] }, &events, sizeof(events)).ok() ||
		    !ctx.memory.read(GuestVA{ ctx.args[3] + 4 }, &data, sizeof(data)).ok())
		{
			return kError(kEfault);
		}
	}
	if (op < 1 || op > 3)
	{
		return kError(kEinval);
	}
	switch (epoll->control(static_cast<vfs::EpollFile::ControlOp>(op), fd, events, data))
	{
	case vfs::EpollFile::ControlResult::Ok:
		return 0;
	case vfs::EpollFile::ControlResult::Exists:
		return kError(kEexist);
	case vfs::EpollFile::ControlResult::Missing:
		return kError(kEnoent);
	}
	return kError(kEinval);
}

int64_t sysEpollPwait(SyscallContext &ctx)
{
	vfs::EpollFile *epoll = epollFile(ctx.vfs, ctx.args[0]);
	if (epoll == nullptr)
	{
		return kError(kEbadf);
	}
	const uint64_t max_events = ctx.args[2];
	if (max_events == 0 || max_events > kMaxDescriptors)
	{
		return kError(kEinval);
	}
	const int64_t timeout_ms = static_cast<int32_t>(ctx.args[3]);

	auto op = std::make_unique<EpollWait>(ctx.memory,
		ctx.vfs,
		*epoll,
		GuestVA{ ctx.args[1] },
		max_events);
	const int64_t ready = op->evaluate();
	if (ready < 0)
	{
		return ready;
	}
	if (ready > 0 || timeout_ms == 0)
	{
		return ready;
	}

	const bool infinite = timeout_ms < 0;
	uint64_t park_us = infinite ? 0 :
				   std::max<uint64_t>(1, static_cast<uint64_t>(timeout_ms) * 1000);
	for (const vfs::EpollRegistration &entry : epoll->registrations())
	{
		park_us = capWithTimer(ctx.vfs, entry.fd, park_us);
	}
	op->attach(registerWake(ctx));
	const int64_t parked = ctx.threads.parkThread(ctx.thread, std::move(op), park_us);
	return parked < 0 ? parked : 0;
}

} // namespace

std::optional<int64_t> handleEventSyscall(SyscallContext &ctx, uint32_t number)
{
	switch (number)
	{
	case kSysEventfd2:
		return sysEventfd2(ctx);
	case kSysTimerfdCreate:
		return sysTimerfdCreate(ctx);
	case kSysTimerfdSettime:
		return sysTimerfdSettime(ctx);
	case kSysTimerfdGettime:
		return sysTimerfdGettime(ctx);
	case kSysPipe2:
		return sysPipe2(ctx);
	case kSysPpoll:
		return sysPpoll(ctx);
	case kSysPselect6:
		return sysPselect6(ctx);
	case kSysEpollCreate1:
		return sysEpollCreate1(ctx);
	case kSysEpollCtl:
		return sysEpollCtl(ctx);
	case kSysEpollPwait:
		return sysEpollPwait(ctx);
	default:
		return std::nullopt;
	}
}

} // namespace duckemu::runtime::svc

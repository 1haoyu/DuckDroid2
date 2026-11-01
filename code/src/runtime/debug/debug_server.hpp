// SPDX-License-Identifier: GPL-2.0-only
#pragma once

#include <atomic>
#include <cstdint>
#include <cstdio>
#include <map>
#include <memory>
#include <string>

#include "common/error/result.hpp"
#include "runtime/debug/debug_target.hpp"

namespace duckemu::runtime
{

namespace threads
{
struct RuntimeThread;
}

namespace debug
{

// One GDB RSP session over one RuntimeInstance. Model A ("debugger drives"):
// the runner installs an entry stop, then callFunction runs the target under
// the client's control. The server never runs on its own thread; it is served
// by whichever guest host thread is parked, while that thread holds the
// instance execution lock.
class DebugServer
{
    public:
	enum class Action
	{
		Continue,
		Step,
		Detach,
	};

	static Result<std::unique_ptr<DebugServer> > create(Target &target, const Options &options);
	~DebugServer();

	DebugServer(const DebugServer &) = delete;
	DebugServer &operator=(const DebugServer &) = delete;
	DebugServer(DebugServer &&) = delete;
	DebugServer &operator=(DebugServer &&) = delete;

	// Blocks until the client resumes or detaches. Must be called on the
	// parked guest host thread, with the execution lock held.
	Action serve(threads::RuntimeThread &thread);

	// Scheduler side. `consumeStop` is called after engine->run returns and
	// reports whether this return must be parked for the debugger.
	[[nodiscard]] bool consumeStop(uint32_t tid);
	// Instruction budget for the next run: 1 after a single-step, else 0.
	[[nodiscard]] size_t nextRunCount() const;

	// Installs the one-shot stop at the target's entry (model A).
	void armEntry(uint64_t entry);
	// Called from the pre-instruction hook (emulating thread).
	bool onStopHook(uint32_t tid, uint64_t address);

	[[nodiscard]] bool attached() const noexcept
	{
		return client_ >= 0;
	}

	[[nodiscard]] uint16_t port() const noexcept
	{
		return options_.port;
	}

	void close();

    private:
	DebugServer(Target &target, const Options &options);

	enum class Command
	{
		None,
		Resume,
		Step,
		Detach,
	};

	// Socket and RSP framing.
	bool listen();
	bool acceptClient();
	bool receivePacket(std::string &payload);
	void sendPacket(const std::string &payload);
	void sendRaw(const std::string &text);
	static std::string escapePayload(const std::string &payload);
	static std::string unescapePayload(const std::string &raw);
	void logPacket(const char *direction, const std::string &payload);
	void log(const char *format, ...) __attribute__((format(printf, 2, 3)));

	// Packet dispatch. `stopped` is true when this serve() is already at a
	// stop (the client is waiting for a stop reply after c/s).
	std::string dispatch(const std::string &packet, Command &command);
	std::string stopReply(bool breakpoint_hit) const;
	std::string handleXfer(const std::string &packet) const;

	// Registers of the parked thread.
	bool readRegister(uint64_t index, uint64_t &value) const;
	bool writeRegister(uint64_t index, uint64_t value);
	std::string readAllRegisters() const;
	bool writeAllRegisters(const std::string &hex);

	Result<void> readMemory(uint64_t address, std::string &out, uint64_t size);
	Result<void> writeMemory(uint64_t address, const std::string &data);

	void installBreakpoint(uint64_t address);
	void removeBreakpoint(uint64_t address);

	Target &target_;
	Options options_;
	threads::RuntimeThread *current_ = nullptr;

	// Packet traffic goes here, not to the console: a debugging session is
	// thousands of packets and would drown the runner's own output.
	std::string log_path_;
	std::FILE *log_file_ = nullptr;

	int listener_ = -1;
	int client_ = -1;
	bool ack_ = true;
	bool no_ack_ = false;
	bool detach_requested_ = false;
	bool pending_stop_reply_ = false;
	bool step_pending_ = false;
	bool last_stop_breakpoint_ = false;
	bool detached_ = false;

	std::atomic<bool> stop_pending_{ false };
	std::atomic<uint32_t> stop_tid_{ 0 };

	// address -> stop-hook id
	std::map<uint64_t, uint32_t> breakpoints_;
	uint32_t entry_hook_ = 0;
	uint64_t entry_address_ = 0;

	// tid -> address whose stop hook must be skipped once (the instruction it
	// is sitting on has not executed yet; re-running would re-trigger it).
	std::map<uint32_t, uint64_t> resume_skip_;
};

} // namespace debug
} // namespace duckemu::runtime

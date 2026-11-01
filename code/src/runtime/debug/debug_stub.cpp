// SPDX-License-Identifier: GPL-2.0-only
// Builds without -DDUCKEMU_ENABLE_DEBUG. The API stays linkable so callers do
// not need their own #ifdef; starting the server reports why it is unavailable.
#include "runtime/debug/debug_server.hpp"

namespace duckemu::runtime::debug
{

DebugServer::DebugServer(Target &target, const Options &options)
	: target_(target)
	, options_(options)
{
}

DebugServer::~DebugServer() = default;

Result<std::unique_ptr<DebugServer> > DebugServer::create(Target &target, const Options &options)
{
	(void)target;
	(void)options;
	return Error{ ErrorCode::Unsupported,
		"GDB remote debugging is not built (configure with -DDUCKEMU_ENABLE_DEBUG=ON)" };
}

DebugServer::Action DebugServer::serve(threads::RuntimeThread &thread)
{
	(void)thread;
	return Action::Detach;
}

bool DebugServer::consumeStop(uint32_t tid)
{
	(void)tid;
	return false;
}

size_t DebugServer::nextRunCount() const
{
	return 0;
}

void DebugServer::armEntry(uint64_t entry)
{
	(void)entry;
}

bool DebugServer::onStopHook(uint32_t tid, uint64_t address)
{
	(void)tid;
	(void)address;
	return false;
}

void DebugServer::close()
{
}

} // namespace duckemu::runtime::debug

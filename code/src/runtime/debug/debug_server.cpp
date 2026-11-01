// SPDX-License-Identifier: GPL-2.0-only
#include "runtime/debug/debug_server.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <cinttypes>
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <string_view>
#include <vector>

#include "runtime/backend/unicorn/unicorn_engine.hpp"
#include "runtime/debug/target_xml.hpp"
#include "runtime/threads/runtime_thread.hpp"

namespace duckemu::runtime::debug
{
namespace
{

void trace(const char *format, ...) __attribute__((format(printf, 1, 2)));
void trace(const char *format, ...)
{
	char buffer[1024];
	va_list args;
	va_start(args, format);
	std::vsnprintf(buffer, sizeof(buffer), format, args);
	va_end(args);
	std::fprintf(stderr, "[gdb] %s\n", buffer);
	std::fflush(stderr);
}

int hexValue(char c)
{
	if (c >= '0' && c <= '9')
	{
		return c - '0';
	}
	if (c >= 'a' && c <= 'f')
	{
		return c - 'a' + 10;
	}
	if (c >= 'A' && c <= 'F')
	{
		return c - 'A' + 10;
	}
	return -1;
}

std::string hexEncode(const void *data, size_t size)
{
	static const char kDigits[] = "0123456789abcdef";
	const auto *bytes = static_cast<const uint8_t *>(data);
	std::string out;
	out.reserve(size * 2);
	for (size_t i = 0; i < size; ++i)
	{
		out.push_back(kDigits[bytes[i] >> 4]);
		out.push_back(kDigits[bytes[i] & 0x0f]);
	}
	return out;
}

bool hexDecode(std::string_view text, std::vector<uint8_t> &out)
{
	if (text.size() % 2 != 0)
	{
		return false;
	}
	out.clear();
	out.reserve(text.size() / 2);
	for (size_t i = 0; i < text.size(); i += 2)
	{
		const int hi = hexValue(text[i]);
		const int lo = hexValue(text[i + 1]);
		if (hi < 0 || lo < 0)
		{
			return false;
		}
		out.push_back(static_cast<uint8_t>((hi << 4) | lo));
	}
	return true;
}

uint64_t parseHex(std::string_view text)
{
	std::string copy{ text };
	return std::strtoull(copy.c_str(), nullptr, 16);
}

bool startsWith(std::string_view text, std::string_view prefix)
{
	return text.size() >= prefix.size() && text.substr(0, prefix.size()) == prefix;
}

std::vector<std::string_view> split(std::string_view text, char separator)
{
	std::vector<std::string_view> parts;
	size_t start = 0;
	for (;;)
	{
		const size_t at = text.find(separator, start);
		if (at == std::string_view::npos)
		{
			parts.push_back(text.substr(start));
			break;
		}
		parts.push_back(text.substr(start, at - start));
		start = at + 1;
	}
	return parts;
}

// aarch64 core register index -> Unicorn register id. X29/X30 are declared at
// the top of the enum, so they are not contiguous with X0..X28.
int ucRegister(uint64_t index)
{
	switch (index)
	{
	case 29:
		return UC_ARM64_REG_X29;
	case 30:
		return UC_ARM64_REG_X30;
	case 31:
		return UC_ARM64_REG_SP;
	case 32:
		return UC_ARM64_REG_PC;
	case 33:
		return UC_ARM64_REG_NZCV;
	default:
		return UC_ARM64_REG_X0 + static_cast<int>(index);
	}
}

} // namespace

DebugServer::DebugServer(Target &target, const Options &options)
	: target_(target)
	, options_(options)
{
}

DebugServer::~DebugServer()
{
	close();
}

Result<std::unique_ptr<DebugServer> > DebugServer::create(Target &target, const Options &options)
{
	std::unique_ptr<DebugServer> server(new DebugServer(target, options));
	if (!server->listen())
	{
		return Error{ ErrorCode::InvalidArgument, "cannot listen for a GDB client" };
	}
	return server;
}

bool DebugServer::listen()
{
	listener_ = ::socket(AF_INET, SOCK_STREAM, 0);
	if (listener_ < 0)
	{
		return false;
	}
	int one = 1;
	::setsockopt(listener_, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

	sockaddr_in address{};
	address.sin_family = AF_INET;
	address.sin_addr.s_addr = htonl(INADDR_LOOPBACK); // never 0.0.0.0
	address.sin_port = htons(options_.port);
	if (::bind(listener_, reinterpret_cast<sockaddr *>(&address), sizeof(address)) != 0 ||
		::listen(listener_, 1) != 0)
	{
		::close(listener_);
		listener_ = -1;
		return false;
	}
	trace("listening on 127.0.0.1:%u", static_cast<unsigned>(options_.port));
	return true;
}

bool DebugServer::acceptClient()
{
	if (listener_ < 0)
	{
		return false;
	}
	const int fd = ::accept(listener_, nullptr, nullptr);
	if (fd < 0)
	{
		return false;
	}
	client_ = fd;
	ack_ = true;
	no_ack_ = false;
	detach_requested_ = false;
	trace("client connected");
	return true;
}

void DebugServer::close()
{
	// Drop every stop hook first: a detached client must not park the target.
	for (const auto &entry : breakpoints_)
	{
		target_.removeStopHook(entry.second);
	}
	breakpoints_.clear();
	if (entry_hook_ != 0)
	{
		target_.removeStopHook(entry_hook_);
		entry_hook_ = 0;
	}
	detached_ = true;
	if (client_ >= 0)
	{
		::close(client_);
		client_ = -1;
	}
	if (listener_ >= 0)
	{
		::close(listener_);
		listener_ = -1;
	}
	current_ = nullptr;
}

void DebugServer::sendRaw(const std::string &text)
{
	size_t sent = 0;
	while (sent < text.size())
	{
		const ssize_t wrote = ::send(client_, text.data() + sent, text.size() - sent, MSG_NOSIGNAL);
		if (wrote <= 0)
		{
			return;
		}
		sent += static_cast<size_t>(wrote);
	}
}

std::string DebugServer::escapePayload(const std::string &payload)
{
	std::string out;
	out.reserve(payload.size() + 8);
	for (const char c : payload)
	{
		if (c == '#' || c == '$' || c == '}' || c == '*')
		{
			out.push_back('}');
			out.push_back(static_cast<char>(static_cast<unsigned char>(c) ^ 0x20));
		}
		else
		{
			out.push_back(c);
		}
	}
	return out;
}

std::string DebugServer::unescapePayload(const std::string &raw)
{
	std::string out;
	out.reserve(raw.size());
	for (size_t i = 0; i < raw.size(); ++i)
	{
		if (raw[i] == '}' && i + 1 < raw.size())
		{
			out.push_back(static_cast<char>(static_cast<unsigned char>(raw[++i]) ^ 0x20));
		}
		else
		{
			out.push_back(raw[i]);
		}
	}
	return out;
}

void DebugServer::logPacket(const char *direction, const std::string &payload)
{
	std::string shown = payload;
	for (char &c : shown)
	{
		if (c < 0x20 || c > 0x7e)
		{
			c = '.';
		}
	}
	if (shown.size() > 160)
	{
		shown = shown.substr(0, 160) + "...";
	}
	trace("%s %s", direction, shown.c_str());
}

bool DebugServer::receivePacket(std::string &payload)
{
	for (;;)
	{
		char byte = 0;
		if (::recv(client_, &byte, 1, 0) != 1)
		{
			return false;
		}
		if (byte == '+' || byte == '-')
		{
			continue;
		}
		if (static_cast<unsigned char>(byte) == 0x03)
		{
			logPacket("<", "<interrupt>");
			payload.assign(1, '\x03');
			return true;
		}
		if (byte != '$')
		{
			continue;
		}

		std::string raw;
		for (;;)
		{
			char inner = 0;
			if (::recv(client_, &inner, 1, 0) != 1)
			{
				return false;
			}
			if (inner == '#')
			{
				break;
			}
			raw.push_back(inner);
		}
		char high = 0;
		char low = 0;
		if (::recv(client_, &high, 1, 0) != 1 || ::recv(client_, &low, 1, 0) != 1)
		{
			return false;
		}
		unsigned sum = 0;
		for (const char c : raw)
		{
			sum += static_cast<unsigned char>(c);
		}
		if (static_cast<int>(sum & 0xff) != ((hexValue(high) << 4) | hexValue(low)))
		{
			if (ack_)
			{
				sendRaw("-");
			}
			continue;
		}
		if (ack_)
		{
			sendRaw("+");
		}
		payload = unescapePayload(raw);
		return true;
	}
}

void DebugServer::sendPacket(const std::string &payload)
{
	const std::string body = escapePayload(payload);
	unsigned sum = 0;
	for (const char c : body)
	{
		sum += static_cast<unsigned char>(c);
	}
	char trailer[4] = {};
	std::snprintf(trailer, sizeof(trailer), "#%02x", static_cast<unsigned>(sum & 0xff));
	sendRaw("$" + body + trailer);
	logPacket(">", payload);
}

// ---------------------------------------------------------------------------
// Registers
// ---------------------------------------------------------------------------
bool DebugServer::readRegister(uint64_t index, uint64_t &value) const
{
	if (current_ == nullptr || current_->engine == nullptr || index > 33)
	{
		return false;
	}
	const auto result = current_->engine->readRegister(ucRegister(index));
	if (!result.ok())
	{
		return false;
	}
	value = result.value();
	return true;
}

bool DebugServer::writeRegister(uint64_t index, uint64_t value)
{
	if (current_ == nullptr || current_->engine == nullptr || index > 33)
	{
		return false;
	}
	return current_->engine->writeRegister(ucRegister(index), value).ok();
}

std::string DebugServer::readAllRegisters() const
{
	std::vector<uint8_t> bytes;
	bytes.reserve(268);
	for (uint64_t index = 0; index < 34; ++index)
	{
		uint64_t value = 0;
		if (!readRegister(index, value))
		{
			return "E01";
		}
		const size_t width = index == 33 ? 4 : 8; // cpsr is 32 bits
		const auto *raw = reinterpret_cast<const uint8_t *>(&value);
		bytes.insert(bytes.end(), raw, raw + width);
	}
	return hexEncode(bytes.data(), bytes.size());
}

bool DebugServer::writeAllRegisters(const std::string &hex)
{
	std::vector<uint8_t> bytes;
	if (!hexDecode(hex, bytes) || bytes.size() < 268)
	{
		return false;
	}
	for (uint64_t index = 0; index < 33; ++index)
	{
		uint64_t value = 0;
		std::memcpy(&value, bytes.data() + index * 8, sizeof(value));
		if (!writeRegister(index, value))
		{
			return false;
		}
	}
	uint32_t cpsr = 0;
	std::memcpy(&cpsr, bytes.data() + 33 * 8, sizeof(cpsr));
	return writeRegister(33, cpsr);
}

// ---------------------------------------------------------------------------
// Memory
// ---------------------------------------------------------------------------
Result<void> DebugServer::readMemory(uint64_t address, std::string &out, uint64_t size)
{
	std::vector<uint8_t> bytes(static_cast<size_t>(size));
	if (size != 0)
	{
		auto result = target_.readMemory(address, bytes.data(), size);
		if (!result.ok())
		{
			return result.error();
		}
	}
	out = hexEncode(bytes.data(), bytes.size());
	return {};
}

Result<void> DebugServer::writeMemory(uint64_t address, const std::string &data)
{
	if (data.empty())
	{
		return {};
	}
	return target_.writeMemory(address, data.data(), data.size());
}

// ---------------------------------------------------------------------------
// Breakpoints
// ---------------------------------------------------------------------------
void DebugServer::installBreakpoint(uint64_t address)
{
	if (breakpoints_.find(address) != breakpoints_.end())
	{
		return;
	}
	auto hook = target_.addStopHook(address, [this, address](uint32_t tid) {
		return onStopHook(tid, address);
	});
	if (hook.ok())
	{
		breakpoints_[address] = hook.value();
		trace("breakpoint 0x%" PRIx64 " armed", address);
	}
}

void DebugServer::removeBreakpoint(uint64_t address)
{
	const auto at = breakpoints_.find(address);
	if (at == breakpoints_.end())
	{
		return;
	}
	target_.removeStopHook(at->second);
	breakpoints_.erase(at);
	trace("breakpoint 0x%" PRIx64 " removed", address);
}

void DebugServer::armEntry(uint64_t entry)
{
	if (entry == 0 || (entry_hook_ != 0 && entry == entry_address_))
	{
		return;
	}
	if (entry_hook_ != 0)
	{
		target_.removeStopHook(entry_hook_);
		entry_hook_ = 0;
	}
	auto hook = target_.addStopHook(entry, [this, entry](uint32_t tid) {
		return onStopHook(tid, entry);
	});
	if (hook.ok())
	{
		entry_hook_ = hook.value();
		entry_address_ = entry;
		trace("entry stop 0x%" PRIx64 " armed", entry);
	}
}

bool DebugServer::onStopHook(uint32_t tid, uint64_t address)
{
	if (detached_)
	{
		return false;
	}
	// The instruction at `address` has not executed yet (Probe 12A). If we are
	// re-entering right after a resume from the same address, let it run.
	const auto skip = resume_skip_.find(tid);
	if (skip != resume_skip_.end() && skip->second == address)
	{
		resume_skip_.erase(skip);
		return false;
	}
	stop_tid_.store(tid, std::memory_order_release);
	stop_pending_.store(true, std::memory_order_release);
	return true;
}

bool DebugServer::consumeStop(uint32_t tid)
{
	const bool breakpoint = stop_pending_.exchange(false, std::memory_order_acquire);
	const bool step = step_pending_;
	step_pending_ = false;
	if (breakpoint && stop_tid_.load(std::memory_order_acquire) != tid)
	{
		// Another thread's stop; the scheduler will see it when that thread
		// returns from its own run.
		stop_pending_.store(true, std::memory_order_release);
		return false;
	}
	if (breakpoint)
	{
		last_stop_breakpoint_ = true;
		return true;
	}
	if (step)
	{
		last_stop_breakpoint_ = false;
		return true;
	}
	return false;
}

size_t DebugServer::nextRunCount() const
{
	return step_pending_ ? 1 : 0;
}

// ---------------------------------------------------------------------------
// Stop reply and xfer
// ---------------------------------------------------------------------------
std::string DebugServer::stopReply(bool breakpoint_hit) const
{
	const uint32_t tid = current_ != nullptr ? current_->tid : stop_tid_.load();
	char buffer[64] = {};
	if (breakpoint_hit)
	{
		std::snprintf(buffer, sizeof(buffer), "T05thread:%x;swbreak:;", tid);
	}
	else
	{
		std::snprintf(buffer, sizeof(buffer), "T05thread:%x;", tid);
	}
	return buffer;
}

std::string DebugServer::handleXfer(const std::string &packet) const
{
	const auto parts = split(std::string_view(packet).substr(6), ':');
	if (parts.size() < 4 || parts[1] != "read")
	{
		return "E00";
	}
	const std::string object{ parts[0] };
	const std::string annex{ parts[2] };
	const auto range = split(parts[3], ',');
	if (range.empty())
	{
		return "E00";
	}
	const uint64_t offset = parseHex(range[0]);
	const uint64_t length = range.size() > 1 ? parseHex(range[1]) : 0x400;

	std::string document;
	if (object == "features")
	{
		if (annex != "target.xml")
		{
			return "";
		}
		document = aarch64TargetXml();
	}
	else if (object == "libraries")
	{
		document = "<library-list>\n";
		for (const ModuleInfo &module : target_.modules())
		{
			if (module.is_virtual || module.base == 0)
			{
				continue;
			}
			char line[512] = {};
			std::snprintf(line, sizeof(line),
				"  <library name=\"%s\"><section address=\"0x%llx\" size=\"0x%llx\"/>"
				"</library>\n",
				module.path.c_str(), static_cast<unsigned long long>(module.base),
				static_cast<unsigned long long>(module.span));
			document += line;
		}
		document += "</library-list>\n";
	}
	else if (object == "memory-map")
	{
		document = "<memory-map>\n";
		for (const ModuleInfo &module : target_.modules())
		{
			if (module.is_virtual || module.base == 0 || module.span == 0)
			{
				continue;
			}
			char line[256] = {};
			std::snprintf(line, sizeof(line),
				"  <memory type=\"ram\" start=\"0x%llx\" length=\"0x%llx\"/>\n",
				static_cast<unsigned long long>(module.base),
				static_cast<unsigned long long>(module.span));
			document += line;
		}
		document += "</memory-map>\n";
	}
	else
	{
		return "";
	}

	if (offset >= document.size())
	{
		return "l";
	}
	const uint64_t end = std::min<uint64_t>(offset + length, document.size());
	std::string chunk = document.substr(static_cast<size_t>(offset), static_cast<size_t>(end - offset));
	return (end < document.size() ? "m" : "l") + chunk;
}

// ---------------------------------------------------------------------------
// Packet dispatch
// ---------------------------------------------------------------------------
std::string DebugServer::dispatch(const std::string &packet, Command &command)
{
	if (packet.empty())
	{
		return "";
	}

	if (packet == "?")
	{
		return stopReply(last_stop_breakpoint_);
	}
	if (packet == "!")
	{
		return "OK";
	}
	if (packet == "QStartNoAckMode")
	{
		no_ack_ = true;
		return "OK";
	}
	if (packet == "QPassSignals" || startsWith(packet, "QPassSignals:"))
	{
		return "OK";
	}
	if (startsWith(packet, "qSupported"))
	{
		return "PacketSize=4000;qXfer:features:read+;qXfer:libraries:read+;"
		       "qXfer:memory-map:read+;QStartNoAckMode+;vContSupported+;swbreak+;"
		       "hwbreak+;multiprocess-";
	}
	if (packet == "vMustReplyEmpty")
	{
		return "";
	}
	if (packet == "vCont?")
	{
		return "vCont;c;s";
	}
	if (startsWith(packet, "vCont;"))
	{
		if (packet.find(";s") != std::string::npos)
		{
			command = Command::Step;
			return "";
		}
		if (packet.find(";c") != std::string::npos)
		{
			command = Command::Resume;
			return "";
		}
		return "E01";
	}
	if (packet == "c" || startsWith(packet, "c"))
	{
		command = Command::Resume;
		return "";
	}
	if (packet == "s" || startsWith(packet, "s"))
	{
		command = Command::Step;
		return "";
	}
	if (startsWith(packet, "H"))
	{
		return "OK";
	}
	if (packet == "qAttached" || startsWith(packet, "qAttached:"))
	{
		return "1";
	}
	if (packet == "qC")
	{
		char reply[32] = {};
		std::snprintf(reply, sizeof(reply), "QC%x",
			current_ != nullptr ? current_->tid : 1u);
		return reply;
	}
	if (packet == "qfThreadInfo")
	{
		std::string reply = "m";
		bool first = true;
		for (const ThreadInfo &thread : target_.threads())
		{
			char item[16] = {};
			std::snprintf(item, sizeof(item), "%s%x", first ? "" : ",", thread.tid);
			reply += item;
			first = false;
		}
		return first ? "l" : reply;
	}
	if (packet == "qsThreadInfo")
	{
		return "l";
	}
	if (startsWith(packet, "qThreadExtraInfo"))
	{
		const auto comma = packet.find(',');
		const uint32_t tid = comma == std::string::npos
			? 0
			: static_cast<uint32_t>(parseHex(std::string_view(packet).substr(comma + 1)));
		std::string state = "unknown";
		for (const ThreadInfo &thread : target_.threads())
		{
			if (thread.tid == tid)
			{
				state = thread.state;
				break;
			}
		}
		return hexEncode(state.data(), state.size());
	}
	if (packet == "qOffsets")
	{
		return "Text=0;Data=0;Bss=0";
	}
	if (packet == "qTStatus")
	{
		return "";
	}
	if (packet == "qSymbol" || startsWith(packet, "qSymbol:"))
	{
		return "OK";
	}
	if (packet == "D" || startsWith(packet, "D;"))
	{
		command = Command::Detach;
		return "OK";
	}
	if (packet == "k")
	{
		command = Command::Detach;
		return "OK";
	}
	if (packet == "g")
	{
		return readAllRegisters();
	}
	if (startsWith(packet, "G"))
	{
		return writeAllRegisters(packet.substr(1)) ? "OK" : "E01";
	}
	if (startsWith(packet, "p"))
	{
		uint64_t value = 0;
		if (!readRegister(parseHex(std::string_view(packet).substr(1)), value))
		{
			return "E01";
		}
		const uint64_t index = parseHex(std::string_view(packet).substr(1));
		return hexEncode(&value, index == 33 ? 4 : 8);
	}
	if (startsWith(packet, "P"))
	{
		const auto parts = split(std::string_view(packet).substr(1), '=');
		if (parts.size() != 2)
		{
			return "E01";
		}
		std::vector<uint8_t> bytes;
		if (!hexDecode(parts[1], bytes))
		{
			return "E01";
		}
		uint64_t value = 0;
		std::memcpy(&value, bytes.data(), std::min<size_t>(bytes.size(), sizeof(value)));
		return writeRegister(parseHex(parts[0]), value) ? "OK" : "E01";
	}
	if (startsWith(packet, "m"))
	{
		const auto parts = split(std::string_view(packet).substr(1), ',');
		if (parts.size() != 2)
		{
			return "E01";
		}
		std::string out;
		if (!readMemory(parseHex(parts[0]), out, parseHex(parts[1])).ok())
		{
			return "E01";
		}
		return out;
	}
	if (startsWith(packet, "M"))
	{
		const auto colon = packet.find(':');
		if (colon == std::string::npos)
		{
			return "E01";
		}
		const auto parts = split(std::string_view(packet).substr(1, colon - 1), ',');
		if (parts.size() != 2)
		{
			return "E01";
		}
		std::vector<uint8_t> bytes;
		if (!hexDecode(std::string_view(packet).substr(colon + 1), bytes))
		{
			return "E01";
		}
		const std::string data(reinterpret_cast<const char *>(bytes.data()), bytes.size());
		return writeMemory(parseHex(parts[0]), data).ok() ? "OK" : "E01";
	}
	if (startsWith(packet, "X"))
	{
		const auto colon = packet.find(':');
		if (colon == std::string::npos)
		{
			return "E01";
		}
		const auto parts = split(std::string_view(packet).substr(1, colon - 1), ',');
		if (parts.size() != 2)
		{
			return "E01";
		}
		return writeMemory(parseHex(parts[0]), packet.substr(colon + 1)).ok() ? "OK" : "E01";
	}
	if (startsWith(packet, "Z") || startsWith(packet, "z"))
	{
		const bool insert = packet[0] == 'Z';
		const auto parts = split(std::string_view(packet).substr(1), ',');
		if (parts.size() < 2)
		{
			return "E01";
		}
		const uint64_t type = parseHex(parts[0]);
		const uint64_t address = parseHex(parts[1]);
		if (type != 0)
		{
			return "E01"; // watchpoints are M9 phase 2
		}
		if (insert)
		{
			installBreakpoint(address);
		}
		else
		{
			removeBreakpoint(address);
		}
		return "OK";
	}
	if (startsWith(packet, "qXfer:"))
	{
		return handleXfer(packet);
	}
	if (startsWith(packet, "qMemoryRegionInfo"))
	{
		const auto colon = packet.find(':');
		const uint64_t address = colon == std::string::npos
			? 0
			: parseHex(std::string_view(packet).substr(colon + 1));
		for (const ModuleInfo &module : target_.modules())
		{
			if (!module.is_virtual && address >= module.base &&
				address < module.base + module.span)
			{
				char reply[160] = {};
				std::snprintf(reply, sizeof(reply),
					"start:0x%llx,size:0x%llx;permissions:rwx;",
					static_cast<unsigned long long>(module.base),
					static_cast<unsigned long long>(module.span));
				return reply;
			}
		}
		return "start:0x0,size:0x0;";
	}
	if (packet == "qHostInfo" || startsWith(packet, "qHostInfo:"))
	{
		return "triple:arm64-unknown-linux-android;endian:little;ptrsize:8;";
	}
	if (packet == "qProcessInfo" || startsWith(packet, "qProcessInfo:"))
	{
		return "pid:1000;ptrsize:8;endian:little;";
	}

	return "";
}

// ---------------------------------------------------------------------------
// Serve loop
// ---------------------------------------------------------------------------
DebugServer::Action DebugServer::serve(threads::RuntimeThread &thread)
{
	current_ = &thread;
	if (detached_)
	{
		current_ = nullptr;
		return Action::Detach;
	}
	if (client_ < 0 && !acceptClient())
	{
		current_ = nullptr;
		return Action::Detach;
	}

	if (pending_stop_reply_)
	{
		sendPacket(stopReply(last_stop_breakpoint_));
		pending_stop_reply_ = false;
	}

	for (;;)
	{
		std::string packet;
		if (!receivePacket(packet))
		{
			close();
			return Action::Detach;
		}
		if (packet.size() == 1 && packet[0] == '\x03')
		{
			continue; // already stopped
		}
		logPacket("<", packet);

		Command command = Command::None;
		const std::string reply = dispatch(packet, command);
		if (command == Command::None)
		{
			sendPacket(reply);
			if (no_ack_)
			{
				ack_ = false; // QStartNoAckMode: the OK reply used the old mode
			}
			continue;
		}

		if (command == Command::Detach)
		{
			sendPacket(reply.empty() ? "OK" : reply);
			close();
			return Action::Detach;
		}

		// Remember the address we are resuming from. Its stop hook fires
		// before the instruction executes, so skip exactly one hit.
		uint64_t pc = 0;
		if (readRegister(32, pc))
		{
			resume_skip_[thread.tid] = pc;
		}
		pending_stop_reply_ = true;
		step_pending_ = command == Command::Step;
		current_ = nullptr;
		return command == Command::Step ? Action::Step : Action::Continue;
	}
}

} // namespace duckemu::runtime::debug

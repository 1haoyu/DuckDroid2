// SPDX-License-Identifier: GPL-2.0-only
// M9 P1 spike: a deliberately flat GDB Remote Serial Protocol stub.
//
// Its job is not to emulate anything. It exists so a client (Binary Ninja,
// gdb, lldb) can connect before any runtime work starts, while every packet
// the client sends is logged verbatim. The log is the deliverable: it tells us
// which packets and which spelling a real client actually uses.
//
// No runtime/, no Unicorn, no third-party code. Fake aarch64 state:
//   code  0x40001000  5 real instructions (mov/add/nop/nop/ret)
//   data  0x40002000  a short string
//   stack 0x40003000
// One guest thread (tid 1), all-stop, execution wraps at `ret`.
//
// Usage:
//   gdb_spike [--port N] [--log FILE] [--listen] [--quiet]
//
//   --port N    TCP port on 127.0.0.1 (default 31337)
//   --log FILE  also append the packet log to FILE
//   --listen    keep accepting after a client disconnects (default: one shot)
//   --quiet     only log packet directions, not per-instruction execution
//
// The packet log goes to stderr; every line starts with "< " (received) or
// "> " (sent). A per-packet-type summary is printed on exit.

#include <arpa/inet.h>
#include <netinet/in.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cinttypes>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <string>
#include <string_view>
#include <vector>

namespace
{

// ---------------------------------------------------------------------------
// Configuration and logging
// ---------------------------------------------------------------------------
bool g_quiet = false;
std::FILE *g_log = nullptr;
std::chrono::steady_clock::time_point g_start;

double nowMs()
{
	return std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - g_start)
		.count();
}

void logLine(const char *direction, const std::string &text)
{
	std::fprintf(stderr, "[%8.2f] %s %s\n", nowMs(), direction, text.c_str());
	if (g_log != nullptr)
	{
		std::fprintf(g_log, "[%8.2f] %s %s\n", nowMs(), direction, text.c_str());
		std::fflush(g_log);
	}
}

void note(const char *format, ...) __attribute__((format(printf, 1, 2)));
void note(const char *format, ...)
{
	char buffer[512];
	va_list args;
	va_start(args, format);
	std::vsnprintf(buffer, sizeof(buffer), format, args);
	va_end(args);
	std::fprintf(stderr, "[%8.2f]   %s\n", nowMs(), buffer);
	if (g_log != nullptr)
	{
		std::fprintf(g_log, "[%8.2f]   %s\n", nowMs(), buffer);
		std::fflush(g_log);
	}
}

// ---------------------------------------------------------------------------
// Hex helpers
// ---------------------------------------------------------------------------
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

std::string hexEncodeU64(uint64_t value)
{
	return hexEncode(&value, sizeof(value));
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

// ---------------------------------------------------------------------------
// Fake guest state
// ---------------------------------------------------------------------------
constexpr uint64_t kCodeBase = 0x40001000;
constexpr uint64_t kDataBase = 0x40002000;
constexpr uint64_t kStackBase = 0x40003000;
constexpr uint64_t kRegionSize = 0x1000;
constexpr uint64_t kStackTop = kStackBase + 0x800;

// mov x0, #1 ; add x1, x0, #1 ; nop ; nop ; ret
constexpr uint32_t kMovX0One = 0xD2800020;
constexpr uint32_t kAddX1X0One = 0x91000401;
constexpr uint32_t kNop = 0xD503201F;
constexpr uint32_t kRet = 0xD65F03C0;

struct Instruction
{
	uint64_t address;
	uint32_t word;
};

constexpr Instruction kProgram[] = {
	{ kCodeBase + 0x00, kMovX0One },
	{ kCodeBase + 0x04, kAddX1X0One },
	{ kCodeBase + 0x08, kNop },
	{ kCodeBase + 0x0C, kNop },
	{ kCodeBase + 0x10, kRet },
};

struct Region
{
	uint64_t base = 0;
	std::vector<uint8_t> data;
};

struct Guest
{
	std::vector<Region> regions;
	uint64_t x[31] = {};
	uint64_t sp = kStackTop;
	uint64_t pc = kCodeBase;
	uint32_t cpsr = 0x60000000; // Z set; value is arbitrary for the probe
	std::map<uint64_t, uint32_t> breakpoints;  // address -> kind
	std::map<uint64_t, uint32_t> watchpoints;  // address -> Z kind (2/3/4)

	Region *find(uint64_t address, uint64_t size)
	{
		for (Region &region : regions)
		{
			if (address >= region.base && address + size <= region.base + region.data.size())
			{
				return &region;
			}
		}
		return nullptr;
	}
};

void initialise(Guest &guest)
{
	Region code;
	code.base = kCodeBase;
	code.data.assign(kRegionSize, 0);
	for (const Instruction &insn : kProgram)
	{
		const size_t offset = static_cast<size_t>(insn.address - kCodeBase);
		std::memcpy(&code.data[offset], &insn.word, sizeof(insn.word));
	}
	guest.regions.push_back(std::move(code));

	Region data;
	data.base = kDataBase;
	data.data.assign(kRegionSize, 0);
	static const char kMessage[] = "DuckDroid2 gdb_spike\n";
	std::memcpy(data.data.data(), kMessage, sizeof(kMessage) - 1);
	guest.regions.push_back(std::move(data));

	Region stack;
	stack.base = kStackBase;
	stack.data.assign(kRegionSize, 0);
	guest.regions.push_back(std::move(stack));

	guest.pc = kCodeBase;
	guest.sp = kStackTop;
}

uint64_t nextPc(uint64_t pc)
{
	for (size_t i = 0; i < sizeof(kProgram) / sizeof(kProgram[0]); ++i)
	{
		if (kProgram[i].address != pc)
		{
			continue;
		}
		if (i + 1 < sizeof(kProgram) / sizeof(kProgram[0]))
		{
			return kProgram[i + 1].address;
		}
		return kProgram[0].address; // wrap: the probe is not a real process
	}
	return kProgram[0].address;
}

void executeOne(Guest &guest)
{
	uint32_t word = 0;
	const Instruction *current = nullptr;
	for (const Instruction &insn : kProgram)
	{
		if (insn.address == guest.pc)
		{
			current = &insn;
			word = insn.word;
			break;
		}
	}
	(void)word;
	if (current != nullptr && !g_quiet)
	{
		note("exec 0x%" PRIx64 "  w=0x%08" PRIx32, guest.pc, current->word);
	}
	if (guest.pc == kCodeBase)
	{
		guest.x[0] = 1;
	}
	else if (guest.pc == kCodeBase + 4)
	{
		guest.x[1] = guest.x[0] + 1;
	}
	guest.pc = nextPc(guest.pc);
}

// ---------------------------------------------------------------------------
// RSP link
// ---------------------------------------------------------------------------
class Link
{
    public:
	explicit Link(int fd)
		: fd_(fd)
	{
	}

	// Returns false on EOF or socket error. `payload` is unescaped.
	bool receive(std::string &payload)
	{
		for (;;)
		{
			char byte = 0;
			const ssize_t got = ::recv(fd_, &byte, 1, 0);
			if (got != 1)
			{
				return false;
			}
			if (byte == '+')
			{
				continue;
			}
			if (byte == '-')
			{
				note("client NAK");
				continue;
			}
			if (static_cast<unsigned char>(byte) == 0x03)
			{
				logLine("<", "<0x03 intercept>");
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
				if (::recv(fd_, &inner, 1, 0) != 1)
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
			if (::recv(fd_, &high, 1, 0) != 1 || ::recv(fd_, &low, 1, 0) != 1)
			{
				return false;
			}
			unsigned sum = 0;
			for (const char c : raw)
			{
				sum += static_cast<unsigned char>(c);
			}
			const int expected = (hexValue(high) << 4) | hexValue(low);
			if (static_cast<int>(sum & 0xff) != expected)
			{
				note("checksum mismatch (got %d, expected %d)", expected,
					static_cast<int>(sum & 0xff));
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
			payload = unescape(raw);
			return true;
		}
	}

	void send(const std::string &payload)
	{
		const std::string body = escape(payload);
		unsigned sum = 0;
		for (const char c : body)
		{
			sum += static_cast<unsigned char>(c);
		}
		char trailer[4] = {};
		std::snprintf(trailer, sizeof(trailer), "#%02x", static_cast<unsigned>(sum & 0xff));
		sendRaw("$" + body + trailer);
		std::string shown = payload;
		if (shown.empty())
		{
			shown = "<empty>";
		}
		if (shown.size() > 200)
		{
			shown = shown.substr(0, 200) + "...";
		}
		logLine(">", shown);
	}

	void setAck(bool enabled)
	{
		ack_ = enabled;
	}

    private:
	static std::string escape(const std::string &payload)
	{
		std::string out;
		out.reserve(payload.size() + 8);
		for (const char c : payload)
		{
			const auto byte = static_cast<unsigned char>(c);
			if (c == '#' || c == '$' || c == '}' || c == '*')
			{
				out.push_back('}');
				out.push_back(static_cast<char>(byte ^ 0x20));
			}
			else
			{
				out.push_back(c);
			}
		}
		return out;
	}

	static std::string unescape(const std::string &raw)
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

	void sendRaw(const std::string &text)
	{
		size_t sent = 0;
		while (sent < text.size())
		{
			const ssize_t wrote = ::send(fd_, text.data() + sent, text.size() - sent, MSG_NOSIGNAL);
			if (wrote <= 0)
			{
				return;
			}
			sent += static_cast<size_t>(wrote);
		}
	}

	int fd_ = -1;
	bool ack_ = true;
};

// ---------------------------------------------------------------------------
// Target description / memory map / library list
// ---------------------------------------------------------------------------
std::string targetXml()
{
	std::string xml;
	xml += "<?xml version=\"1.0\"?>\n";
	xml += "<!DOCTYPE target SYSTEM \"gdb-target.dtd\">\n";
	xml += "<target>\n";
	xml += "  <architecture>aarch64</architecture>\n";
	xml += "  <feature name=\"org.gnu.gdb.aarch64.core\">\n";
	for (int i = 0; i < 31; ++i)
	{
		char line[96] = {};
		std::snprintf(line, sizeof(line),
			"    <reg name=\"x%d\" bitsize=\"64\" type=\"int\" regnum=\"%d\"/>\n", i, i);
		xml += line;
	}
	xml += "    <reg name=\"sp\" bitsize=\"64\" type=\"data_ptr\" regnum=\"31\"/>\n";
	xml += "    <reg name=\"pc\" bitsize=\"64\" type=\"code_ptr\" regnum=\"32\"/>\n";
	xml += "    <reg name=\"cpsr\" bitsize=\"32\" type=\"int\" regnum=\"33\"/>\n";
	xml += "  </feature>\n";
	xml += "</target>\n";
	return xml;
}

std::string librariesXml()
{
	std::string xml;
	xml += "<library-list>\n";
	xml += "  <library name=\"gdb_spike.so\">\n";
	xml += "    <section address=\"0x40001000\" size=\"0x1000\"/>\n";
	xml += "  </library>\n";
	xml += "</library-list>\n";
	return xml;
}

std::string memoryMapXml()
{
	std::string xml;
	xml += "<memory-map>\n";
	for (const auto &range : { std::make_pair(kCodeBase, "ram"),
		     std::make_pair(kDataBase, "ram"),
		     std::make_pair(kStackBase, "ram") })
	{
		char line[128] = {};
		std::snprintf(line, sizeof(line),
			"  <memory type=\"%s\" start=\"0x%llx\" length=\"0x1000\"/>\n", range.second,
			static_cast<unsigned long long>(range.first));
		xml += line;
	}
	xml += "</memory-map>\n";
	return xml;
}

// ---------------------------------------------------------------------------
// Packet handling
// ---------------------------------------------------------------------------
struct Session
{
	Guest guest;
	bool no_ack = false;
	bool attached = true;
	std::map<std::string, uint64_t> counts;
};

std::string xferReply(const std::string &document, std::string_view offsetText)
{
	const auto parts = split(offsetText, ',');
	if (parts.empty())
	{
		return "E00";
	}
	const uint64_t offset = parseHex(parts[0]);
	const uint64_t length = parts.size() > 1 ? parseHex(parts[1]) : 0x400;
	if (offset >= document.size())
	{
		return "l";
	}
	const uint64_t end = std::min<uint64_t>(offset + length, document.size());
	std::string chunk = document.substr(static_cast<size_t>(offset), static_cast<size_t>(end - offset));
	return (end < document.size() ? "m" : "l") + chunk;
}

std::string readRegisters(const Guest &guest)
{
	std::vector<uint8_t> bytes;
	bytes.reserve(34 * 8);
	for (int i = 0; i < 31; ++i)
	{
		const uint64_t value = guest.x[i];
		bytes.insert(bytes.end(), reinterpret_cast<const uint8_t *>(&value),
			reinterpret_cast<const uint8_t *>(&value) + 8);
	}
	for (const uint64_t value : { guest.sp, guest.pc })
	{
		bytes.insert(bytes.end(), reinterpret_cast<const uint8_t *>(&value),
			reinterpret_cast<const uint8_t *>(&value) + 8);
	}
	// aarch64 core: x0..x30 (31 x 8) + sp (8) + pc (8) + cpsr (4) = 268 bytes.
	const uint32_t cpsr = guest.cpsr;
	bytes.insert(bytes.end(), reinterpret_cast<const uint8_t *>(&cpsr),
		reinterpret_cast<const uint8_t *>(&cpsr) + 4);
	return hexEncode(bytes.data(), bytes.size());
}

bool writeRegister(Guest &guest, uint64_t index, uint64_t value)
{
	if (index < 31)
	{
		guest.x[index] = value;
		return true;
	}
	if (index == 31)
	{
		guest.sp = value;
		return true;
	}
	if (index == 32)
	{
		guest.pc = value;
		return true;
	}
	if (index == 33)
	{
		guest.cpsr = static_cast<uint32_t>(value);
		return true;
	}
	return false;
}

uint64_t decodeU64(const std::vector<uint8_t> &bytes)
{
	uint64_t value = 0;
	if (bytes.size() >= 8)
	{
		std::memcpy(&value, bytes.data(), sizeof(value));
	}
	return value;
}

std::string runUntilStop(Session &session, bool single_step)
{
	Guest &guest = session.guest;
	bool first = true;
	uint64_t steps = 0;
	for (;;)
	{
		if (!first && guest.breakpoints.find(guest.pc) != guest.breakpoints.end())
		{
			note("breakpoint hit at 0x%" PRIx64, guest.pc);
			return "T05thread:1;swbreak:;";
		}
		first = false;
		executeOne(guest);
		++steps;
		if (single_step)
		{
			return "T05thread:1;";
		}
		if (steps > 100000)
		{
			note("step budget exhausted");
			return "T05thread:1;";
		}
	}
}

std::string handle(Session &session, const std::string &packet, bool &close_after)
{
	if (packet.size() == 1 && packet[0] == '\x03')
	{
		return "";
	}

	// Packet-type counter for the exit summary. Address-carrying packets are
	// grouped by their command letter so the summary stays readable.
	std::string key = packet;
	const size_t cut = key.find_first_of(",:");
	if (cut != std::string::npos)
	{
		key = key.substr(0, cut);
	}
	if (!key.empty() && std::strchr("mMXZzpPH", key[0]) != nullptr)
	{
		key = key.substr(0, 1);
	}
	++session.counts[key];

	Guest &guest = session.guest;

	if (packet == "?")
	{
		return "T05thread:1;";
	}
	if (packet == "!")
	{
		return "OK";
	}
	if (packet == "QStartNoAckMode")
	{
		session.no_ack = true;
		return "OK";
	}
	if (packet == "QPassSignals" || startsWith(packet, "QPassSignals:"))
	{
		return "OK";
	}
	if (startsWith(packet, "qSupported"))
	{
		return "PacketSize=4000;qXfer:features:read+;qXfer:libraries:read+;"
		       "qXfer:memory-map:read+;QStartNoAckMode+;"
		       "vContSupported+;swbreak+;hwbreak+;multiprocess-";
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
		// Accept the first action we understand: continue or step.
		for (const char *action : { ";c", ";s" })
		{
			if (packet.find(action) != std::string::npos)
			{
				return runUntilStop(session, action[1] == 's');
			}
		}
		return "E01";
	}
	if (packet == "c" || startsWith(packet, "c"))
	{
		return runUntilStop(session, false);
	}
	if (packet == "s" || startsWith(packet, "s"))
	{
		return runUntilStop(session, true);
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
		return "QC1";
	}
	if (packet == "qfThreadInfo")
	{
		return "m1";
	}
	if (packet == "qsThreadInfo")
	{
		return "l";
	}
	if (startsWith(packet, "qThreadExtraInfo"))
	{
		const std::string text = "Runnable";
		return hexEncode(text.data(), text.size());
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
		close_after = true;
		return "OK";
	}
	if (packet == "k")
	{
		close_after = true;
		return "OK";
	}
	if (packet == "g")
	{
		return readRegisters(guest);
	}
	if (startsWith(packet, "G"))
	{
		std::vector<uint8_t> bytes;
		if (!hexDecode(std::string_view(packet).substr(1), bytes) || bytes.size() < 268)
		{
			return "E01";
		}
		for (uint64_t i = 0; i < 33; ++i)
		{
			uint64_t value = 0;
			std::memcpy(&value, bytes.data() + i * 8, sizeof(value));
			writeRegister(guest, i, value);
		}
		uint32_t cpsr = 0;
		std::memcpy(&cpsr, bytes.data() + 33 * 8, sizeof(cpsr));
		guest.cpsr = cpsr;
		return "OK";
	}
	if (startsWith(packet, "p"))
	{
		const uint64_t index = parseHex(std::string_view(packet).substr(1));
		if (index < 31)
		{
			return hexEncodeU64(guest.x[index]);
		}
		if (index == 31)
		{
			return hexEncodeU64(guest.sp);
		}
		if (index == 32)
		{
			return hexEncodeU64(guest.pc);
		}
		if (index == 33)
		{
			return hexEncode(&guest.cpsr, sizeof(guest.cpsr));
		}
		return "E01";
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
		if (!writeRegister(guest, parseHex(parts[0]), decodeU64(bytes)))
		{
			return "E01";
		}
		return "OK";
	}
	if (startsWith(packet, "m"))
	{
		const auto parts = split(std::string_view(packet).substr(1), ',');
		if (parts.size() != 2)
		{
			return "E01";
		}
		const uint64_t address = parseHex(parts[0]);
		const uint64_t length = parseHex(parts[1]);
		Region *region = guest.find(address, length);
		if (region == nullptr)
		{
			return "E01";
		}
		const size_t offset = static_cast<size_t>(address - region->base);
		return hexEncode(region->data.data() + offset, static_cast<size_t>(length));
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
		const uint64_t address = parseHex(parts[0]);
		const uint64_t length = parseHex(parts[1]);
		std::vector<uint8_t> bytes;
		if (!hexDecode(std::string_view(packet).substr(colon + 1), bytes) ||
			bytes.size() != length)
		{
			return "E01";
		}
		Region *region = guest.find(address, length);
		if (region == nullptr)
		{
			return "E01";
		}
		std::memcpy(region->data.data() + (address - region->base), bytes.data(), bytes.size());
		return "OK";
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
		const uint64_t address = parseHex(parts[0]);
		const uint64_t length = parseHex(parts[1]);
		const std::string body = packet.substr(colon + 1);
		Region *region = guest.find(address, length);
		if (region == nullptr || body.size() != length)
		{
			return "E01";
		}
		std::memcpy(region->data.data() + (address - region->base), body.data(), body.size());
		return "OK";
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
		const uint64_t kind = parts.size() > 2 ? parseHex(parts[2]) : 0;
		if (type == 0)
		{
			if (insert)
			{
				guest.breakpoints[address] = static_cast<uint32_t>(kind);
				note("Z0 breakpoint insert 0x%" PRIx64 " kind %" PRIu64, address, kind);
			}
			else
			{
				guest.breakpoints.erase(address);
				note("z0 breakpoint remove 0x%" PRIx64, address);
			}
			return "OK";
		}
		if (type >= 2 && type <= 4)
		{
			if (insert)
			{
				guest.watchpoints[address] = static_cast<uint32_t>(type);
				note("Z%" PRIu64 " watchpoint insert 0x%" PRIx64 " len %" PRIu64, type, address,
					kind);
			}
			else
			{
				guest.watchpoints.erase(address);
				note("z%" PRIu64 " watchpoint remove 0x%" PRIx64, type, address);
			}
			return "OK";
		}
		return "E01";
	}
	if (startsWith(packet, "qXfer:"))
	{
		const auto parts = split(std::string_view(packet).substr(6), ':');
		// object : read : annex : offset,length
		if (parts.size() < 4)
		{
			return "E00";
		}
		const std::string object{ parts[0] };
		const std::string operation{ parts[1] };
		const std::string annex{ parts[2] };
		const std::string range{ parts[3] };
		if (operation != "read")
		{
			return "E00";
		}
		if (object == "features")
		{
			return annex == "target.xml" ? xferReply(targetXml(), range) : "";
		}
		if (object == "libraries")
		{
			return xferReply(librariesXml(), range);
		}
		if (object == "memory-map")
		{
			return xferReply(memoryMapXml(), range);
		}
		if (object == "exec-file")
		{
			// An empty annex keeps gdb from trying to load a local path; the
			// module is advertised through qXfer:libraries:read instead.
			return "";
		}
		return "";
	}
	if (startsWith(packet, "qMemoryRegionInfo"))
	{
		// LLDB-style; Binary Ninja may ask. Answer for the three regions.
		const auto colon = packet.find(':');
		const uint64_t address =
			colon == std::string::npos ? 0 : parseHex(std::string_view(packet).substr(colon + 1));
		for (const Region &region : guest.regions)
		{
			if (address >= region.base && address < region.base + region.data.size())
			{
				char reply[128] = {};
				std::snprintf(reply, sizeof(reply),
					"start:0x%llx,size:0x%zx;permissions:rwx;",
					static_cast<unsigned long long>(region.base), region.data.size());
				return reply;
			}
		}
		return "start:0x0,size:0x0;";
	}
	if (startsWith(packet, "qXfer:auxv"))
	{
		return "";
	}
	if (packet == "qHostInfo" || startsWith(packet, "qHostInfo:"))
	{
		return "triple:arm64-unknown-linux-android;endian:little;ptrsize:8;";
	}
	if (packet == "qProcessInfo" || startsWith(packet, "qProcessInfo:"))
	{
		return "pid:1000;parent-pid:1;real-uid:1000;real-gid:1000;"
		       "effective-uid:1000;effective-gid:1000;ptrsize:8;";
	}

	// Unknown packet: an empty reply is the protocol's "not supported".
	return "";
}

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------
void serveConnection(int fd, bool keep_listening, std::map<std::string, uint64_t> &summary)
{
	logLine("=", "client connected");
	Session session;
	initialise(session.guest);

	Link link(fd);
	bool close_after = false;
	for (;;)
	{
		std::string packet;
		if (!link.receive(packet))
		{
			logLine("=", "client disconnected");
			break;
		}
		if (packet.empty())
		{
			continue;
		}
		std::string shown = packet;
		for (char &c : shown)
		{
			if (c < 0x20 || c > 0x7e)
			{
				c = '.';
			}
		}
		logLine("<", shown);
		const std::string reply = handle(session, packet, close_after);
		if (session.no_ack)
		{
			link.setAck(false);
		}
		link.send(reply);
		if (close_after)
		{
			break;
		}
	}
	for (const auto &[name, count] : session.counts)
	{
		summary[name] += count;
	}
	(void)keep_listening;
	(void)summary;
	::close(fd);
}

int listenOnce(uint16_t port)
{
	const int listener = ::socket(AF_INET, SOCK_STREAM, 0);
	if (listener < 0)
	{
		std::perror("socket");
		return -1;
	}
	int one = 1;
	::setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

	sockaddr_in address{};
	address.sin_family = AF_INET;
	address.sin_addr.s_addr = htonl(INADDR_LOOPBACK); // never 0.0.0.0
	address.sin_port = htons(port);
	if (::bind(listener, reinterpret_cast<sockaddr *>(&address), sizeof(address)) != 0)
	{
		std::perror("bind");
		::close(listener);
		return -1;
	}
	if (::listen(listener, 1) != 0)
	{
		std::perror("listen");
		::close(listener);
		return -1;
	}
	return listener;
}

} // namespace

int main(int argc, char **argv)
{
	uint16_t port = 31337;
	bool keep_listening = false;
	std::string log_path;
	std::string dump_raw;

	for (int i = 1; i < argc; ++i)
	{
		const std::string_view argument = argv[i];
		if (argument == "--port" && i + 1 < argc)
		{
			port = static_cast<uint16_t>(std::strtoul(argv[++i], nullptr, 10));
		}
		else if (argument == "--log" && i + 1 < argc)
		{
			log_path = argv[++i];
		}
		else if (argument == "--dump-raw" && i + 1 < argc)
		{
			dump_raw = argv[++i];
		}
		else if (argument == "--listen")
		{
			keep_listening = true;
		}
		else if (argument == "--quiet")
		{
			g_quiet = true;
		}
		else
		{
			std::fprintf(stderr,
				"usage: %s [--port N] [--log FILE] [--dump-raw FILE] [--listen] "
				"[--quiet]\n",
				argv[0]);
			return 2;
		}
	}

	g_start = std::chrono::steady_clock::now();

	// --dump-raw: write the 4 KiB code page so a client can open it as a raw
	// binary rebased to 0x40001000 and show real disassembly.
	if (!dump_raw.empty())
	{
		Guest guest;
		initialise(guest);
		std::FILE *out = std::fopen(dump_raw.c_str(), "wb");
		if (out == nullptr)
		{
			std::perror("--dump-raw");
			return 2;
		}
		const Region &code = guest.regions.front();
		std::fwrite(code.data.data(), 1, code.data.size(), out);
		std::fclose(out);
		std::fprintf(stderr, "%s: %zu bytes (open as raw, base 0x%llx)\n", dump_raw.c_str(),
			code.data.size(), static_cast<unsigned long long>(code.base));
		return 0;
	}

	::signal(SIGPIPE, SIG_IGN);
	if (!log_path.empty())
	{
		g_log = std::fopen(log_path.c_str(), "w");
		if (g_log == nullptr)
		{
			std::perror("--log");
			return 2;
		}
	}

	const int listener = listenOnce(port);
	if (listener < 0)
	{
		return 1;
	}
	std::fprintf(stderr,
		"gdb_spike listening on 127.0.0.1:%u  (Binary Ninja: Debugger -> "
		"Connect to Remote Process -> GDB RSP)\n",
		static_cast<unsigned>(port));
	std::fflush(stderr);

	std::map<std::string, uint64_t> summary;
	for (;;)
	{
		sockaddr_in peer{};
		socklen_t peer_length = sizeof(peer);
		const int fd = ::accept(listener, reinterpret_cast<sockaddr *>(&peer), &peer_length);
		if (fd < 0)
		{
			if (errno == EINTR)
			{
				continue;
			}
			std::perror("accept");
			break;
		}
		serveConnection(fd, keep_listening, summary);
		if (!keep_listening)
		{
			break;
		}
	}
	::close(listener);

	std::fprintf(stderr, "--- packet summary ---\n");
	for (const auto &[name, count] : summary)
	{
		std::fprintf(stderr, "  %-32s %" PRIu64 "\n", name.c_str(), count);
	}
	if (g_log != nullptr)
	{
		std::fclose(g_log);
	}
	return 0;
}

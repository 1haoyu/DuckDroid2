// SPDX-License-Identifier: GPL-2.0-only
#include "runtime/observer/trace/svc_trace.hpp"

#include <array>
#include <cerrno>
#include <cstdint>
#include <cstring>

namespace duckemu::runtime::observer
{
namespace
{

constexpr size_t kFieldCount = 9;
constexpr std::string_view kHexPrefix = "0x";

void appendHex(std::string &out, uint64_t value)
{
	char buffer[32];
	std::snprintf(buffer, sizeof(buffer), "0x%llx", static_cast<unsigned long long>(value));
	out += buffer;
}

void appendJsonString(std::string &out, std::string_view text)
{
	out += '"';
	for (const char ch : text)
	{
		switch (ch)
		{
		case '"':
			out += "\\\"";
			break;
		case '\\':
			out += "\\\\";
			break;
		case '\t':
			out += "\\t";
			break;
		case '\n':
			out += "\\n";
			break;
		default:
			out += ch;
			break;
		}
	}
	out += '"';
}

std::string jsonString(std::string_view text)
{
	std::string out;
	appendJsonString(out, text);
	return out;
}

// The name column must stay a single tab-free token: host stub names are
// developer-provided, and one stray tab would shift every later column.
std::string columnToken(std::string_view text)
{
	std::string out(text);
	for (char &ch : out)
	{
		if (ch == '\t' || ch == '\n' || ch == '\r')
		{
			ch = '_';
		}
	}
	return out;
}

bool splitFields(std::string_view line, std::string_view (&fields)[kFieldCount])
{
	size_t start = 0;
	for (size_t i = 0; i < kFieldCount; ++i)
	{
		const size_t tab = line.find('\t', start);
		if (i + 1 == kFieldCount)
		{
			if (tab != std::string_view::npos)
			{
				return false;
			}
			fields[i] = line.substr(start);
			return !fields[i].empty();
		}
		if (tab == std::string_view::npos)
		{
			return false;
		}
		fields[i] = line.substr(start, tab - start);
		start = tab + 1;
	}
	return false;
}

// Accepts "abc" when `requirePrefix` is false (the seq column) and "0xabc"
// otherwise. Digits only, lowercase, no sign.
std::optional<uint64_t> parseHex(std::string_view text, bool requirePrefix)
{
	if (requirePrefix)
	{
		if (text.size() <= kHexPrefix.size() || text.substr(0, kHexPrefix.size()) != kHexPrefix)
		{
			return std::nullopt;
		}
		text.remove_prefix(kHexPrefix.size());
	}
	if (text.empty())
	{
		return std::nullopt;
	}

	uint64_t value = 0;
	for (const char ch : text)
	{
		unsigned int digit = 0;
		if (ch >= '0' && ch <= '9')
		{
			digit = static_cast<unsigned int>(ch - '0');
		}
		else if (ch >= 'a' && ch <= 'f')
		{
			digit = static_cast<unsigned int>(ch - 'a' + 10);
		}
		else
		{
			return std::nullopt;
		}
		if (value > (UINT64_MAX - digit) / 16)
		{
			return std::nullopt;
		}
		value = value * 16 + digit;
	}
	return value;
}

bool parseKind(std::string_view text, SvcKind &kind)
{
	if (text == svcKindName(SvcKind::Syscall))
	{
		kind = SvcKind::Syscall;
		return true;
	}
	if (text == svcKindName(SvcKind::HostStub))
	{
		kind = SvcKind::HostStub;
		return true;
	}
	if (text == svcKindName(SvcKind::UnknownTrap))
	{
		kind = SvcKind::UnknownTrap;
		return true;
	}
	return false;
}

bool parseArgs(std::string_view text, std::array<uint64_t, 6> &args)
{
	if (text.size() < 2 || text.front() != '[' || text.back() != ']')
	{
		return false;
	}
	text.remove_prefix(1);
	text.remove_suffix(1);

	size_t index = 0;
	while (!text.empty())
	{
		if (index >= args.size() || text.front() != '"')
		{
			return false;
		}
		const size_t quote = text.find('"', 1);
		if (quote == std::string_view::npos)
		{
			return false;
		}
		const auto value = parseHex(text.substr(1, quote - 1), true);
		if (!value.has_value())
		{
			return false;
		}
		args[index++] = value.value();
		text.remove_prefix(quote + 1);

		if (text.empty())
		{
			break;
		}
		if (text.front() != ',')
		{
			return false;
		}
		text.remove_prefix(1);
	}
	return index == args.size();
}

std::string unescapeJson(std::string_view text)
{
	std::string out;
	out.reserve(text.size());
	for (size_t i = 0; i < text.size(); ++i)
	{
		if (text[i] != '\\' || i + 1 >= text.size())
		{
			out += text[i];
			continue;
		}
		++i;
		switch (text[i])
		{
		case 't':
			out += '\t';
			break;
		case 'n':
			out += '\n';
			break;
		default:
			out += text[i];
			break;
		}
	}
	return out;
}

bool parseNote(std::string_view text, SvcEvent &event)
{
	if (text == "{}")
	{
		event.support = SvcSupport::Supported;
		return true;
	}

	constexpr std::string_view kDegraded = "{\"degraded\":1";
	if (text.substr(0, kDegraded.size()) == kDegraded)
	{
		event.support = SvcSupport::Degraded;
		text.remove_prefix(kDegraded.size());

		constexpr std::string_view kReason = ",\"reason\":\"";
		if (text.substr(0, kReason.size()) == kReason)
		{
			text.remove_prefix(kReason.size());
			const size_t end = text.find('"');
			if (end == std::string_view::npos)
			{
				return false;
			}
			event.degraded_reason = unescapeJson(text.substr(0, end));
			text.remove_prefix(end + 1);
		}
		return text == "}";
	}

	constexpr std::string_view kUnsupported = "{\"unsupported\":1";
	if (text.substr(0, kUnsupported.size()) != kUnsupported)
	{
		return false;
	}
	event.support = SvcSupport::Unsupported;
	text.remove_prefix(kUnsupported.size());

	constexpr std::string_view kStop = ",\"stop\":\"";
	if (text.substr(0, kStop.size()) == kStop)
	{
		text.remove_prefix(kStop.size());
		const size_t end = text.find('"');
		if (end == std::string_view::npos)
		{
			return false;
		}
		event.stack_stop = unescapeJson(text.substr(0, end));
		text.remove_prefix(end + 1);
	}

	constexpr std::string_view kStack = ",\"stack\":[";
	if (text.substr(0, kStack.size()) != kStack)
	{
		return false;
	}
	text.remove_prefix(kStack.size());

	while (!text.empty() && text.front() != ']')
	{
		constexpr std::string_view kPc = "{\"pc\":\"";
		if (text.substr(0, kPc.size()) != kPc)
		{
			return false;
		}
		text.remove_prefix(kPc.size());
		const size_t pc_end = text.find('"');
		if (pc_end == std::string_view::npos)
		{
			return false;
		}
		const auto pc = parseHex(text.substr(0, pc_end), true);
		if (!pc.has_value())
		{
			return false;
		}
		text.remove_prefix(pc_end + 1);

		constexpr std::string_view kName = ",\"name\":\"";
		if (text.substr(0, kName.size()) != kName)
		{
			return false;
		}
		text.remove_prefix(kName.size());
		const size_t name_end = text.find('"');
		if (name_end == std::string_view::npos)
		{
			return false;
		}
		event.stack.push_back(GuestFrame{ pc.value(), unescapeJson(text.substr(0, name_end)) });
		text.remove_prefix(name_end + 1);

		if (text.empty() || text.front() != '}')
		{
			return false;
		}
		text.remove_prefix(1);
		if (!text.empty() && text.front() == ',')
		{
			text.remove_prefix(1);
		}
	}

	constexpr std::string_view kEnd = "]}";
	if (text != kEnd)
	{
		return false;
	}
	return true;
}

} // namespace

std::string formatSvcTraceLine(const SvcEvent &event)
{
	std::string line;
	char buffer[64];

	std::snprintf(buffer, sizeof(buffer), "%llx", static_cast<unsigned long long>(event.id));
	line += buffer;
	line += '\t';

	std::snprintf(buffer, sizeof(buffer), "%llx", static_cast<unsigned long long>(event.seq));
	line += buffer;
	line += '\t';

	std::snprintf(buffer, sizeof(buffer), "0x%x", event.tid);
	line += buffer;
	line += '\t';

	appendHex(line, event.svc_address);
	line += '\t';
	line += svcKindName(event.kind);
	line += '\t';
	line += columnToken(event.name);
	line += '\t';

	line += '[';
	for (size_t i = 0; i < event.args.size(); ++i)
	{
		if (i != 0)
		{
			line += ',';
		}
		std::snprintf(buffer, sizeof(buffer), "\"0x%llx\"", static_cast<unsigned long long>(event.args[i]));
		line += buffer;
	}
	line += "]\t";

	appendHex(line, event.result);
	line += '\t';

	if (event.support == SvcSupport::Supported)
	{
		line += "{}";
		return line;
	}

	if (event.support == SvcSupport::Degraded)
	{
		line += "{\"degraded\":1";
		if (!event.degraded_reason.empty())
		{
			line += ",\"reason\":";
			line += jsonString(event.degraded_reason);
		}
		line += '}';
		return line;
	}

	line += "{\"unsupported\":1";
	if (!event.stack_stop.empty())
	{
		line += ",\"stop\":";
		line += jsonString(event.stack_stop);
	}
	line += ",\"stack\":[";
	for (size_t i = 0; i < event.stack.size(); ++i)
	{
		if (i != 0)
		{
			line += ',';
		}
		line += "{\"pc\":\"";
		appendHex(line, event.stack[i].pc);
		line += "\",\"name\":";
		line += jsonString(event.stack[i].name);
		line += '}';
	}
	line += "]}";
	return line;
}

std::optional<SvcEvent> parseSvcTraceLine(std::string_view line)
{
	std::string_view fields[kFieldCount];
	if (!splitFields(line, fields))
	{
		return std::nullopt;
	}

	const auto id = parseHex(fields[0], false);
	const auto seq = parseHex(fields[1], false);
	const auto tid = parseHex(fields[2], true);
	const auto svc = parseHex(fields[3], true);
	const auto result = parseHex(fields[7], true);
	if (!id.has_value() || !seq.has_value() || !tid.has_value() || !svc.has_value() ||
		!result.has_value())
	{
		return std::nullopt;
	}

	SvcEvent event;
	event.id = id.value();
	event.seq = seq.value();
	event.tid = static_cast<uint32_t>(tid.value());
	event.svc_address = svc.value();
	event.result = result.value();

	if (!parseKind(fields[4], event.kind))
	{
		return std::nullopt;
	}
	if (fields[5].empty())
	{
		return std::nullopt;
	}
	event.name = std::string(fields[5]);
	if (!parseArgs(fields[6], event.args))
	{
		return std::nullopt;
	}
	if (!parseNote(fields[8], event))
	{
		return std::nullopt;
	}
	return event;
}

Result<std::unique_ptr<SvcTraceFile> > SvcTraceFile::open(std::string_view path)
{
	const std::string file_path(path);
	std::FILE *file = std::fopen(file_path.c_str(), "wb");
	if (file == nullptr)
	{
		return Error{ ErrorCode::NotFound, "cannot open trace file " + file_path + ": " + std::strerror(errno) };
	}
	return std::unique_ptr<SvcTraceFile>(new SvcTraceFile(file));
}

SvcTraceFile::~SvcTraceFile()
{
	if (file_ != nullptr)
	{
		std::fflush(file_);
		std::fclose(file_);
	}
}

void SvcTraceFile::write(const SvcEvent &event)
{
	buffer_.clear();
	buffer_ = formatSvcTraceLine(event);
	buffer_ += '\n';
	if (file_ != nullptr)
	{
		(void)std::fwrite(buffer_.data(), 1, buffer_.size(), file_);
		// Flushed per record: the file must be readable while the instance is
		// still alive, and the svc rate is low enough that this is free.
		std::fflush(file_);
	}
}

} // namespace duckemu::runtime::observer

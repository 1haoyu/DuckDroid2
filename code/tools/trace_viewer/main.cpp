// SPDX-License-Identifier: GPL-2.0-only
// Reader for svc.log (M2).
//
// The file is written by RuntimeInstance when RuntimeConfig.trace_path is set;
// the line format lives in runtime/observer/trace/svc_trace.hpp and this tool
// shares its parser, so there is exactly one definition of the format.
//
// Usage:
//   trace_viewer summary <file>
//   trace_viewer list <file> [--name NAME] [--tid 0xTID] [--unsupported]
//   trace_viewer stack <file> <id>

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "runtime/observer/trace/svc_trace.hpp"

using duckemu::runtime::observer::SvcEvent;
using duckemu::runtime::observer::parseSvcTraceLine;

namespace {

struct Loaded {
    std::vector<SvcEvent> records;
    size_t malformed = 0;
};

bool loadTrace(const char* path, Loaded& out) {
    std::ifstream input(path);
    if (!input) {
        std::fprintf(stderr, "trace_viewer: cannot open %s\n", path);
        return false;
    }

    std::string line;
    while (std::getline(input, line)) {
        if (line.empty()) {
            continue;
        }
        auto record = parseSvcTraceLine(line);
        if (!record.has_value()) {
            ++out.malformed;
            continue;
        }
        out.records.push_back(std::move(record).value());
    }
    return true;
}

std::string formatArgs(const SvcEvent& record) {
    std::string text = "[";
    for (size_t i = 0; i < record.args.size(); ++i) {
        if (i != 0) {
            text += ", ";
        }
        char buffer[32];
        std::snprintf(buffer, sizeof(buffer), "0x%llx",
                      static_cast<unsigned long long>(record.args[i]));
        text += buffer;
    }
    text += "]";
    return text;
}

void printRecord(const SvcEvent& record) {
    std::printf(
        "%6llu | seq %6llu | tid 0x%x | %-4s | %-12s | svc 0x%llx | args %s | ret %lld (0x%llx)\n",
        static_cast<unsigned long long>(record.id), static_cast<unsigned long long>(record.seq),
        record.tid, std::string(duckemu::runtime::observer::svcKindName(record.kind)).c_str(),
        record.name.c_str(), static_cast<unsigned long long>(record.svc_address),
        formatArgs(record).c_str(), static_cast<long long>(static_cast<int64_t>(record.result)),
        static_cast<unsigned long long>(record.result));
    for (const auto& frame : record.stack) {
        std::printf("         frame 0x%llx  %s\n",
                    static_cast<unsigned long long>(frame.pc), frame.name.c_str());
    }
    if (!record.stack_stop.empty()) {
        std::printf("         (walk stopped: %s)\n", record.stack_stop.c_str());
    }
}

int commandSummary(const char* path) {
    Loaded loaded;
    if (!loadTrace(path, loaded)) {
        return 1;
    }

    size_t unsupported = 0;
    std::map<std::string, size_t> by_name;
    std::map<uint32_t, size_t> by_tid;
    std::map<std::string, size_t> by_kind;
    for (const auto& record : loaded.records) {
        if (record.support == duckemu::runtime::observer::SvcSupport::Unsupported) {
            ++unsupported;
        }
        ++by_name[record.name];
        ++by_tid[record.tid];
        ++by_kind[std::string(duckemu::runtime::observer::svcKindName(record.kind))];
    }

    std::printf("file: %s\n", path);
    std::printf("records: %zu  unsupported: %zu  malformed lines: %zu\n", loaded.records.size(),
                unsupported, loaded.malformed);
    if (!loaded.records.empty()) {
        std::printf("id range: 0x%llx .. 0x%llx\n",
                    static_cast<unsigned long long>(loaded.records.front().id),
                    static_cast<unsigned long long>(loaded.records.back().id));
    }

    std::printf("by kind:\n");
    for (const auto& [kind, count] : by_kind) {
        std::printf("  %-6s %zu\n", kind.c_str(), count);
    }
    std::printf("by tid:\n");
    for (const auto& [tid, count] : by_tid) {
        std::printf("  0x%-6x %zu\n", tid, count);
    }
    std::printf("by name:\n");
    for (const auto& [name, count] : by_name) {
        std::printf("  %-20s %zu\n", name.c_str(), count);
    }
    return 0;
}

int commandList(const char* path, const std::optional<std::string>& name,
                const std::optional<uint32_t>& tid, bool unsupported_only) {
    Loaded loaded;
    if (!loadTrace(path, loaded)) {
        return 1;
    }

    size_t printed = 0;
    for (const auto& record : loaded.records) {
        if (name.has_value() && record.name != *name) {
            continue;
        }
        if (tid.has_value() && record.tid != *tid) {
            continue;
        }
        if (unsupported_only && record.support != duckemu::runtime::observer::SvcSupport::Unsupported) {
            continue;
        }
        printRecord(record);
        ++printed;
    }
    std::printf("%zu record(s)\n", printed);
    return 0;
}

int commandStack(const char* path, std::string_view id_text) {
    char* end = nullptr;
    const std::string text(id_text);
    const unsigned long long id = std::strtoull(text.c_str(), &end, 16);
    if (end == nullptr || *end != '\0') {
        std::fprintf(stderr, "trace_viewer: id must be hexadecimal (e.g. 3 or 0x3)\n");
        return 1;
    }

    Loaded loaded;
    if (!loadTrace(path, loaded)) {
        return 1;
    }
    for (const auto& record : loaded.records) {
        if (record.id != id) {
            continue;
        }
        printRecord(record);
        if (record.stack.empty()) {
            std::printf("no stack was captured for this record\n");
        }
        return 0;
    }
    std::fprintf(stderr, "trace_viewer: no record with id 0x%llx\n", id);
    return 1;
}

void usage() {
    std::fprintf(stderr,
                 "usage:\n"
                 "  trace_viewer summary <file>\n"
                 "  trace_viewer list <file> [--name NAME] [--tid 0xTID] [--unsupported]\n"
                 "  trace_viewer stack <file> <id>     # id is the first column of svc.log\n");
}

} // namespace

int main(int argc, char** argv) {
    if (argc < 3) {
        usage();
        return 1;
    }
    const std::string_view command = argv[1];
    const char* path = argv[2];

    if (command == "summary") {
        return commandSummary(path);
    }

    if (command == "list") {
        std::optional<std::string> name;
        std::optional<uint32_t> tid;
        bool unsupported_only = false;
        for (int i = 3; i < argc; ++i) {
            const std::string_view option = argv[i];
            if (option == "--unsupported") {
                unsupported_only = true;
            } else if (option == "--name" && i + 1 < argc) {
                name = argv[++i];
            } else if (option == "--tid" && i + 1 < argc) {
                char* end = nullptr;
                const unsigned long value = std::strtoul(argv[++i], &end, 0);
                if (end == nullptr || *end != '\0') {
                    usage();
                    return 1;
                }
                tid = static_cast<uint32_t>(value);
            } else {
                usage();
                return 1;
            }
        }
        return commandList(path, name, tid, unsupported_only);
    }

    if (command == "stack") {
        if (argc != 4) {
            usage();
            return 1;
        }
        return commandStack(path, argv[3]);
    }

    usage();
    return 1;
}

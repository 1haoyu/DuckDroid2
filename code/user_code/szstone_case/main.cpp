// SPDX-License-Identifier: GPL-2.0-only
// szstone_case: 得物 6.1.5.10 libszstone.so SzSdk.lf.
//
//   ./duckemu_szstone_case
//   ./duckemu_szstone_case --blob lf_in.bin --expect lf_out.bin
//   ./duckemu_szstone_case --trace DIR
//
// lf([BZZZ)[B is the local half of sk registration: it takes the device
// profile blob (key\x1cvalue\x1d...) and returns the /call request body. The
// captured profile and the device's own output live in assets/.

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "runtime/instance/runtime_instance.hpp"
#include "runtime/observer/semantic/jni_event.hpp"
#include "szstone_case/szstone_codec.hpp"
#include "szstone_case/szstone_env.hpp"

#ifndef DUCKEMU_ROM_BOOTSTRAP
#error "DUCKEMU_ROM_BOOTSTRAP must point at the ROM bootstrap lib directory"
#endif
#ifndef DUCKEMU_ROM_LIB64
#error "DUCKEMU_ROM_LIB64 must point at the ROM system/lib64 directory"
#endif
#ifndef DUCKEMU_SZSTONE_SO
#error "DUCKEMU_SZSTONE_SO must point at libszstone.so"
#endif
#ifndef DUCKEMU_SZSTONE_BLOB
#error "DUCKEMU_SZSTONE_BLOB must point at the captured profile blob"
#endif
#ifndef DUCKEMU_SZSTONE_EXPECT
#error "DUCKEMU_SZSTONE_EXPECT must point at the captured lf output"
#endif
#ifndef DUCKEMU_SZSTONE_ROOT
#error "DUCKEMU_SZSTONE_ROOT must point at the device snapshot root"
#endif
#ifndef DUCKEMU_SZSTONE_PROPERTIES
#error "DUCKEMU_SZSTONE_PROPERTIES must point at the device build.prop"
#endif

using namespace duckemu;
using namespace duckemu::runtime;
using namespace duckemu::user;

namespace
{

// libszstone's startup (UPX-style in-place unpack) is slower than the runtime
// default; keep the same 60 s ceiling the other real targets use.
constexpr uint64_t kCallTimeoutUs = 60ULL * 1000 * 1000;

std::string romLibc()
{
	return std::string(DUCKEMU_ROM_BOOTSTRAP) + "/libc.so";
}

bool readFile(const std::string &path, std::vector<uint8_t> *out, std::string *error)
{
	std::ifstream file(path, std::ios::binary);
	if (!file)
	{
		*error = "cannot open " + path;
		return false;
	}
	out->assign(std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>());
	return true;
}

} // namespace

int main(int argc, char **argv)
{
	std::string trace_path;
	// The bundled device snapshot first; --root appends more.
	std::vector<std::string> roots = { DUCKEMU_SZSTONE_ROOT };
	std::string blob_path = DUCKEMU_SZSTONE_BLOB;
	std::string expect_path = DUCKEMU_SZSTONE_EXPECT;
	// The real sk-registration call is lf(blob, true, true, true).
	std::array<uint64_t, 3> z = { 1, 1, 1 };
	std::optional<uint64_t> wall_time_ns;
	std::optional<uint64_t> monotonic_time_ns;
	std::optional<uint64_t> random_seed;
	if (const char *seed = std::getenv("SZSTONE_RANDOM_SEED"))
	{
		random_seed = std::strtoull(seed, nullptr, 10);
	}
	for (int index = 1; index < argc; ++index)
	{
		const std::string argument = argv[index];
		const auto needValue = [&](const char *flag) -> const char * {
			if (index + 1 >= argc)
			{
				std::fprintf(stderr, "%s needs a value\n", flag);
				return nullptr;
			}
			return argv[++index];
		};
		if (argument == "--trace")
		{
			const char *value = needValue("--trace");
			if (value == nullptr)
			{
				return 2;
			}
			trace_path = value;
			continue;
		}
		if (argument == "--root")
		{
			const char *value = needValue("--root");
			if (value == nullptr)
			{
				return 2;
			}
			roots.emplace_back(value);
			continue;
		}
		if (argument == "--blob")
		{
			const char *value = needValue("--blob");
			if (value == nullptr)
			{
				return 2;
			}
			blob_path = value;
			continue;
		}
		if (argument == "--expect")
		{
			const char *value = needValue("--expect");
			if (value == nullptr)
			{
				return 2;
			}
			expect_path = value;
			continue;
		}
		if (argument == "--z")
		{
			const char *value = needValue("--z");
			if (value == nullptr)
			{
				return 2;
			}
			if (!szstone::parseZ(value, &z))
			{
				std::fprintf(stderr, "--z must look like 0,1,0\n");
				return 2;
			}
			continue;
		}
		if (argument == "--wall-time-ns" || argument == "--monotonic-time-ns" ||
			argument == "--random-seed")
		{
			const char *value = needValue(argument.c_str());
			if (value == nullptr)
			{
				return 2;
			}
			const uint64_t parsed = std::strtoull(value, nullptr, 10);
			if (argument == "--wall-time-ns")
			{
				wall_time_ns = parsed;
			}
			else if (argument == "--monotonic-time-ns")
			{
				monotonic_time_ns = parsed;
			}
			else
			{
				random_seed = parsed;
			}
			continue;
		}
		std::fprintf(stderr,
			"usage: %s [--trace DIR] [--blob FILE] [--expect FILE] [--z a,b,c]\n"
			"\t[--wall-time-ns N] [--monotonic-time-ns N] [--random-seed N]\n",
			argv[0]);
		return 2;
	}

	if (!trace_path.empty())
	{
		std::error_code directory_error;
		std::filesystem::create_directories(trace_path, directory_error);
		if (directory_error)
		{
			std::fprintf(stderr, "cannot create trace directory %s: %s\n",
				trace_path.c_str(), directory_error.message().c_str());
			return 1;
		}
	}

	std::vector<uint8_t> blob;
	std::string error;
	if (!readFile(blob_path, &blob, &error))
	{
		std::fprintf(stderr, "%s\n", error.c_str());
		return 1;
	}
	std::vector<uint8_t> expect;
	const bool have_expect = readFile(expect_path, &expect, &error);
	if (!have_expect)
	{
		std::fprintf(stderr, "warning: %s (output will not be compared)\n",
			error.c_str());
	}

	RuntimeConfig config;
	config.library_search_paths = { DUCKEMU_ROM_BOOTSTRAP, DUCKEMU_ROM_LIB64 };
	config.trace_path = trace_path.empty() ? std::string{} : trace_path + "/svc.log";
	config.filesystem_roots = roots;
	config.property_file = DUCKEMU_SZSTONE_PROPERTIES;
	config.default_timeout_us = kCallTimeoutUs;
	config.random_seed = random_seed;
	if (const char *pid = std::getenv("SZSTONE_PID"))
	{
		config.pid = static_cast<uint32_t>(std::strtoul(pid, nullptr, 10));
	}

	auto created = RuntimeInstance::create(config);
	if (!created.ok())
	{
		std::fprintf(stderr, "RuntimeInstance::create failed: %s\n",
			created.error().message.c_str());
		return 1;
	}
	RuntimeInstance &instance = *created.value();

	if (wall_time_ns.has_value())
	{
		instance.setWallTimeNs(wall_time_ns.value());
	}
	if (monotonic_time_ns.has_value())
	{
		instance.setMonotonicTimeNs(monotonic_time_ns.value());
	}

	auto installed = instance.installJavaEnvironment(&szstone::installEnvironment);
	if (!installed.ok())
	{
		std::fprintf(stderr, "install Java environment failed: %s\n",
			installed.error().message.c_str());
		return 1;
	}

	// Strict Java world: every undeclared lookup the native makes is printed
	// instead of silently becoming null.
	uint64_t jni_events = 0;
	instance.addJniListener([&jni_events](const observer::JniEvent &event) {
		++jni_events;
		std::fprintf(stderr, "jni %s class=%s name=%s sig=%s slot=%u tid=%u\n",
			std::string(observer::jniEventKindName(event.kind)).c_str(),
			event.class_descriptor.c_str(),
			event.name.c_str(),
			event.signature.c_str(),
			event.slot,
			event.tid);
	});

	auto libc = instance.loadLibrary(romLibc());
	if (!libc.ok())
	{
		std::fprintf(stderr, "load libc failed: %s\n", libc.error().message.c_str());
		return 1;
	}
	auto module = instance.loadLibrary(DUCKEMU_SZSTONE_SO);
	if (!module.ok())
	{
		std::fprintf(stderr, "load libszstone failed: %s\n", module.error().message.c_str());
		return 1;
	}

	if (!trace_path.empty())
	{
		// Trace only the lf call, not the UPX unpack and loader work above.
		// The range is the loaded target module, computed from its handle.
		auto range = instance.moduleRange(module.value());
		if (!range.ok())
		{
			std::fprintf(stderr, "module range for trace failed: %s\n",
				range.error().message.c_str());
			return 1;
		}
		observer::InsnTraceOptions options;
		options.directory = trace_path + "/insn";
		options.begin = range.value().base;
		options.size = range.value().span;
		options.stop_at_return = true;
		auto started = instance.startInsnTrace(options);
		if (!started.ok())
		{
			std::fprintf(stderr, "start instruction trace failed: %s\n",
				started.error().message.c_str());
			return 1;
		}
	}

	const std::string_view blob_view = blob.empty()
		? std::string_view{}
		: std::string_view(reinterpret_cast<const char *>(blob.data()), blob.size());
	auto output = szstone::invokeLf(instance, blob_view, z);
	instance.stopInsnTrace();
	if (!output.ok())
	{
		std::fprintf(stderr, "SzSdk.lf failed: %s\n", output.error().message.c_str());
		return 1;
	}

	std::printf("lf in=%zu z=(%llu,%llu,%llu) out=%zu\n", blob.size(),
		static_cast<unsigned long long>(z[0]), static_cast<unsigned long long>(z[1]),
		static_cast<unsigned long long>(z[2]), output.value().size());
	std::printf("%s\n", szstone::encodeHex(output.value()).c_str());
	std::printf("jni_events=%llu\n", static_cast<unsigned long long>(jni_events));

	if (have_expect)
	{
		const bool match = output.value() == expect;
		std::printf("match_expect=%s\n", match ? "true" : "false");
		return match ? 0 : 3;
	}
	return 0;
}

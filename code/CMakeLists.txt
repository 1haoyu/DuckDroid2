# SPDX-License-Identifier: GPL-2.0-only
cmake_minimum_required(VERSION 3.20)
project(DuckDroid2 LANGUAGES C CXX)

# ---------------------------------------------------------------------------
# Global language settings
# ---------------------------------------------------------------------------
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
include(CompilerWarnings)
include(Sanitizers)

option(DUCKEMU_BUILD_TESTS "Build the test suite" ON)
option(DUCKEMU_USE_SYSTEM_UNICORN
       "Link the system libunicorn instead of code/third_party/unicorn" OFF)

# Instruction-level trace is an analysis-mode feature. It needs capstone for
# disassembly and operand access flags; production builds leave it off so the
# runtime has no extra dependency. Address hooks do not need capstone and are
# always built.
option(DUCKEMU_ENABLE_TRACE
       "Build the instruction-level trace (requires capstone >= 5)" OFF)

# GDB remote debugging (M9) is an analysis-mode feature too. It has no extra
# dependency, but it exposes arbitrary register/memory writes, so production
# builds leave it out entirely: OFF compiles debug_stub.cpp instead.
option(DUCKEMU_ENABLE_DEBUG
       "Build the GDB remote debug server (RSP)" OFF)

duckemu_setup_sanitizers()

# ---------------------------------------------------------------------------
# Unicorn
#
# The pinned submodule is the default: the design docs cite source lines from
# it, and M0 measurements must come from the same tree.
# ---------------------------------------------------------------------------
if(DUCKEMU_USE_SYSTEM_UNICORN)
  find_package(PkgConfig REQUIRED)
  pkg_check_modules(DUCKEMU_UNICORN REQUIRED IMPORTED_TARGET unicorn)
  add_library(duckemu_unicorn INTERFACE)
  target_link_libraries(duckemu_unicorn INTERFACE PkgConfig::DUCKEMU_UNICORN)
  message(STATUS "Unicorn: system library via pkg-config "
                 "(${DUCKEMU_UNICORN_VERSION})")
else()
  if(NOT EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/third_party/unicorn/uc.c")
    message(FATAL_ERROR
      "code/third_party/unicorn is missing. Run:\n"
      "  git submodule update --init code/third_party/unicorn")
  endif()

  # Keep the build minimal: the project only emulates AArch64.
  set(UNICORN_ARCH "aarch64" CACHE STRING "Unicorn architectures" FORCE)
  set(UNICORN_BUILD_TESTS OFF CACHE BOOL "" FORCE)
  set(UNICORN_INSTALL OFF CACHE BOOL "" FORCE)
  set(UNICORN_LEGACY_STATIC_ARCHIVE OFF CACHE BOOL "" FORCE)
  set(BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)
  add_subdirectory(third_party/unicorn EXCLUDE_FROM_ALL)

  add_library(duckemu_unicorn INTERFACE)
  target_link_libraries(duckemu_unicorn INTERFACE unicorn)
  target_include_directories(duckemu_unicorn INTERFACE
    "${CMAKE_CURRENT_SOURCE_DIR}/third_party/unicorn/include")
  message(STATUS "Unicorn: bundled submodule (aarch64 only)")
endif()

# ---------------------------------------------------------------------------
# Targets
# ---------------------------------------------------------------------------
find_package(Threads REQUIRED)

if(DUCKEMU_ENABLE_TRACE)
  find_package(PkgConfig REQUIRED)
  pkg_check_modules(DUCKEMU_CAPSTONE REQUIRED IMPORTED_TARGET capstone>=5)
  message(STATUS "Instruction trace: capstone ${DUCKEMU_CAPSTONE_VERSION}")
endif()

# JSON is the M7 wire format. A system package (same as DuckDroid) keeps the
# tree free of a vendored single-header dependency.
find_package(nlohmann_json 3.11 QUIET)
if(NOT nlohmann_json_FOUND)
  message(FATAL_ERROR
    "M7 requires nlohmann_json >= 3.11 (install nlohmann-json or vendor it "
    "under code/third_party)")
endif()

add_library(duckemu_common STATIC
  src/common/log/logger.cpp
  src/common/uds/socket.cpp
)
target_include_directories(duckemu_common PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/src")
duckemu_set_warnings(duckemu_common)

set(DUCKEMU_TRACE_SOURCES)
if(DUCKEMU_ENABLE_TRACE)
  list(APPEND DUCKEMU_TRACE_SOURCES
    src/runtime/observer/trace/buffered_file.cpp
    src/runtime/observer/trace/insn_decode.cpp
    src/runtime/observer/trace/insn_trace.cpp)
else()
  list(APPEND DUCKEMU_TRACE_SOURCES
    src/runtime/observer/trace/insn_trace_stub.cpp)
endif()

set(DUCKEMU_DEBUG_SOURCES)
if(DUCKEMU_ENABLE_DEBUG)
  list(APPEND DUCKEMU_DEBUG_SOURCES
    src/runtime/debug/debug_server.cpp
    src/runtime/debug/target_xml.cpp)
else()
  list(APPEND DUCKEMU_DEBUG_SOURCES
    src/runtime/debug/debug_stub.cpp)
endif()

add_library(duckemu_runtime STATIC
  src/runtime/instance/runtime_instance.cpp
  src/runtime/clock/runtime_clock.cpp
  ${DUCKEMU_DEBUG_SOURCES}
  src/runtime/jni/jni_types.cpp
  src/runtime/jni/abi/abi_adapter.cpp
  src/runtime/jni/env/jni_state.cpp
  src/runtime/jni/envs/all.cpp
  src/runtime/jni/envs/java_lang.cpp
  src/runtime/jni/envs/java_io.cpp
  src/runtime/jni/envs/java_math.cpp
  src/runtime/jni/envs/java_security.cpp
  src/runtime/jni/refs/ref_table.cpp
  src/runtime/jni/world/java_world.cpp
  src/runtime/loader/bionic/shared_globals.cpp
  src/runtime/loader/elf/elf_image.cpp
  src/runtime/loader/module_loader.cpp
  src/runtime/loader/module_registry.cpp
  src/runtime/loader/reloc/reloc_applier.cpp
  src/runtime/loader/symbol_lookup.cpp
  src/runtime/loader/virtual_modules/virtual_modules.cpp
  src/runtime/memory/address_space.cpp
  src/runtime/memory/thunk/thunk_table.cpp
  src/runtime/props/property_files.cpp
  src/runtime/props/property_image.cpp
  src/runtime/props/property_table.cpp
  src/runtime/random/random_source.cpp
  src/runtime/vfs/runtime_vfs.cpp
  src/runtime/vfs/file.cpp
  src/runtime/vfs/dir_cursor.cpp
  src/runtime/vfs/dir_file.cpp
  src/runtime/vfs/fd_table.cpp
  src/runtime/vfs/dev_file_system.cpp
  src/runtime/vfs/event_file.cpp
  src/runtime/vfs/proc_fs.cpp
  src/runtime/vfs/backend.cpp
  src/runtime/vfs/mount_table.cpp
  src/runtime/vfs/backends/host_ro_fs.cpp
  src/runtime/vfs/backends/sandbox_fs.cpp
  src/runtime/vfs/backends/overlay_fs.cpp
  src/runtime/vfs/backends/proc_fs.cpp
  src/runtime/vfs/backends/synthetic_mount_fs.cpp
  src/runtime/vfs/virtual_file_system.cpp
  src/runtime/backend/unicorn/unicorn_engine.cpp
  src/runtime/backend/unicorn/unicorn_backend.cpp
  src/runtime/backend/unicorn/unicorn_hooks.cpp
  src/runtime/observer/event_bus.cpp
  src/runtime/observer/diagnostic/guest_stack.cpp
  src/runtime/observer/hook/hook_context.cpp
  src/runtime/observer/trace/svc_trace.cpp
  ${DUCKEMU_TRACE_SOURCES}
  src/runtime/threads/tls/tls_manager.cpp
  src/runtime/threads/scheduler.cpp
  src/runtime/svc/dispatcher.cpp
  src/runtime/svc/syscall_names.cpp
  src/runtime/svc/handlers/memory_handlers.cpp
  src/runtime/svc/handlers/fs_handlers.cpp
  src/runtime/svc/handlers/event_handlers.cpp
  src/runtime/svc/handlers/misc_handlers.cpp
  src/runtime/svc/handlers/thread_handlers.cpp
)
target_include_directories(duckemu_runtime PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/src")
target_link_libraries(duckemu_runtime PUBLIC
  duckemu_common
  duckemu_unicorn
  Threads::Threads
)
if(DUCKEMU_ENABLE_TRACE)
  target_link_libraries(duckemu_runtime PUBLIC PkgConfig::DUCKEMU_CAPSTONE)
endif()
duckemu_set_warnings(duckemu_runtime)

# M7 wire protocol: framing + JSON messages. Shared by System, Worker and the
# instance processes; deliberately has no dependency on the runtime.
add_library(duckemu_protocol STATIC
  src/protocol/channel.cpp
  src/protocol/frame.cpp
  src/protocol/messages.cpp
  src/protocol/instance_messages.cpp
)
target_include_directories(duckemu_protocol PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/src")
target_link_libraries(duckemu_protocol PUBLIC
  duckemu_common
  nlohmann_json::nlohmann_json
)
duckemu_set_warnings(duckemu_protocol)

# Target projects. They link the runtime and register their Java environment
# modules at static-init time; the runtime never names a target.
add_subdirectory(user_code)

# M7 instance host: the `--instance` side of the worker. It owns the only
# RuntimeInstance in its process; the supervisor never links this path into a
# process that forks.
add_library(duckemu_worker_core STATIC
  src/worker/instance_host.cpp
  src/worker/worker_process.cpp
)
target_link_libraries(duckemu_worker_core PUBLIC
  duckemu_protocol
  duckemu_runtime
)
duckemu_set_warnings(duckemu_worker_core)

add_executable(duckemu_worker src/worker/main.cpp)
target_link_libraries(duckemu_worker PRIVATE
  duckemu_worker_core
  duckemu_user_registry
)
duckemu_set_warnings(duckemu_worker)

# M7 System: UDS gateway + worker pool. Deliberately no runtime dependency —
# the gateway never touches guest state.
add_library(duckemu_system_core STATIC
  src/system/system.cpp
  src/system/worker_pool.cpp
)
target_link_libraries(duckemu_system_core PUBLIC duckemu_protocol)
duckemu_set_warnings(duckemu_system_core)

add_executable(duckemu_system src/system/main.cpp)
target_link_libraries(duckemu_system PRIVATE duckemu_system_core)
duckemu_set_warnings(duckemu_system)

# M0 spike: deliberately flat, no runtime abstractions.
add_executable(unicorn_spike tools/spike/unicorn_spike.cpp)
target_link_libraries(unicorn_spike PRIVATE
  duckemu_common
  duckemu_unicorn
  Threads::Threads
)
duckemu_set_warnings(unicorn_spike)

# M9 P1 spike: minimal GDB RSP stub that logs every client packet. No runtime,
# no Unicorn; the fake target exists only to make a client connect and talk.
add_executable(gdb_spike tools/spike/gdb_spike.cpp)
duckemu_set_warnings(gdb_spike)

# Reads svc.log produced by any RuntimeInstance (M2).
add_executable(trace_viewer tools/trace_viewer/main.cpp)
target_link_libraries(trace_viewer PRIVATE duckemu_runtime)
duckemu_set_warnings(trace_viewer)

if(DUCKEMU_BUILD_TESTS)
  enable_testing()
  add_subdirectory(tests)
endif()

// SPDX-License-Identifier: GPL-2.0-only
#pragma once

#include <string_view>

namespace duckemu {

// Coarse error categories. Specific codes are added when a caller actually
// has to branch on them; do not pre-populate this with syscall errnos.
enum class ErrorCode : int {
    Ok = 0,
    InvalidArgument,
    NotFound,
    AlreadyExists,
    OutOfMemory,
    Unsupported,
    PermissionDenied,
    Unmapped,
    EmulationFault,
    Internal,
    // Added when the VFS became a syscall-facing component: fs_handlers has to
    // turn these back into distinct errno values.
    BadFileDescriptor,
    IsDirectory,
    NotDirectory,
    NotSeekable, // ESPIPE: a pipe/socket-like description
    WouldBlock,  // EAGAIN: the operation would have blocked
    Timeout,     // a host-initiated guest call exceeded its budget
};

constexpr std::string_view to_string(ErrorCode code) noexcept {
    switch (code) {
    case ErrorCode::Ok:
        return "ok";
    case ErrorCode::InvalidArgument:
        return "invalid-argument";
    case ErrorCode::NotFound:
        return "not-found";
    case ErrorCode::AlreadyExists:
        return "already-exists";
    case ErrorCode::OutOfMemory:
        return "out-of-memory";
    case ErrorCode::Unsupported:
        return "unsupported";
    case ErrorCode::PermissionDenied:
        return "permission-denied";
    case ErrorCode::Unmapped:
        return "unmapped";
    case ErrorCode::EmulationFault:
        return "emulation-fault";
    case ErrorCode::Internal:
        return "internal";
    case ErrorCode::BadFileDescriptor:
        return "bad-file-descriptor";
    case ErrorCode::IsDirectory:
        return "is-directory";
    case ErrorCode::NotDirectory:
        return "not-directory";
    case ErrorCode::NotSeekable:
        return "not-seekable";
    case ErrorCode::WouldBlock:
        return "would-block";
    case ErrorCode::Timeout:
        return "timeout";
    }
    return "unknown";
}

} // namespace duckemu

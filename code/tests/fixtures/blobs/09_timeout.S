// SPDX-License-Identifier: GPL-2.0-only
// A guest function that never returns. 09_call_timeout calls it with a
// short RuntimeConfig::default_timeout_us and expects ErrorCode::Timeout.
	.text
	.global _start
_start:
	b	.

// SPDX-License-Identifier: GPL-2.0-only
// One raw SVC trampoline. bionic does not export some numbers as functions
// (getdents64 is the reason this file exists), so the M10 gates issue them
// directly from the host while still crossing the guest syscall boundary.

long vfs_syscall(long number, long a0, long a1, long a2, long a3, long a4)
{
	register long x8 __asm__("x8") = number;
	register long x0 __asm__("x0") = a0;
	register long x1 __asm__("x1") = a1;
	register long x2 __asm__("x2") = a2;
	register long x3 __asm__("x3") = a3;
	register long x4 __asm__("x4") = a4;
	__asm__ volatile("svc #0"
			 : "+r"(x0)
			 : "r"(x8), "r"(x1), "r"(x2), "r"(x3), "r"(x4)
			 : "memory");
	return x0;
}

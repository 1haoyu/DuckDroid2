// SPDX-License-Identifier: GPL-2.0-only
// sched_yield(2) must actually yield the single guest CPU.
//
// x0 = shared flag page (writable), x1 = child stack top.
// The parent spins on the flag and calls sched_yield each iteration; the
// child publishes the flag and exits. Without a real yield the parent holds
// the execution lock forever and the host call times out.

	.text
	.globl _start
_start:
	mov	x19, x0			// shared flag word
	mov	x20, x1			// child stack top
	str	wzr, [x19]

	// clone(SIGCHLD|CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_THREAD,
	//       stack_top, 0, 0, 0) = 0x10f11
	movz	x0, #0x0f11
	movk	x0, #0x1, lsl #16
	mov	x1, x20
	mov	x2, #0
	mov	x3, #0
	mov	x4, #0
	mov	x8, #220
	svc	#0
	cbnz	x0, parent

child:
	mov	w1, #1
	str	w1, [x19]
	mov	x0, #0
	mov	x8, #93			// exit (this thread)
	svc	#0
	b	.

parent:
	ldr	w1, [x19]
	cbnz	w1, done
	mov	x8, #124		// sched_yield
	svc	#0
	b	parent

done:
	mov	x0, #0
	mov	x8, #94			// exit_group
	svc	#0
	b	.

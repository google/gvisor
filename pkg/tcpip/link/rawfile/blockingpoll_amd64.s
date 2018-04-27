#include "textflag.h"

// blockingPoll makes the poll() syscall while calling the version of
// entersyscall that relinquishes the P so that other Gs can run. This is meant
// to be called in cases when the syscall is expected to block.
//
// func blockingPoll(fds unsafe.Pointer, nfds int, timeout int64) (n int, err syscall.Errno)
TEXT ·blockingPoll(SB),NOSPLIT,$0-40
	CALL	runtime·entersyscallblock(SB)
	MOVQ	fds+0(FP), DI
	MOVQ	nfds+8(FP), SI
	MOVQ	timeout+16(FP), DX
	MOVQ	$0x7, AX // SYS_POLL
	SYSCALL
	CMPQ	AX, $0xfffffffffffff001
	JLS	ok
	MOVQ	$-1, n+24(FP)
	NEGQ	AX
	MOVQ	AX, err+32(FP)
	CALL	runtime·exitsyscall(SB)
	RET
ok:
	MOVQ	AX, n+24(FP)
	MOVQ	$0, err+32(FP)
	CALL	runtime·exitsyscall(SB)
	RET

// Copyright 2024 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// ...
//

//go:build loong64
// +build loong64

#include "textflag.h"

// LoongArch uses the asm-generic syscall table.
#define SYS_clock_gettime 113

// func vdsoClockGettime(clockid int32, ts *Timespec) int64
//
// On LoongArch the Go runtime does not (yet) export
// runtime.vdsoClockgettimeSym, so we take the syscall path
// unconditionally. The OJ workload is not sensitive to the extra ~50ns
// per call.
TEXT ·vdsoClockGettime(SB), NOSPLIT, $0-24
	MOVW	clockid+0(FP), R4
	MOVV	ts+8(FP), R5
	MOVV	$SYS_clock_gettime, R11
	SYSCALL
	MOVV	R4, ret+16(FP)
	RET

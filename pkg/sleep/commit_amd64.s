// Copyright 2016 The Netstack Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

#include "textflag.h"

#define preparingG 1

// See commit_noasm.go for a description of commitSleep.
//
// func commitSleep(g uintptr, waitingG *uintptr) bool
TEXT ·commitSleep(SB),NOSPLIT,$0-24
	MOVQ waitingG+8(FP), CX
	MOVQ g+0(FP), DX

	// Store the G in waitingG if it's still preparingG. If it's anything
	// else it means a waker has aborted the sleep.
	MOVQ $preparingG, AX
	LOCK
	CMPXCHGQ DX, 0(CX)

	SETEQ AX
	MOVB AX, ret+16(FP)

	RET

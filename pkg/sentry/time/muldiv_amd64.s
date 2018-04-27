// Copyright 2018 Google Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "textflag.h"

// Documentation is available in parameters.go.
//
// func muldiv64(value, multiplier, divisor uint64) (uint64, bool)
TEXT ·muldiv64(SB),NOSPLIT,$0-33
	MOVQ value+0(FP), AX
	MOVQ multiplier+8(FP), BX
	MOVQ divisor+16(FP), CX

	// Multiply AX*BX and store result in DX:AX.
	MULQ BX

	// If divisor <= (value*multiplier) / 2^64, then the division will overflow.
	//
	// (value*multiplier) / 2^64 is DX:AX >> 64, or simply DX.
	CMPQ CX, DX
	JLE overflow

	// Divide DX:AX by CX.
	DIVQ CX

	MOVQ AX, result+24(FP)
	MOVB $1, ok+32(FP)
	RET

overflow:
	MOVQ $0, result+24(FP)
	MOVB $0, ok+32(FP)
	RET

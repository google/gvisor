// Copyright 2018 The gVisor Authors.
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

#include "funcdata.h"
#include "textflag.h"

// Documentation is available in parameters.go.
//
// func muldiv64(value, multiplier, divisor uint64) (uint64, bool)
TEXT ·muldiv64(SB),NOSPLIT,$40-33
    GO_ARGS
    NO_LOCAL_POINTERS
    MOV    value+0(FP), A0
    MOV    multiplier+8(FP), A1
    MOV    divisor+16(FP), A2

    MULHU   A0, A1, A3
    MUL     A0, A1, A4

    // If divisor <= (value*multiplier) / 2^64, then the division will overflow.
    //
    // (value*multiplier) / 2^64 is A3:A4 >> 64, or simply A3.
    BGE     A3, A2, overflow

    MOV    A3, 8(SP)
    MOV    A4, 16(SP)
    MOV    A2, 24(SP)
    CALL    ·divWW(SB)
    MOV    32(SP), A0
    MOV    A0, ret+24(FP)
    MOV    $1, A0
    MOVB    A0, ret1+32(FP)
    RET

overflow:
    MOV    ZERO, ret+24(FP)
    MOVB   ZERO, ret1+32(FP)
    RET

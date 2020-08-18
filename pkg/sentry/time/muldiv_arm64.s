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
    MOVD    value+0(FP), R0
    MOVD    multiplier+8(FP), R1
    MOVD    divisor+16(FP), R2

    UMULH   R0, R1, R3
    MUL     R0, R1, R4

    CMP     R2, R3
    BHS     overflow

    MOVD    R3, 8(RSP)
    MOVD    R4, 16(RSP)
    MOVD    R2, 24(RSP)
    CALL    ·divWW(SB)
    MOVD    32(RSP), R0
    MOVD    R0, result+24(FP)
    MOVD    $1, R0
    MOVB    R0, ok+32(FP)
    RET

overflow:
    MOVD    ZR, result+24(FP)
    MOVB    ZR, ok+32(FP)
    RET

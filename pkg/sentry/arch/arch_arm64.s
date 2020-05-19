// Copyright 2020 The gVisor Authors.
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

#define FPCR_RM_RN (0x0 << 22)	// Round to Nearest(RN) mode
#define FPCR_INIT FPCR_RM_RN

// initAarch64FPState initializes floating point state.
//
// func initAarch64FPState(data *FloatingPointData)
//
TEXT ·initAarch64FPState(SB),NOSPLIT,$0-8
	MOVD $0, R0
	FMOVD R0, F0
	FMOVD R0, F1
	FMOVD R0, F2
	FMOVD R0, F3
	FMOVD R0, F4
	FMOVD R0, F5
	FMOVD R0, F6
	FMOVD R0, F7
	FMOVD R0, F8
	FMOVD R0, F9
	FMOVD R0, F10
	FMOVD R0, F11
	FMOVD R0, F12
	FMOVD R0, F13
	FMOVD R0, F14
	FMOVD R0, F15
	FMOVD R0, F16
	FMOVD R0, F17
	FMOVD R0, F18
	FMOVD R0, F19
	FMOVD R0, F20
	FMOVD R0, F21
	FMOVD R0, F22
	FMOVD R0, F23
	FMOVD R0, F24
	FMOVD R0, F25
	FMOVD R0, F26
	FMOVD R0, F27
	FMOVD R0, F28
	FMOVD R0, F29
	FMOVD R0, F30
	FMOVD R0, F31

	MSR $FPCR_INIT, FPCR
	RET

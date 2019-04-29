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

// func HostID(rax, rcx uint32) (ret0, ret1, ret2, ret3 uint32)
TEXT ·HostID(SB),$0-48
	MOVL ax+0(FP), AX
	MOVL cx+4(FP), CX
	CPUID
	MOVL AX, ret0+8(FP)
	MOVL BX, ret1+12(FP)
	MOVL CX, ret2+16(FP)
	MOVL DX, ret3+20(FP)
	RET

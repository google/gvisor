// Copyright 2019 The gVisor Authors.
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

//go:build arm64
// +build arm64

TEXT ·TrailingZeros64(SB),$0-16
  MOVD  x+0(FP), R0
  RBIT  R0, R0
  CLZ   R0, R0        // return 64 if x == 0
  MOVD  R0, ret+8(FP)
  RET

TEXT ·MostSignificantOne64(SB),$0-16
  MOVD  x+0(FP), R0
  CLZ   R0, R0        // return 64 if x == 0
  MOVD  $63, R1
  SUBS  R0, R1, R0    // ret = 63 - CLZ
  BPL   end
  MOVD  $64, R0       // x == 0
end:
  MOVD  R0, ret+8(FP)
  RET

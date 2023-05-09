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

//go:build amd64
// +build amd64

TEXT ·TrailingZeros64(SB),$0-16
  BSFQ  x+0(FP), AX
  JNZ   end
  MOVQ  $64, AX
end:
  MOVQ  AX, ret+8(FP)
  RET

TEXT ·MostSignificantOne64(SB),$0-16
  BSRQ  x+0(FP), AX
  JNZ   end
  MOVQ  $64, AX
end:
  MOVQ  AX, ret+8(FP)
  RET

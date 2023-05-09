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

#define GOID_OFFSET 152 // +checkoffset runtime g.goid

// func goid() int64
TEXT ·goid(SB),NOSPLIT,$0-8
        MOVD g, R0      // g
        MOVD GOID_OFFSET(R0), R0
        MOVD R0, ret+0(FP)
        RET

// Copyright 2024 The gVisor Authors.
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

//go:build loong64

#include "textflag.h"

#define GOID_OFFSET {{ Offset (Import "runtime") "g.goid" }}

// func goid() int64
//
// Go's LoongArch backend pins the per-goroutine `g` to $r22; the Go
// assembler exposes it via the `g` pseudo-register, so we don't need to
// hard-code the register here.
TEXT ·goid(SB),NOSPLIT,$0-8
	MOVV	g, R4
	MOVV	GOID_OFFSET(R4), R4
	MOVV	R4, ret+0(FP)
	RET

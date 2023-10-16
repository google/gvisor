// Copyright 2023 The gVisor Authors.
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

#include "textflag.h"

// func MemoryFenceReads()
TEXT ·MemoryFenceReads(SB),NOSPLIT|NOFRAME,$0-0
	// No memory fence is required on x86. However, a compiler fence is
	// required to prevent the compiler from reordering memory accesses. The Go
	// compiler will not reorder memory accesses around a call to an assembly
	// function; compare runtime.publicationBarrier.
	RET

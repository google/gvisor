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

// Halt provides the body for ring0.Halt(), which is declared as a bodyless
// function in kernel.go and referenced from defaultHooks.{KernelSyscall,
// KernelException}. On LoongArch ring0 is never engaged, so reaching this
// instruction means the program took an unrecoverable wrong turn.
TEXT ·Halt(SB), NOSPLIT, $0
	BREAK	$0
	RET

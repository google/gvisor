// Copyright 2026 The gVisor Authors.
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

//go:build riscv64
// +build riscv64

package ptrace

// PTRACE_SYSEMU and PTRACE_SYSEMU_SINGLESTEP are not yet defined in
// golang.org/x/sys/unix for riscv64. Use standard Linux values.
const (
	_PTRACE_SYSEMU            = 0x1f
	_PTRACE_SYSEMU_SINGLESTEP = 0x20
)

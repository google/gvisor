// Copyright 2021 The gVisor Authors.
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

package systrap

import (
	// Required for fact extraction.
	_ "golang.org/x/sys/unix"
	_ "gvisor.dev/gvisor/pkg/abi/linux"
)

// _NEW_STUB is the value of the BX register when a new stub thread is created.
const _NEW_STUB = 1

// _NEW_STUB is the value of the BX register when the syscall loop is executed.
const _RUN_SYSCALL_LOOP = 5
const _RUN_SECCOMP_LOOP = 6

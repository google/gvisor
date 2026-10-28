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

package sandboxposture

import (
	"unsafe"

	"golang.org/x/sys/unix"
)

// coreTag returns the core scheduling cookie of a thread.
func coreTag(tid int) (uint64, error) {
	var tag uint64
	if _, _, errno := unix.Syscall6(unix.SYS_PRCTL, unix.PR_SCHED_CORE, unix.PR_SCHED_CORE_GET, uintptr(tid), unix.PR_SCHED_CORE_SCOPE_THREAD, uintptr(unsafe.Pointer(&tag)), 0); errno != 0 {
		return 0, errno
	}
	return tag, nil
}

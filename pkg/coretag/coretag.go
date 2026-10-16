// Copyright 2022 The gVisor Authors.
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

// Package coretag implements core tagging.
package coretag

import (
	"fmt"
	"runtime"
	"syscall"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
)

// Enable core tagging and returns the created core tag. If this returns with
// no error, all threads in the current thread group will be run in a core
// tagged thread.
func Enable() (uint64, error) {
	// Pin the current goroutine to its OS thread so the thread cannot exit or
	// migrate.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// Get the exact OS Thread ID of that pinned thread. Do not use Getpid(), as
	// the goroutine may be pinned to a worker thread rather than the main thread.
	tid := unix.Gettid()

	// Create the cookie on that single thread.
	if _, _, errno := unix.Syscall6(unix.SYS_PRCTL, unix.PR_SCHED_CORE,
		unix.PR_SCHED_CORE_CREATE, uintptr(tid), linux.PR_SCHED_CORE_SCOPE_THREAD, 0, 0); errno != 0 {
		return 0, fmt.Errorf("failed to create core tag on thread %d: %w", tid, errno)
	}

	// Broadcast PR_SCHED_CORE_SHARE_FROM via AllThreadsSyscall6 referencing tid.
	// This stops the world, halts Go thread creation, and forces every existing
	// OS thread to pull the cookie from tid.
	if _, _, errno := syscall.AllThreadsSyscall6(unix.SYS_PRCTL, unix.PR_SCHED_CORE,
		unix.PR_SCHED_CORE_SHARE_FROM, uintptr(tid), linux.PR_SCHED_CORE_SCOPE_THREAD, 0, 0); errno != 0 {
		return 0, fmt.Errorf("failed to share core tag from thread %d: %w", tid, errno)
	}
	return getCoreTag(tid)
}

// Copyright 2020 The gVisor Authors.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build amd64

package sync

import (
	"sync/atomic"
)

// HaveNMSpinning is true if the IncNMSpinning and DecNMSpinning functions are
// implemented. Calls to these functions panic if HaveNMSpinning is false.
const HaveNMSpinning = true

// addrOfSpinning returns the address of runtime.sched.nmspinning.
func addrOfSpinning() *int32

// nmspinning caches addrOfSpinning.
var nmspinning = addrOfSpinning()

// IncNMSpinning increments runtime.sched.nmspinning, the runtime's count of
// the number of spinning Ms (runtime threads searching for work). As of this
// writing, a non-zero nmspinning has at least the following effects
// **globally** (throughout the process):
//
// - When a goroutine is woken, goready() => wakep() will not wake a thread to
// run it.
//
// - When a spinning thread finds a goroutine to run, resetspinning() will not
// wake a new spinning thread to continue to search for more work. Note that
// this action is critical to the work-conserving nature of the runtime.
//
// - When a thread-locked goroutine blocks in Go, handoffp() will not wake
// another thread to run other goroutines on its P's runqueue.
//
// - When sysmon decides that a goroutine in syscall.Syscall() has blocked,
// handoffp() will not wake another thread to run other goroutines on the
// blocked goroutine's P's runqueue.
//
// While it is possible to use IncNMSpinning() and DecNMSpinning() to call
// Goready() without waking a thread, there is no known way to avoid the above
// global side effects when doing so. In the worst known case, use of
// Inc/DecNMSpinning() may leave the process arbitrarily underutilized (e.g.
// with only one running thread when many goroutines are runnable and
// GOMAXPROCS is arbitrarily large), for an arbitrarily long duration (until
// the next wakep()/handoffp()/resetspinning().)
//
//go:nosplit
func IncNMSpinning() {
	atomic.AddInt32(nmspinning, 1)
}

// DecNMSpinning decrements runtime.sched.nmspinning.
//
//go:nosplit
func DecNMSpinning() {
	atomic.AddInt32(nmspinning, -1)
}

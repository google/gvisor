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

// Package pinring allows asynchronous release of
// otherwise-expensive-to-release files.
//
// In Linux, some types of files require a full RCU grace period to release,
// such as `AF_PACKET` sockets (used in gVisor userspace networking), and KVM
// VM FDs (used, unsurprisingly, by the gVisor KVM platform).
// By releasing them asynchronously, we free up the sandbox process memory
// earlier, allowing better density of sandboxes to exist.
//
// How does this work? Kernel FDs are released when the last reference holder
// loses its ref, and typically that holder is the process that pays the cost.
// However, here, we want *none* of the gVisor processes to pay the cost, so we
// use a neat trick with `io_uring`. We create a disabled `io_uring` to which
// we can pin file descriptors (in what `io_uring` calls its "fixed-file
// table"). The `io_uring` itself is useless, won't accept work (disabled
// state), and our seccomp filters won't allow `io_uring`-related syscalls
// after sandbox startup anyway. But what we want is the side-effect:
// releasing an `io_uring` with FDs pinned to it causes the release to happen
// in a kernel thread, i.e. asynchronously. Victory.
package pinring

import (
	"sync"

	"golang.org/x/sys/unix"

	"gvisor.dev/gvisor/pkg/log"
)

// A PinRing accumulates host fds to pin into a donated pin ring.
// The zero value means "no ring" and pins nothing.
type PinRing struct {
	// FD is the donated ring's FD number.
	FD int

	// mu protects the fields below.
	mu        sync.Mutex
	fds       []int32
	finalized bool
}

// Exists reports whether there is a ring to pin into.
func (r *PinRing) Exists() bool {
	// stdio FDs can never be rings, so we use this as a proxy to know if
	// we have a legit io_uring FD at `r.FD`.
	// Has the nice property that the zero value of PinRing is meaningful.
	return r != nil && r.FD >= 3
}

// Add records host FD `fd` for pinning. No-op if there is no ring.
// It duplicates `fd`, so no ownership transfer.
func (r *PinRing) Add(fd int) {
	if !r.Exists() {
		return
	}
	dup, err := unix.FcntlInt(uintptr(fd), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		log.Warningf("Pin ring: cannot dup FD %d, not pinning it: %v", fd, err)
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.finalized {
		panic("tried to pin an FD to PinRing after finalization")
	}
	r.fds = append(r.fds, int32(dup))
}

// Finalize pins the added FDs into the ring.
// No-op if there is no ring.
func (r *PinRing) Finalize() error {
	if !r.Exists() {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.finalized {
		return nil
	}
	r.finalized = true
	log.Debugf("Pin ring: finalizing with %d FDs (ring at FD %d)", len(r.fds), r.FD)
	defer unix.Close(r.FD)
	if len(r.fds) == 0 {
		return nil
	}
	err := registerFiles(r.FD, r.fds)
	for _, fd := range r.fds {
		unix.Close(int(fd))
	}
	return err
}

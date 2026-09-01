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

package sandboxsetup

import (
	"fmt"
	"structs"
	"syscall"
	"unsafe"

	"github.com/moby/sys/capability"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"

	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/timing"
)

// capHeader mirrors `struct __user_cap_header_struct`.
type capHeader struct {
	_       structs.HostLayout
	version uint32
	pid     int32
}

// capData mirrors `struct __user_cap_data_struct`.
type capData struct {
	_           structs.HostLayout
	effective   uint32
	permitted   uint32
	inheritable uint32
}

// linuxCapVer3 is the V3 capability API version (struct pair of `capData`).
const linuxCapVer3 = 0x20080522

// capsetHdr and capsetData are package-level so that their addresses are
// stable for the duration of the raw capset syscall issued on every thread
// (Did you know? Unlike stack variables, globals are never moved by the Go
// runtime.)
var (
	capsetHdr  capHeader
	capsetData [2]capData
)

// allThreadsPrctl issues `prctl(option, arg2, arg3)` on every OS thread of the
// process via `syscall.AllThreadsSyscall6`.
func allThreadsPrctl(option, arg2, arg3 uintptr) error {
	// EINVAL is ignored to mirror `capability.Apply`'s handling of unsupported caps.
	if _, _, errno := syscall.AllThreadsSyscall6(unix.SYS_PRCTL, option, arg2, arg3, 0, 0, 0); errno != 0 && errno != unix.EINVAL {
		return errno
	}
	return nil
}

// ResolvedThreadCaps is a set of capability masks resolved against the
// current process's capabilities.
type ResolvedThreadCaps struct {
	bounding, effective, permitted, inheritable, ambient uint64

	// lastCap is the highest capability number supported by the host kernel.
	lastCap capability.Cap

	// haveSetPCap is whether the effective set had `CAP_SETPCAP` at
	// resolution time. (`PR_CAPBSET_DROP` requires it.)
	haveSetPCap bool
}

// ResolveThreadCaps resolves the capability sets in the spec against the
// current process's capabilities.
//
// Precondition: procfs is mounted at `/proc`.
// This reads `/proc/self/status` and `/proc/sys/kernel/cap_last_cap`.
func ResolveThreadCaps(caps *specs.LinuxCapabilities, timer *timing.Timer) (*ResolvedThreadCaps, error) {
	curCaps, err := capability.NewPid2(0)
	if err != nil {
		return nil, err
	}
	if err := curCaps.Load(); err != nil {
		return nil, err
	}
	timer.Reached("current capabilities read")
	var r ResolvedThreadCaps
	for i, mask := range [5]*uint64{&r.bounding, &r.effective, &r.permitted, &r.inheritable, &r.ambient} {
		set, err := TrimCaps(GetCaps(AllCapTypes[i], caps), curCaps)
		if err != nil {
			return nil, err
		}
		for _, c := range set {
			*mask |= uint64(1) << uint(c)
		}
	}
	if r.lastCap, err = capability.LastCap(); err != nil {
		return nil, err
	}
	r.haveSetPCap = curCaps.Get(capability.EFFECTIVE, capability.CAP_SETPCAP)
	return &r, nil
}

// Apply applies `r` to every thread of the current process.
// May be run without procfs available.
// Fails with `ENOTSUP` in cgo builds.
func (r *ResolvedThreadCaps) Apply(timer *timing.Timer) error {
	// 1. Trim the bounding set on every thread. This must happen before
	// capset drops CAP_SETPCAP from the effective set (PR_CAPBSET_DROP
	// requires it).
	if r.haveSetPCap {
		for c := capability.Cap(0); c <= r.lastCap; c++ {
			if r.bounding&(uint64(1)<<uint(c)) != 0 {
				continue
			}
			if err := allThreadsPrctl(unix.PR_CAPBSET_DROP, uintptr(c), 0); err != nil {
				return fmt.Errorf("dropping bounding capability %v on all threads: %w", c, err)
			}
		}
	}
	timer.Reached("bounding set trimmed on all threads")

	// 2. Apply effective/permitted/inheritable via `capset(2)` on all threads.
	capsetHdr = capHeader{
		version: linuxCapVer3,
		// PID 0 means "calling thread".
		// The Go runtime will reuse this for all of its threads, so this will
		// in turn mean each Go runtime thread.
		pid: 0,
	}
	capsetData[0].effective = uint32(r.effective)
	capsetData[1].effective = uint32(r.effective >> 32)
	capsetData[0].permitted = uint32(r.permitted)
	capsetData[1].permitted = uint32(r.permitted >> 32)
	capsetData[0].inheritable = uint32(r.inheritable)
	capsetData[1].inheritable = uint32(r.inheritable >> 32)
	if _, _, errno := syscall.AllThreadsSyscall6(unix.SYS_CAPSET, uintptr(unsafe.Pointer(&capsetHdr)), uintptr(unsafe.Pointer(&capsetData[0])), 0, 0, 0, 0); errno != 0 {
		return fmt.Errorf("capset on all threads: %w", errno)
	}
	timer.Reached("capset applied on all threads")

	// 3. Ambient set: clear everything, then raise the requested caps.
	if err := allThreadsPrctl(unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_CLEAR_ALL, 0); err != nil {
		return fmt.Errorf("clearing ambient capabilities on all threads: %w", err)
	}
	for c := capability.Cap(0); c <= r.lastCap; c++ {
		if r.ambient&(uint64(1)<<uint(c)) == 0 {
			continue
		}
		if err := allThreadsPrctl(unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_RAISE, uintptr(c)); err != nil {
			return fmt.Errorf("raising ambient capability %v on all threads: %w", c, err)
		}
	}

	log.Infof("Capabilities applied to all threads: bounding=%#x effective=%#x permitted=%#x inheritable=%#x ambient=%#x",
		r.bounding, r.effective, r.permitted, r.inheritable, r.ambient)
	return nil
}

// ApplyCapsAllThreads applies the capabilities in the spec to every thread of
// the current process. Fails with `ENOTSUP` in cgo builds.
// Requires procfs to be mounted at `/proc`; see `ResolveThreadCaps` if you
// need to decouple these operations.
func ApplyCapsAllThreads(caps *specs.LinuxCapabilities, timer *timing.Timer) error {
	r, err := ResolveThreadCaps(caps, timer)
	if err != nil {
		return err
	}
	return r.Apply(timer)
}

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

// Package pac provides a helper to disable ARM64 Pointer Authentication
// (PAC) for the calling thread, used by any platform implementation that
// runs host code (Go runtime, VDSO, libc) whose PAC-signed pointers may
// cross a boundary where the verifying PAC keys differ from the signing
// PAC keys.
package pac

import (
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/hostsyscall"
)

// checkPAC returns true if the host CPU supports pointer authentication.
// It is implemented in assembly: it signs the return address with PACIASP
// and checks whether the value changed.
//
//go:nosplit
func checkPAC() bool

// addressPACKeys is the bitmask of every ARM64 address pointer
// authentication key recognised by PR_PAC_SET_ENABLED_KEYS. The generic
// authentication key (PR_PAC_APGAKEY) is NOT accepted by this prctl on
// Linux (the kernel returns EINVAL); generic auth applies only to PACGA,
// which is not used by any of the code paths this package protects
// against, so it is irrelevant here.
const addressPACKeys = unix.PR_PAC_APIAKEY | unix.PR_PAC_APIBKEY |
	unix.PR_PAC_APDAKEY | unix.PR_PAC_APDBKEY

// DisableHostPAC disables pointer authentication for the calling thread.
//
// Background: ARM64 Pointer Authentication (PAC) instructions
// (paciasp/autiasp) sign and verify pointers (typically return addresses)
// using per-process/per-thread key registers that are opaque to userspace
// and cannot be synchronized across process/thread boundaries (e.g. across
// gVisor's checkpoint/restore, which recreates the sandboxed process as a
// brand-new native process with its own freshly-randomized PAC keys, or
// across the KVM platform's guest/host EL boundary). If a pointer is signed
// under one set of PAC keys and later verified under a different set, the
// verification fails; on hosts with FEAT_FPAC this raises an immediate
// synchronous SIGILL at the autiasp instruction, rather than merely
// producing a garbage pointer.
//
// Since PAC keys are per-process secrets that cannot be read from
// userspace, there is no way to synchronize them across such boundaries.
// Instead, this disables the host's PAC keys entirely for the calling
// thread; that turns paciasp/autiasp into no-op HINT instructions, which
// removes the mismatch without requiring any cross-boundary coordination.
//
// The prctl return value is intentionally ignored: it returns EINVAL on
// kernels older than 5.13 (which lack PR_PAC_SET_ENABLED_KEYS) and on
// hardware without address authentication, both of which imply the crash
// this guards against cannot occur, so there is nothing to disable.
//
//go:nosplit
func DisableHostPAC() {
	if !checkPAC() {
		return
	}
	hostsyscall.RawSyscallErrno6(
		unix.SYS_PRCTL,
		unix.PR_PAC_SET_ENABLED_KEYS,
		addressPACKeys, // keys to modify
		0,              // 0 = disable, 1 = enable
		0, 0, 0)
}

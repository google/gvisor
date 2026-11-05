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

//go:build amd64
// +build amd64

package kvm

import (
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/ring0"
	ktime "gvisor.dev/gvisor/pkg/sentry/time"
)

// kvmGetDeviceAttr is KVM_GET_DEVICE_ATTR.
const kvmGetDeviceAttr = 0x4018aee2

// getTSCOffset returns the TSC offset that KVM applies to the vCPU.
func (c *vCPU) getTSCOffset() (uint64, error) {
	var offset uint64
	da := struct {
		flags uint32
		group uint32
		attr  uint64
		addr  unsafe.Pointer
	}{
		group: _KVM_VCPU_TSC_CTRL,
		attr:  _KVM_VCPU_TSC_OFFSET,
		addr:  unsafe.Pointer(&offset),
	}
	if _, _, errno := unix.RawSyscall(unix.SYS_IOCTL, uintptr(c.fd), kvmGetDeviceAttr, uintptr(unsafe.Pointer(&da))); errno != 0 {
		return 0, errno
	}
	return offset, nil
}

// prepareRestore applies offset to k, as a restore does to the machine that
// the sandbox created at boot.
func prepareRestore(t testHarness, k *KVM, offset uint64) {
	reused, err := k.PrepareRestore(offset)
	if err != nil {
		t.Fatalf("PrepareRestore(%d) failed: %v", offset, err)
	}
	if !reused {
		t.Fatalf("PrepareRestore(%d) refused to reuse an unused machine", offset)
	}
}

// checkShadowVDSOMappings checks that the guest page tables map the host
// [vdso] to the shadow [vdso], in the kernel page tables and in the upper
// shared page tables.
func checkShadowVDSOMappings(t *testing.T, m *machine) {
	t.Helper()
	if len(m.shadowVDSO) == 0 {
		t.Skipf("no shadow [vdso]")
	}
	shadowVirt := m.shadowVDSOVirt()
	for offset := uintptr(0); offset < uintptr(len(m.shadowVDSO)); offset += hostarch.PageSize {
		want, _, ok := translateToPhysical(shadowVirt + offset)
		if !ok {
			t.Fatalf("can't translate the shadow [vdso] address %#x", shadowVirt+offset)
		}
		lower := m.vdsoVirt + offset
		if _, got, _, _ := m.kernel.PageTables.Lookup(hostarch.Addr(lower), false); got != want {
			t.Errorf("kernel page tables map [vdso] address %#x to %#x, want %#x", lower, got, want)
		}
		upper := ring0.KernelStartAddress | lower
		if _, got, _, _ := m.upperSharedPageTables.Lookup(hostarch.Addr(upper), false); got != want {
			t.Errorf("upper shared page tables map [vdso] address %#x to %#x, want %#x", upper, got, want)
		}
	}
}

// TestShadowVDSOMappings checks that PrepareRestore maps the shadow [vdso] as
// newMachine does for a machine created with a TSC offset.
func TestShadowVDSOMappings(t *testing.T) {
	const offset = uint64(1_000_000_000_000)
	t.Run("New", func(t *testing.T) {
		kvmTestWithConfig(t, Config{TSCOffset: offset}, func(k *KVM) {
			checkShadowVDSOMappings(t, k.machine)
		}, func(*vCPU) bool {
			return false
		})
	})
	t.Run("PrepareRestore", func(t *testing.T) {
		kvmTest(t, func(k *KVM) {
			prepareRestore(t, k, offset)
			checkShadowVDSOMappings(t, k.machine)
		}, func(*vCPU) bool {
			return false
		})
	})
}

// TestPrepareRestoreTSCOffset checks that PrepareRestore applies the TSC offset
// to all vCPUs: those created before it and those created in the background
// after it.
func TestPrepareRestoreTSCOffset(t *testing.T) {
	const offset = uint64(10_000_000_000)
	kvmTest(t, func(k *KVM) {
		prepareRestore(t, k, offset)
		k.machine.waitVCPUs()
		if got := k.TSCOffset(); got != offset {
			t.Errorf("TSCOffset() = %d, want %d", got, offset)
		}
		k.machine.mu.RLock()
		defer k.machine.mu.RUnlock()
		for _, c := range k.machine.vCPUsByID[:k.machine.createdVCPUs] {
			got, err := c.getTSCOffset()
			if err == unix.ENXIO {
				t.Skipf("KVM_VCPU_TSC_OFFSET is not supported")
			}
			if err != nil {
				t.Fatalf("vCPU %d: KVM_GET_DEVICE_ATTR failed: %v", c.id, err)
			}
			if got != offset {
				t.Errorf("vCPU %d: TSC offset = %d, want %d", c.id, got, offset)
			}
		}
	}, func(*vCPU) bool {
		return false
	})
}

// TestPrepareRestoreAfterUse checks that PrepareRestore refuses to reuse a
// machine that handed out a vCPU.
func TestPrepareRestoreAfterUse(t *testing.T) {
	var k *KVM
	kvmTest(t, func(kvm *KVM) {
		k = kvm
	}, func(*vCPU) bool {
		reused, err := k.PrepareRestore(10_000_000_000)
		if err != nil {
			t.Fatalf("PrepareRestore failed: %v", err)
		}
		if reused {
			t.Errorf("PrepareRestore reused a machine that handed out a vCPU")
		}
		if got := k.TSCOffset(); got != 0 {
			t.Errorf("TSCOffset() = %d after a refused PrepareRestore, want 0", got)
		}
		return false
	})
}

// TestRdtscWithPreparedRestore is TestRdtscWithOffset for a machine that got
// its TSC offset from PrepareRestore.
func TestRdtscWithPreparedRestore(t *testing.T) {
	const offset = uint64(10_000_000_000)
	i := 0
	kvmTest(t, func(k *KVM) {
		prepareRestore(t, k, offset)
	}, func(c *vCPU) bool {
		start := uint64(ktime.Rdtsc())
		bluepill(c)
		guest := uint64(ktime.Rdtsc())
		redpill()
		end := uint64(ktime.Rdtsc())
		if start+offset > guest || guest > end+offset {
			t.Errorf("inconsistent time with offset: start+offset=%d, guest=%d, end+offset=%d", start+offset, guest, end+offset)
		}
		i++
		return i < 100
	})
}

// TestTSCDomainWithPreparedRestore is TestTSCDomainWithOffset for a machine
// that got its TSC offset from PrepareRestore.
func TestTSCDomainWithPreparedRestore(t *testing.T) {
	const offset = uint64(1_000_000_000_000)
	defer ktime.SetTSCOffset(0)
	i := 0
	kvmTest(t, func(k *KVM) {
		prepareRestore(t, k, offset)
		if err := ktime.SetTSCOffset(int64(offset)); err != nil {
			t.Fatalf("SetTSCOffset(%d) failed: %v", offset, err)
		}
	}, func(c *vCPU) bool {
		start := ktime.TSC()
		bluepill(c)
		exitsBefore := c.guestExits.Load()
		guest := ktime.TSC()
		exitsAfter := c.guestExits.Load()
		redpill()
		end := ktime.TSC()

		if exitsAfter != exitsBefore {
			t.Fatalf("iter %d: TSC() in guest mode triggered a VM exit (exitsBefore=%d, exitsAfter=%d)", i, exitsBefore, exitsAfter)
		}
		if start > guest || guest > end {
			t.Fatalf("iter %d: inconsistent TSC domains: start=%d, guest=%d, end=%d", i, start, guest, end)
		}
		i++
		return i < 100
	})
}

// TestKernelVDSOWithPreparedRestore is TestKernelVDSOWithTSCOffset for a
// machine that got its TSC offset from PrepareRestore, which maps the shadow
// [vdso] after the machine was created.
func TestKernelVDSOWithPreparedRestore(t *testing.T) {
	for _, tc := range []struct {
		name   string
		offset uint64
	}{
		{"PositiveOffset", 1_000_000_000_000},
		{"NegativeOffset", ^uint64(1_000_000_000_000) + 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const n = 50
			i, exited := 0, 0
			kvmTest(t, func(k *KVM) {
				prepareRestore(t, k, tc.offset)
				if len(k.machine.shadowVDSO) == 0 {
					t.Skipf("no shadow [vdso]")
				}
			}, func(c *vCPU) bool {
				tBefore := time.Now()
				bluepill(c)
				exitsBefore := c.guestExits.Load()
				tGuest := time.Now()
				exitsAfter := c.guestExits.Load()
				var exitDesc string
				var disallowed bool
				if exitsAfter != exitsBefore {
					exitDesc, disallowed = disallowedVDSOExit(c)
				}
				redpill()
				tAfter := time.Now()

				// See TestKernelVDSOWithTSCOffset.
				if exitsAfter != exitsBefore {
					if disallowed {
						t.Fatalf("iter %d: time.Now() in GR0 triggered VM-exit: %s", i, exitDesc)
					}
					exited++
				}
				if tGuest.Before(tBefore) || tAfter.Before(tGuest) {
					t.Fatalf("iter %d: GR0 time not monotonic with HR3: tBefore=%v, tGuest=%v, tAfter=%v", i, tBefore, tGuest, tAfter)
				}
				if wallDiff := tGuest.Round(0).Sub(tBefore.Round(0)); wallDiff < 0 || wallDiff > time.Second {
					t.Fatalf("iter %d: GR0 wall-clock time diverged from HR3: diff=%v", i, wallDiff)
				}
				i++
				return i < n
			})
			if exited == n {
				t.Errorf("time.Now() in GR0 triggered a VM-exit in all %d iterations", n)
			}
		})
	}
}

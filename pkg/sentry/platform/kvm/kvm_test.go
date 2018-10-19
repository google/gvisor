// Copyright 2018 Google LLC
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

package kvm

import (
	"math/rand"
	"reflect"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"gvisor.googlesource.com/gvisor/pkg/sentry/arch"
	"gvisor.googlesource.com/gvisor/pkg/sentry/platform"
	"gvisor.googlesource.com/gvisor/pkg/sentry/platform/kvm/testutil"
	"gvisor.googlesource.com/gvisor/pkg/sentry/platform/ring0"
	"gvisor.googlesource.com/gvisor/pkg/sentry/platform/ring0/pagetables"
	"gvisor.googlesource.com/gvisor/pkg/sentry/usermem"
)

var dummyFPState = (*byte)(arch.NewFloatingPointData())

type testHarness interface {
	Errorf(format string, args ...interface{})
	Fatalf(format string, args ...interface{})
}

func kvmTest(t testHarness, setup func(*KVM), fn func(*vCPU) bool) {
	// Create the machine.
	deviceFile, err := OpenDevice()
	if err != nil {
		t.Fatalf("error opening device file: %v", err)
	}
	k, err := New(deviceFile)
	if err != nil {
		t.Fatalf("error creating KVM instance: %v", err)
	}
	defer k.machine.Destroy()
	defer k.FileMem.Destroy()

	// Call additional setup.
	if setup != nil {
		setup(k)
	}

	var c *vCPU // For recovery.
	defer func() {
		redpill()
		if c != nil {
			k.machine.Put(c)
		}
	}()
	for {
		c = k.machine.Get()
		if !fn(c) {
			break
		}

		// We put the vCPU here and clear the value so that the
		// deferred recovery will not re-put it above.
		k.machine.Put(c)
		c = nil
	}
}

func bluepillTest(t testHarness, fn func(*vCPU)) {
	kvmTest(t, nil, func(c *vCPU) bool {
		bluepill(c)
		fn(c)
		return false
	})
}

func TestKernelSyscall(t *testing.T) {
	bluepillTest(t, func(c *vCPU) {
		redpill() // Leave guest mode.
		if got := atomic.LoadUint32(&c.state); got != vCPUUser {
			t.Errorf("vCPU not in ready state: got %v", got)
		}
	})
}

func hostFault() {
	defer func() {
		recover()
	}()
	var foo *int
	*foo = 0
}

func TestKernelFault(t *testing.T) {
	hostFault() // Ensure recovery works.
	bluepillTest(t, func(c *vCPU) {
		hostFault()
		if got := atomic.LoadUint32(&c.state); got != vCPUUser {
			t.Errorf("vCPU not in ready state: got %v", got)
		}
	})
}

func TestKernelFloatingPoint(t *testing.T) {
	bluepillTest(t, func(c *vCPU) {
		if !testutil.FloatingPointWorks() {
			t.Errorf("floating point does not work, and it should!")
		}
	})
}

func applicationTest(t testHarness, useHostMappings bool, target func(), fn func(*vCPU, *syscall.PtraceRegs, *pagetables.PageTables) bool) {
	// Initialize registers & page tables.
	var (
		regs syscall.PtraceRegs
		pt   *pagetables.PageTables
	)
	testutil.SetTestTarget(&regs, target)

	kvmTest(t, func(k *KVM) {
		// Create new page tables.
		as, _, err := k.NewAddressSpace(nil /* invalidator */)
		if err != nil {
			t.Fatalf("can't create new address space: %v", err)
		}
		pt = as.(*addressSpace).pageTables

		if useHostMappings {
			// Apply the physical mappings to these page tables.
			// (This is normally dangerous, since they point to
			// physical pages that may not exist. This shouldn't be
			// done for regular user code, but is fine for test
			// purposes.)
			applyPhysicalRegions(func(pr physicalRegion) bool {
				pt.Map(usermem.Addr(pr.virtual), pr.length, pagetables.MapOpts{
					AccessType: usermem.AnyAccess,
					User:       true,
				}, pr.physical)
				return true // Keep iterating.
			})
		}
	}, func(c *vCPU) bool {
		// Invoke the function with the extra data.
		return fn(c, &regs, pt)
	})
}

func TestApplicationSyscall(t *testing.T) {
	applicationTest(t, true, testutil.SyscallLoop, func(c *vCPU, regs *syscall.PtraceRegs, pt *pagetables.PageTables) bool {
		if _, _, err := c.SwitchToUser(ring0.SwitchOpts{
			Registers:          regs,
			FloatingPointState: dummyFPState,
			PageTables:         pt,
			FullRestore:        true,
		}); err == platform.ErrContextInterrupt {
			return true // Retry.
		} else if err != nil {
			t.Errorf("application syscall with full restore failed: %v", err)
		}
		return false
	})
	applicationTest(t, true, testutil.SyscallLoop, func(c *vCPU, regs *syscall.PtraceRegs, pt *pagetables.PageTables) bool {
		if _, _, err := c.SwitchToUser(ring0.SwitchOpts{
			Registers:          regs,
			FloatingPointState: dummyFPState,
			PageTables:         pt,
		}); err == platform.ErrContextInterrupt {
			return true // Retry.
		} else if err != nil {
			t.Errorf("application syscall with partial restore failed: %v", err)
		}
		return false
	})
}

func TestApplicationFault(t *testing.T) {
	applicationTest(t, true, testutil.Touch, func(c *vCPU, regs *syscall.PtraceRegs, pt *pagetables.PageTables) bool {
		testutil.SetTouchTarget(regs, nil) // Cause fault.
		if si, _, err := c.SwitchToUser(ring0.SwitchOpts{
			Registers:          regs,
			FloatingPointState: dummyFPState,
			PageTables:         pt,
			FullRestore:        true,
		}); err == platform.ErrContextInterrupt {
			return true // Retry.
		} else if err != platform.ErrContextSignal || (si != nil && si.Signo != int32(syscall.SIGSEGV)) {
			t.Errorf("application fault with full restore got (%v, %v), expected (%v, SIGSEGV)", err, si, platform.ErrContextSignal)
		}
		return false
	})
	applicationTest(t, true, testutil.Touch, func(c *vCPU, regs *syscall.PtraceRegs, pt *pagetables.PageTables) bool {
		testutil.SetTouchTarget(regs, nil) // Cause fault.
		if si, _, err := c.SwitchToUser(ring0.SwitchOpts{
			Registers:          regs,
			FloatingPointState: dummyFPState,
			PageTables:         pt,
		}); err == platform.ErrContextInterrupt {
			return true // Retry.
		} else if err != platform.ErrContextSignal || (si != nil && si.Signo != int32(syscall.SIGSEGV)) {
			t.Errorf("application fault with partial restore got (%v, %v), expected (%v, SIGSEGV)", err, si, platform.ErrContextSignal)
		}
		return false
	})
}

func TestRegistersSyscall(t *testing.T) {
	applicationTest(t, true, testutil.TwiddleRegsSyscall, func(c *vCPU, regs *syscall.PtraceRegs, pt *pagetables.PageTables) bool {
		testutil.SetTestRegs(regs) // Fill values for all registers.
		for {
			if _, _, err := c.SwitchToUser(ring0.SwitchOpts{
				Registers:          regs,
				FloatingPointState: dummyFPState,
				PageTables:         pt,
			}); err == platform.ErrContextInterrupt {
				continue // Retry.
			} else if err != nil {
				t.Errorf("application register check with partial restore got unexpected error: %v", err)
			}
			if err := testutil.CheckTestRegs(regs, false); err != nil {
				t.Errorf("application register check with partial restore failed: %v", err)
			}
			break // Done.
		}
		return false
	})
}

func TestRegistersFault(t *testing.T) {
	applicationTest(t, true, testutil.TwiddleRegsFault, func(c *vCPU, regs *syscall.PtraceRegs, pt *pagetables.PageTables) bool {
		testutil.SetTestRegs(regs) // Fill values for all registers.
		for {
			if si, _, err := c.SwitchToUser(ring0.SwitchOpts{
				Registers:          regs,
				FloatingPointState: dummyFPState,
				PageTables:         pt,
				FullRestore:        true,
			}); err == platform.ErrContextInterrupt {
				continue // Retry.
			} else if err != platform.ErrContextSignal || si.Signo != int32(syscall.SIGSEGV) {
				t.Errorf("application register check with full restore got unexpected error: %v", err)
			}
			if err := testutil.CheckTestRegs(regs, true); err != nil {
				t.Errorf("application register check with full restore failed: %v", err)
			}
			break // Done.
		}
		return false
	})
}

func TestSegments(t *testing.T) {
	applicationTest(t, true, testutil.TwiddleSegments, func(c *vCPU, regs *syscall.PtraceRegs, pt *pagetables.PageTables) bool {
		testutil.SetTestSegments(regs)
		for {
			if _, _, err := c.SwitchToUser(ring0.SwitchOpts{
				Registers:          regs,
				FloatingPointState: dummyFPState,
				PageTables:         pt,
				FullRestore:        true,
			}); err == platform.ErrContextInterrupt {
				continue // Retry.
			} else if err != nil {
				t.Errorf("application segment check with full restore got unexpected error: %v", err)
			}
			if err := testutil.CheckTestSegments(regs); err != nil {
				t.Errorf("application segment check with full restore failed: %v", err)
			}
			break // Done.
		}
		return false
	})
}

func TestBounce(t *testing.T) {
	applicationTest(t, true, testutil.SpinLoop, func(c *vCPU, regs *syscall.PtraceRegs, pt *pagetables.PageTables) bool {
		go func() {
			time.Sleep(time.Millisecond)
			c.BounceToKernel()
		}()
		if _, _, err := c.SwitchToUser(ring0.SwitchOpts{
			Registers:          regs,
			FloatingPointState: dummyFPState,
			PageTables:         pt,
		}); err != platform.ErrContextInterrupt {
			t.Errorf("application partial restore: got %v, wanted %v", err, platform.ErrContextInterrupt)
		}
		return false
	})
	applicationTest(t, true, testutil.SpinLoop, func(c *vCPU, regs *syscall.PtraceRegs, pt *pagetables.PageTables) bool {
		go func() {
			time.Sleep(time.Millisecond)
			c.BounceToKernel()
		}()
		if _, _, err := c.SwitchToUser(ring0.SwitchOpts{
			Registers:          regs,
			FloatingPointState: dummyFPState,
			PageTables:         pt,
			FullRestore:        true,
		}); err != platform.ErrContextInterrupt {
			t.Errorf("application full restore: got %v, wanted %v", err, platform.ErrContextInterrupt)
		}
		return false
	})
}

func TestBounceStress(t *testing.T) {
	applicationTest(t, true, testutil.SpinLoop, func(c *vCPU, regs *syscall.PtraceRegs, pt *pagetables.PageTables) bool {
		randomSleep := func() {
			// O(hundreds of microseconds) is appropriate to ensure
			// different overlaps and different schedules.
			if n := rand.Intn(1000); n > 100 {
				time.Sleep(time.Duration(n) * time.Microsecond)
			}
		}
		for i := 0; i < 1000; i++ {
			// Start an asynchronously executing goroutine that
			// calls Bounce at pseudo-random point in time.
			// This should wind up calling Bounce when the
			// kernel is in various stages of the switch.
			go func() {
				randomSleep()
				c.BounceToKernel()
			}()
			randomSleep()
			if _, _, err := c.SwitchToUser(ring0.SwitchOpts{
				Registers:          regs,
				FloatingPointState: dummyFPState,
				PageTables:         pt,
			}); err != platform.ErrContextInterrupt {
				t.Errorf("application partial restore: got %v, wanted %v", err, platform.ErrContextInterrupt)
			}
			c.unlock()
			randomSleep()
			c.lock()
		}
		return false
	})
}

func TestInvalidate(t *testing.T) {
	var data uintptr // Used below.
	applicationTest(t, true, testutil.Touch, func(c *vCPU, regs *syscall.PtraceRegs, pt *pagetables.PageTables) bool {
		testutil.SetTouchTarget(regs, &data) // Read legitimate value.
		for {
			if _, _, err := c.SwitchToUser(ring0.SwitchOpts{
				Registers:          regs,
				FloatingPointState: dummyFPState,
				PageTables:         pt,
			}); err == platform.ErrContextInterrupt {
				continue // Retry.
			} else if err != nil {
				t.Errorf("application partial restore: got %v, wanted nil", err)
			}
			break // Done.
		}
		// Unmap the page containing data & invalidate.
		pt.Unmap(usermem.Addr(reflect.ValueOf(&data).Pointer() & ^uintptr(usermem.PageSize-1)), usermem.PageSize)
		for {
			if _, _, err := c.SwitchToUser(ring0.SwitchOpts{
				Registers:          regs,
				FloatingPointState: dummyFPState,
				PageTables:         pt,
				Flush:              true,
			}); err == platform.ErrContextInterrupt {
				continue // Retry.
			} else if err != platform.ErrContextSignal {
				t.Errorf("application partial restore: got %v, wanted %v", err, platform.ErrContextSignal)
			}
			break // Success.
		}
		return false
	})
}

// IsFault returns true iff the given signal represents a fault.
func IsFault(err error, si *arch.SignalInfo) bool {
	return err == platform.ErrContextSignal && si.Signo == int32(syscall.SIGSEGV)
}

func TestEmptyAddressSpace(t *testing.T) {
	applicationTest(t, false, testutil.SyscallLoop, func(c *vCPU, regs *syscall.PtraceRegs, pt *pagetables.PageTables) bool {
		if si, _, err := c.SwitchToUser(ring0.SwitchOpts{
			Registers:          regs,
			FloatingPointState: dummyFPState,
			PageTables:         pt,
		}); err == platform.ErrContextInterrupt {
			return true // Retry.
		} else if !IsFault(err, si) {
			t.Errorf("first fault with partial restore failed got %v", err)
			t.Logf("registers: %#v", &regs)
		}
		return false
	})
	applicationTest(t, false, testutil.SyscallLoop, func(c *vCPU, regs *syscall.PtraceRegs, pt *pagetables.PageTables) bool {
		if si, _, err := c.SwitchToUser(ring0.SwitchOpts{
			Registers:          regs,
			FloatingPointState: dummyFPState,
			PageTables:         pt,
			FullRestore:        true,
		}); err == platform.ErrContextInterrupt {
			return true // Retry.
		} else if !IsFault(err, si) {
			t.Errorf("first fault with full restore failed got %v", err)
			t.Logf("registers: %#v", &regs)
		}
		return false
	})
}

func TestWrongVCPU(t *testing.T) {
	kvmTest(t, nil, func(c1 *vCPU) bool {
		kvmTest(t, nil, func(c2 *vCPU) bool {
			// Basic test, one then the other.
			bluepill(c1)
			bluepill(c2)
			if c2.switches == 0 {
				// Don't allow the test to proceed if this fails.
				t.Fatalf("wrong vCPU#2 switches: vCPU1=%+v,vCPU2=%+v", c1, c2)
			}

			// Alternate vCPUs; we expect to need to trigger the
			// wrong vCPU path on each switch.
			for i := 0; i < 100; i++ {
				bluepill(c1)
				bluepill(c2)
			}
			if count := c1.switches; count < 90 {
				t.Errorf("wrong vCPU#1 switches: vCPU1=%+v,vCPU2=%+v", c1, c2)
			}
			if count := c2.switches; count < 90 {
				t.Errorf("wrong vCPU#2 switches: vCPU1=%+v,vCPU2=%+v", c1, c2)
			}
			return false
		})
		return false
	})
	kvmTest(t, nil, func(c1 *vCPU) bool {
		kvmTest(t, nil, func(c2 *vCPU) bool {
			bluepill(c1)
			bluepill(c2)
			return false
		})
		return false
	})
}

func BenchmarkApplicationSyscall(b *testing.B) {
	var (
		i int // Iteration includes machine.Get() / machine.Put().
		a int // Count for ErrContextInterrupt.
	)
	applicationTest(b, true, testutil.SyscallLoop, func(c *vCPU, regs *syscall.PtraceRegs, pt *pagetables.PageTables) bool {
		if _, _, err := c.SwitchToUser(ring0.SwitchOpts{
			Registers:          regs,
			FloatingPointState: dummyFPState,
			PageTables:         pt,
		}); err == platform.ErrContextInterrupt {
			a++
			return true // Ignore.
		} else if err != nil {
			b.Fatalf("benchmark failed: %v", err)
		}
		i++
		return i < b.N
	})
	if a != 0 {
		b.Logf("ErrContextInterrupt occurred %d times (in %d iterations).", a, a+i)
	}
}

func BenchmarkKernelSyscall(b *testing.B) {
	// Note that the target passed here is irrelevant, we never execute SwitchToUser.
	applicationTest(b, true, testutil.Getpid, func(c *vCPU, regs *syscall.PtraceRegs, pt *pagetables.PageTables) bool {
		// iteration does not include machine.Get() / machine.Put().
		for i := 0; i < b.N; i++ {
			testutil.Getpid()
		}
		return false
	})
}

func BenchmarkWorldSwitchToUserRoundtrip(b *testing.B) {
	// see BenchmarkApplicationSyscall.
	var (
		i int
		a int
	)
	applicationTest(b, true, testutil.SyscallLoop, func(c *vCPU, regs *syscall.PtraceRegs, pt *pagetables.PageTables) bool {
		if _, _, err := c.SwitchToUser(ring0.SwitchOpts{
			Registers:          regs,
			FloatingPointState: dummyFPState,
			PageTables:         pt,
		}); err == platform.ErrContextInterrupt {
			a++
			return true // Ignore.
		} else if err != nil {
			b.Fatalf("benchmark failed: %v", err)
		}
		// This will intentionally cause the world switch. By executing
		// a host syscall here, we force the transition between guest
		// and host mode.
		testutil.Getpid()
		i++
		return i < b.N
	})
	if a != 0 {
		b.Logf("ErrContextInterrupt occurred %d times (in %d iterations).", a, a+i)
	}
}

// Copyright 2018 Google Inc.
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
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"

	"gvisor.googlesource.com/gvisor/pkg/sentry/platform/procid"
	"gvisor.googlesource.com/gvisor/pkg/sentry/platform/ring0"
	"gvisor.googlesource.com/gvisor/pkg/sentry/platform/ring0/pagetables"
	"gvisor.googlesource.com/gvisor/pkg/sentry/usermem"
	"gvisor.googlesource.com/gvisor/pkg/tmutex"
)

// machine contains state associated with the VM as a whole.
type machine struct {
	// fd is the vm fd.
	fd int

	// nextSlot is the next slot for setMemoryRegion.
	//
	// This must be accessed atomically. If nextSlot is ^uint32(0), then
	// slots are currently being updated, and the caller should retry.
	nextSlot uint32

	// kernel is the set of global structures.
	kernel *ring0.Kernel

	// mappingCache is used for mapPhysical.
	mappingCache sync.Map

	// mu protects vCPUs.
	mu sync.Mutex

	// vCPUs are the machine vCPUs.
	//
	// This is eventually keyed by system TID, but is initially indexed by
	// the negative vCPU id. This is merely an optimization, so while
	// collisions here are not possible, it wouldn't matter anyways.
	vCPUs map[uint64]*vCPU
}

const (
	// vCPUReady is the lock value for an available vCPU.
	//
	// Legal transitions: vCPUGuest (bluepill).
	vCPUReady uintptr = iota

	// vCPUGuest indicates the vCPU is in guest mode.
	//
	// Legal transition: vCPUReady (bluepill), vCPUWaiter (wait).
	vCPUGuest

	// vCPUWaiter indicates that the vCPU should be released.
	//
	// Legal transition: vCPUReady (bluepill).
	vCPUWaiter
)

// vCPU is a single KVM vCPU.
type vCPU struct {
	// CPU is the kernel CPU data.
	//
	// This must be the first element of this structure, it is referenced
	// by the bluepill code (see bluepill_amd64.s).
	ring0.CPU

	// fd is the vCPU fd.
	fd int

	// tid is the last set tid.
	tid uint64

	// switches is a count of world switches (informational only).
	switches uint32

	// faults is a count of world faults (informational only).
	faults uint32

	// state is the vCPU state; all are described above.
	state uintptr

	// runData for this vCPU.
	runData *runData

	// machine associated with this vCPU.
	machine *machine

	// mu applies across get/put; it does not protect the above.
	mu tmutex.Mutex
}

// newMachine returns a new VM context.
func newMachine(vm int, vCPUs int) (*machine, error) {
	// Create the machine.
	m := &machine{
		fd:    vm,
		vCPUs: make(map[uint64]*vCPU),
	}
	if vCPUs > _KVM_NR_VCPUS {
		// Hard cap at KVM's limit.
		vCPUs = _KVM_NR_VCPUS
	}
	if n := 2 * runtime.NumCPU(); vCPUs > n {
		// Cap at twice the number of physical cores. Otherwise we're
		// just wasting memory and thrashing. (There may be scheduling
		// issues when you've got > n active threads.)
		vCPUs = n
	}
	m.kernel = ring0.New(ring0.KernelOpts{
		PageTables: pagetables.New(m, pagetablesOpts),
	})

	// Initialize architecture state.
	if err := m.initArchState(vCPUs); err != nil {
		m.Destroy()
		return nil, err
	}

	// Create all the vCPUs.
	for id := 0; id < vCPUs; id++ {
		// Create the vCPU.
		fd, _, errno := syscall.RawSyscall(syscall.SYS_IOCTL, uintptr(vm), _KVM_CREATE_VCPU, uintptr(id))
		if errno != 0 {
			m.Destroy()
			return nil, fmt.Errorf("error creating VCPU: %v", errno)
		}
		c := &vCPU{
			fd:      int(fd),
			machine: m,
		}
		c.mu.Init()
		c.CPU.Init(m.kernel)
		c.CPU.KernelSyscall = bluepillSyscall
		c.CPU.KernelException = bluepillException
		m.vCPUs[uint64(-id)] = c // See above.

		// Ensure the signal mask is correct.
		if err := c.setSignalMask(); err != nil {
			m.Destroy()
			return nil, err
		}

		// Initialize architecture state.
		if err := c.initArchState(); err != nil {
			m.Destroy()
			return nil, err
		}

		// Map the run data.
		runData, err := mapRunData(int(fd))
		if err != nil {
			m.Destroy()
			return nil, err
		}
		c.runData = runData
	}

	// Apply the physical mappings. Note that these mappings may point to
	// guest physical addresses that are not actually available. These
	// physical pages are mapped on demand, see kernel_unsafe.go.
	applyPhysicalRegions(func(pr physicalRegion) bool {
		// Map everything in the lower half.
		m.kernel.PageTables.Map(usermem.Addr(pr.virtual), pr.length, false /* kernel */, usermem.AnyAccess, pr.physical)
		// And keep everything in the upper half.
		kernelAddr := usermem.Addr(ring0.KernelStartAddress | pr.virtual)
		m.kernel.PageTables.Map(kernelAddr, pr.length, false /* kernel */, usermem.AnyAccess, pr.physical)
		return true // Keep iterating.
	})

	// Ensure that the currently mapped virtual regions are actually
	// available in the VM. Note that this doesn't guarantee no future
	// faults, however it should guarantee that everything is available to
	// ensure successful vCPU entry.
	applyVirtualRegions(func(vr virtualRegion) {
		if excludeVirtualRegion(vr) {
			return // skip region.
		}
		for virtual := vr.virtual; virtual < vr.virtual+vr.length; {
			physical, length, ok := TranslateToPhysical(virtual)
			if !ok {
				// This must be an invalid region that was
				// knocked out by creation of the physical map.
				return
			}
			if virtual+length > vr.virtual+vr.length {
				// Cap the length to the end of the area.
				length = vr.virtual + vr.length - virtual
			}

			// Ensure the physical range is mapped.
			m.mapPhysical(physical, length)
			virtual += length
		}
	})

	// Ensure the machine is cleaned up properly.
	runtime.SetFinalizer(m, (*machine).Destroy)
	return m, nil
}

// mapPhysical checks for the mapping of a physical range, and installs one if
// not available. This attempts to be efficient for calls in the hot path.
//
// This panics on error.
func (m *machine) mapPhysical(physical, length uintptr) {
	for end := physical + length; physical < end; {
		_, physicalStart, length, ok := calculateBluepillFault(m, physical)
		if !ok {
			// Should never happen.
			panic("mapPhysical on unknown physical address")
		}

		if _, ok := m.mappingCache.LoadOrStore(physicalStart, true); !ok {
			// Not present in the cache; requires setting the slot.
			if _, ok := handleBluepillFault(m, physical); !ok {
				panic("handleBluepillFault failed")
			}
		}

		// Move to the next chunk.
		physical = physicalStart + length
	}
}

// Destroy frees associated resources.
//
// Destroy should only be called once all active users of the machine are gone.
// The machine object should not be used after calling Destroy.
//
// Precondition: all vCPUs must be returned to the machine.
func (m *machine) Destroy() {
	runtime.SetFinalizer(m, nil)

	// Destroy vCPUs.
	for _, c := range m.vCPUs {
		// Ensure the vCPU is not still running in guest mode. This is
		// possible iff teardown has been done by other threads, and
		// somehow a single thread has not executed any system calls.
		c.wait()

		// Teardown the vCPU itself.
		switch state := c.State(); state {
		case vCPUReady:
			// Note that the runData may not be mapped if an error
			// occurs during the middle of initialization.
			if c.runData != nil {
				if err := unmapRunData(c.runData); err != nil {
					panic(fmt.Sprintf("error unmapping rundata: %v", err))
				}
			}
			if err := syscall.Close(int(c.fd)); err != nil {
				panic(fmt.Sprintf("error closing vCPU fd: %v", err))
			}
		case vCPUGuest, vCPUWaiter:
			// Should never happen; waited above.
			panic("vCPU disposed in guest state")
		default:
			// Should never happen; not a valid state.
			panic(fmt.Sprintf("vCPU in invalid state: %v", state))
		}
	}

	// Release host mappings.
	if m.kernel.PageTables != nil {
		m.kernel.PageTables.Release()
	}

	// vCPUs are gone: teardown machine state.
	if err := syscall.Close(m.fd); err != nil {
		panic(fmt.Sprintf("error closing VM fd: %v", err))
	}
}

// Get gets an available vCPU.
func (m *machine) Get() (*vCPU, error) {
	runtime.LockOSThread()
	tid := procid.Current()
	m.mu.Lock()

	for {
		// Check for an exact match.
		if c := m.vCPUs[tid]; c != nil && c.mu.TryLock() {
			m.mu.Unlock()
			return c, nil
		}

		// Scan for an available vCPU.
		for origTID, c := range m.vCPUs {
			if c.LockInState(vCPUReady) {
				delete(m.vCPUs, origTID)
				m.vCPUs[tid] = c
				m.mu.Unlock()

				// We need to reload thread-local segments as
				// we have origTID != tid and the vCPU state
				// may be stale.
				c.loadSegments()
				atomic.StoreUint64(&c.tid, tid)
				return c, nil
			}
		}

		// Everything is busy executing user code (locked).
		//
		// We hold the pool lock here, so we should be able to kick something
		// out of kernel mode and have it bounce into host mode when it tries
		// to grab the vCPU again.
		for _, c := range m.vCPUs {
			if c.State() != vCPUWaiter {
				c.Bounce()
			}
		}

		// Give other threads an opportunity to run.
		yield()
	}
}

// Put puts the current vCPU.
func (m *machine) Put(c *vCPU) {
	c.Unlock()
	runtime.UnlockOSThread()
}

// State returns the current state.
func (c *vCPU) State() uintptr {
	return atomic.LoadUintptr(&c.state)
}

// Lock locks the vCPU.
func (c *vCPU) Lock() {
	c.mu.Lock()
}

// Invalidate invalidates caches.
func (c *vCPU) Invalidate() {
}

// LockInState locks the vCPU if it is in the given state and TryLock succeeds.
func (c *vCPU) LockInState(state uintptr) bool {
	if c.State() == state && c.mu.TryLock() {
		if c.State() != state {
			c.mu.Unlock()
			return false
		}
		return true
	}
	return false
}

// Unlock unlocks the given vCPU.
func (c *vCPU) Unlock() {
	// Ensure we're out of guest mode, if necessary.
	if c.State() == vCPUWaiter {
		redpill() // Force guest mode exit.
	}
	c.mu.Unlock()
}

// NotifyInterrupt implements interrupt.Receiver.NotifyInterrupt.
func (c *vCPU) NotifyInterrupt() {
	c.Bounce()
}

// pid is used below in bounce.
var pid = syscall.Getpid()

// Bounce ensures that the vCPU bounces back to the kernel.
//
// In practice, this means returning EAGAIN from running user code. The vCPU
// will be unlocked and relock, and the kernel is guaranteed to check for
// interrupt notifications (e.g. injected via Notify) and invalidations.
func (c *vCPU) Bounce() {
	for {
		if c.mu.TryLock() {
			// We know that the vCPU must be in the kernel already,
			// because the lock was not acquired. We specifically
			// don't want to call bounce in this case, because it's
			// not necessary to knock the vCPU out of guest mode.
			c.mu.Unlock()
			return
		}

		if state := c.State(); state == vCPUGuest || state == vCPUWaiter {
			// We know that the vCPU was in guest mode, so a single signal
			// interruption will guarantee that a transition takes place.
			syscall.Tgkill(pid, int(atomic.LoadUint64(&c.tid)), bounceSignal)
			return
		}

		// Someone holds the lock, but the vCPU is not yet transitioned
		// into guest mode. It's in the critical section; give it time.
		yield()
	}
}

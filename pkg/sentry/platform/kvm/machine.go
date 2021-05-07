// Copyright 2018 The gVisor Authors.
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
	"sync/atomic"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/atomicbitops"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/procid"
	"gvisor.dev/gvisor/pkg/ring0"
	"gvisor.dev/gvisor/pkg/ring0/pagetables"
	ktime "gvisor.dev/gvisor/pkg/sentry/time"
	"gvisor.dev/gvisor/pkg/sync"
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

	// upperSharedPageTables tracks the read-only shared upper of all the pagetables.
	upperSharedPageTables *pagetables.PageTables

	// kernel is the set of global structures.
	kernel ring0.Kernel

	// mu protects vCPUs.
	mu sync.RWMutex

	// available is notified when vCPUs are available.
	available sync.Cond

	// vCPUsByTID are the machine vCPUs.
	//
	// These are populated dynamically.
	vCPUsByTID map[uint64]*vCPU

	// vCPUsByID are the machine vCPUs, can be indexed by the vCPU's ID.
	vCPUsByID []*vCPU

	// maxVCPUs is the maximum number of vCPUs supported by the machine.
	maxVCPUs int

	// maxSlots is the maximum number of memory slots supported by the machine.
	maxSlots int

	// tscControl checks whether cpu supports TSC scaling
	tscControl bool

	// usedSlots is the set of used physical addresses (sorted).
	usedSlots []uintptr

	// nextID is the next vCPU ID.
	nextID uint32

	// machineArchState is the architecture-specific state.
	machineArchState
}

const (
	// vCPUReady is an alias for all the below clear.
	vCPUReady uint32 = 0

	// vCPUser indicates that the vCPU is in or about to enter user mode.
	vCPUUser uint32 = 1 << 0

	// vCPUGuest indicates the vCPU is in guest mode.
	vCPUGuest uint32 = 1 << 1

	// vCPUWaiter indicates that there is a waiter.
	//
	// If this is set, then notify must be called on any state transitions.
	vCPUWaiter uint32 = 1 << 2
)

// vCPU is a single KVM vCPU.
type vCPU struct {
	// CPU is the kernel CPU data.
	//
	// This must be the first element of this structure, it is referenced
	// by the bluepill code (see bluepill_amd64.s).
	ring0.CPU

	// id is the vCPU id.
	id int

	// fd is the vCPU fd.
	fd int

	// tid is the last set tid.
	tid uint64

	// userExits is the count of user exits.
	userExits uint64

	// guestExits is the count of guest to host world switches.
	guestExits uint64

	// faults is a count of world faults (informational only).
	faults uint32

	// state is the vCPU state.
	//
	// This is a bitmask of the three fields (vCPU*) described above.
	state uint32

	// runData for this vCPU.
	runData *runData

	// machine associated with this vCPU.
	machine *machine

	// active is the current addressSpace: this is set and read atomically,
	// it is used to elide unnecessary interrupts due to invalidations.
	active atomicAddressSpace

	// vCPUArchState is the architecture-specific state.
	vCPUArchState

	// dieState holds state related to vCPU death.
	dieState dieState
}

type dieState struct {
	// message is thrown from die.
	message string

	// guestRegs is used to store register state during vCPU.die() to prevent
	// allocation inside nosplit function.
	guestRegs userRegs
}

// newVCPU creates a returns a new vCPU.
//
// Precondition: mu must be held.
func (m *machine) newVCPU() *vCPU {
	// Create the vCPU.
	id := int(atomic.AddUint32(&m.nextID, 1) - 1)
	fd, _, errno := unix.RawSyscall(unix.SYS_IOCTL, uintptr(m.fd), _KVM_CREATE_VCPU, uintptr(id))
	if errno != 0 {
		panic(fmt.Sprintf("error creating new vCPU: %v", errno))
	}

	c := &vCPU{
		id:      id,
		fd:      int(fd),
		machine: m,
	}
	c.CPU.Init(&m.kernel, c.id, c)
	m.vCPUsByID[c.id] = c

	// Ensure the signal mask is correct.
	if err := c.setSignalMask(); err != nil {
		panic(fmt.Sprintf("error setting signal mask: %v", err))
	}

	// Map the run data.
	runData, err := mapRunData(int(fd))
	if err != nil {
		panic(fmt.Sprintf("error mapping run data: %v", err))
	}
	c.runData = runData

	// Initialize architecture state.
	if err := c.initArchState(); err != nil {
		panic(fmt.Sprintf("error initialization vCPU state: %v", err))
	}

	return c // Done.
}

// newMachine returns a new VM context.
func newMachine(vm int) (*machine, error) {
	// Create the machine.
	m := &machine{fd: vm}
	m.available.L = &m.mu

	// Pull the maximum vCPUs.
	m.getMaxVCPU()
	log.Debugf("The maximum number of vCPUs is %d.", m.maxVCPUs)
	m.vCPUsByTID = make(map[uint64]*vCPU)
	m.vCPUsByID = make([]*vCPU, m.maxVCPUs)
	m.kernel.Init(m.maxVCPUs)

	// Pull the maximum slots.
	maxSlots, _, errno := unix.RawSyscall(unix.SYS_IOCTL, uintptr(m.fd), _KVM_CHECK_EXTENSION, _KVM_CAP_MAX_MEMSLOTS)
	if errno != 0 {
		m.maxSlots = _KVM_NR_MEMSLOTS
	} else {
		m.maxSlots = int(maxSlots)
	}
	log.Debugf("The maximum number of slots is %d.", m.maxSlots)
	m.usedSlots = make([]uintptr, m.maxSlots)

	// Check TSC Scaling
	hasTSCControl, _, errno := unix.RawSyscall(unix.SYS_IOCTL, uintptr(m.fd), _KVM_CHECK_EXTENSION, _KVM_CAP_TSC_CONTROL)
	m.tscControl = errno == 0 && hasTSCControl == 1
	log.Debugf("TSC scaling support: %t.", m.tscControl)

	// Create the upper shared pagetables and kernel(sentry) pagetables.
	m.upperSharedPageTables = pagetables.New(newAllocator())
	m.mapUpperHalf(m.upperSharedPageTables)
	m.upperSharedPageTables.Allocator.(*allocator).base.Drain()
	m.upperSharedPageTables.MarkReadOnlyShared()
	m.kernel.PageTables = pagetables.NewWithUpper(newAllocator(), m.upperSharedPageTables, ring0.KernelStartAddress)

	// Apply the physical mappings. Note that these mappings may point to
	// guest physical addresses that are not actually available. These
	// physical pages are mapped on demand, see kernel_unsafe.go.
	applyPhysicalRegions(func(pr physicalRegion) bool {
		// Map everything in the lower half.
		m.kernel.PageTables.Map(
			hostarch.Addr(pr.virtual),
			pr.length,
			pagetables.MapOpts{AccessType: hostarch.AnyAccess},
			pr.physical)

		return true // Keep iterating.
	})

	var physicalRegionsReadOnly []physicalRegion
	var physicalRegionsAvailable []physicalRegion

	physicalRegionsReadOnly = rdonlyRegionsForSetMem()
	physicalRegionsAvailable = availableRegionsForSetMem()

	// Map all read-only regions.
	for _, r := range physicalRegionsReadOnly {
		m.mapPhysical(r.physical, r.length, physicalRegionsReadOnly, _KVM_MEM_READONLY)
	}

	// Ensure that the currently mapped virtual regions are actually
	// available in the VM. Note that this doesn't guarantee no future
	// faults, however it should guarantee that everything is available to
	// ensure successful vCPU entry.
	applyVirtualRegions(func(vr virtualRegion) {
		if excludeVirtualRegion(vr) {
			return // skip region.
		}

		for _, r := range physicalRegionsReadOnly {
			if vr.virtual == r.virtual {
				return
			}
		}

		for virtual := vr.virtual; virtual < vr.virtual+vr.length; {
			physical, length, ok := translateToPhysical(virtual)
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
			m.mapPhysical(physical, length, physicalRegionsAvailable, _KVM_MEM_FLAGS_NONE)
			virtual += length
		}
	})

	// Initialize architecture state.
	if err := m.initArchState(); err != nil {
		m.Destroy()
		return nil, err
	}

	// Ensure the machine is cleaned up properly.
	runtime.SetFinalizer(m, (*machine).Destroy)
	return m, nil
}

// hasSlot returns true iff the given address is mapped.
//
// This must be done via a linear scan.
//
//go:nosplit
func (m *machine) hasSlot(physical uintptr) bool {
	for i := 0; i < len(m.usedSlots); i++ {
		if p := atomic.LoadUintptr(&m.usedSlots[i]); p == physical {
			return true
		}
	}
	return false
}

// mapPhysical checks for the mapping of a physical range, and installs one if
// not available. This attempts to be efficient for calls in the hot path.
//
// This panics on error.
//
//go:nosplit
func (m *machine) mapPhysical(physical, length uintptr, phyRegions []physicalRegion, flags uint32) {
	for end := physical + length; physical < end; {
		_, physicalStart, length, ok := calculateBluepillFault(physical, phyRegions)
		if !ok {
			// Should never happen.
			panic("mapPhysical on unknown physical address")
		}

		// Is this already mapped? Check the usedSlots.
		if !m.hasSlot(physicalStart) {
			if _, ok := handleBluepillFault(m, physical, phyRegions, flags); !ok {
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
	for _, c := range m.vCPUsByID {
		if c == nil {
			continue
		}

		// Ensure the vCPU is not still running in guest mode. This is
		// possible iff teardown has been done by other threads, and
		// somehow a single thread has not executed any system calls.
		c.BounceToHost()

		// Note that the runData may not be mapped if an error occurs
		// during the middle of initialization.
		if c.runData != nil {
			if err := unmapRunData(c.runData); err != nil {
				panic(fmt.Sprintf("error unmapping rundata: %v", err))
			}
		}
		if err := unix.Close(int(c.fd)); err != nil {
			panic(fmt.Sprintf("error closing vCPU fd: %v", err))
		}
	}

	// vCPUs are gone: teardown machine state.
	if err := unix.Close(m.fd); err != nil {
		panic(fmt.Sprintf("error closing VM fd: %v", err))
	}
}

// Get gets an available vCPU.
//
// This will return with the OS thread locked.
//
// It is guaranteed that if any OS thread TID is in guest, m.vCPUs[TID] points
// to the vCPU in which the OS thread TID is running. So if Get() returns with
// the corrent context in guest, the vCPU of it must be the same as what
// Get() returns.
func (m *machine) Get() *vCPU {
	m.mu.RLock()
	runtime.LockOSThread()
	tid := procid.Current()

	// Check for an exact match.
	if c := m.vCPUsByTID[tid]; c != nil {
		c.lock()
		m.mu.RUnlock()
		return c
	}

	// The happy path failed. We now proceed to acquire an exclusive lock
	// (because the vCPU map may change), and scan all available vCPUs.
	// In this case, we first unlock the OS thread. Otherwise, if mu is
	// not available, the current system thread will be parked and a new
	// system thread spawned. We avoid this situation by simply refreshing
	// tid after relocking the system thread.
	m.mu.RUnlock()
	runtime.UnlockOSThread()
	m.mu.Lock()
	runtime.LockOSThread()
	tid = procid.Current()

	// Recheck for an exact match.
	if c := m.vCPUsByTID[tid]; c != nil {
		c.lock()
		m.mu.Unlock()
		return c
	}

	for {
		// Scan for an available vCPU.
		for origTID, c := range m.vCPUsByTID {
			if atomic.CompareAndSwapUint32(&c.state, vCPUReady, vCPUUser) {
				delete(m.vCPUsByTID, origTID)
				m.vCPUsByTID[tid] = c
				m.mu.Unlock()
				c.loadSegments(tid)
				return c
			}
		}

		// Get a new vCPU (maybe).
		if c := m.getNewVCPU(); c != nil {
			c.lock()
			m.vCPUsByTID[tid] = c
			m.mu.Unlock()
			c.loadSegments(tid)
			return c
		}

		// Scan for something not in user mode.
		for origTID, c := range m.vCPUsByTID {
			if !atomic.CompareAndSwapUint32(&c.state, vCPUGuest, vCPUGuest|vCPUWaiter) {
				continue
			}

			// The vCPU is not be able to transition to
			// vCPUGuest|vCPUWaiter or to vCPUUser because that
			// transition requires holding the machine mutex, as we
			// do now. There is no path to register a waiter on
			// just the vCPUReady state.
			for {
				c.waitUntilNot(vCPUGuest | vCPUWaiter)
				if atomic.CompareAndSwapUint32(&c.state, vCPUReady, vCPUUser) {
					break
				}
			}

			// Steal the vCPU.
			delete(m.vCPUsByTID, origTID)
			m.vCPUsByTID[tid] = c
			m.mu.Unlock()
			c.loadSegments(tid)
			return c
		}

		// Everything is executing in user mode. Wait until something
		// is available.  Note that signaling the condition variable
		// will have the extra effect of kicking the vCPUs out of guest
		// mode if that's where they were.
		m.available.Wait()
	}
}

// Put puts the current vCPU.
func (m *machine) Put(c *vCPU) {
	c.unlock()
	runtime.UnlockOSThread()

	m.mu.RLock()
	m.available.Signal()
	m.mu.RUnlock()
}

// newDirtySet returns a new dirty set.
func (m *machine) newDirtySet() *dirtySet {
	return &dirtySet{
		vCPUMasks: make([]uint64, (m.maxVCPUs+63)/64, (m.maxVCPUs+63)/64),
	}
}

// dropPageTables drops cached page table entries.
func (m *machine) dropPageTables(pt *pagetables.PageTables) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Clear from all PCIDs.
	for _, c := range m.vCPUsByID {
		if c != nil && c.PCIDs != nil {
			c.PCIDs.Drop(pt)
		}
	}
}

// lock marks the vCPU as in user mode.
//
// This should only be called directly when known to be safe, i.e. when
// the vCPU is owned by the current TID with no chance of theft.
//
//go:nosplit
func (c *vCPU) lock() {
	atomicbitops.OrUint32(&c.state, vCPUUser)
}

// unlock clears the vCPUUser bit.
//
//go:nosplit
func (c *vCPU) unlock() {
	if atomic.CompareAndSwapUint32(&c.state, vCPUUser|vCPUGuest, vCPUGuest) {
		// Happy path: no exits are forced, and we can continue
		// executing on our merry way with a single atomic access.
		return
	}

	// Clear the lock.
	origState := atomic.LoadUint32(&c.state)
	atomicbitops.AndUint32(&c.state, ^vCPUUser)
	switch origState {
	case vCPUUser:
		// Normal state.
	case vCPUUser | vCPUGuest | vCPUWaiter:
		// Force a transition: this must trigger a notification when we
		// return from guest mode. We must clear vCPUWaiter here
		// anyways, because BounceToKernel will force a transition only
		// from ring3 to ring0, which will not clear this bit. Halt may
		// workaround the issue, but if there is no exception or
		// syscall in this period, BounceToKernel will hang.
		atomicbitops.AndUint32(&c.state, ^vCPUWaiter)
		c.notify()
	case vCPUUser | vCPUWaiter:
		// Waiting for the lock to be released; the responsibility is
		// on us to notify the waiter and clear the associated bit.
		atomicbitops.AndUint32(&c.state, ^vCPUWaiter)
		c.notify()
	default:
		panic("invalid state")
	}
}

// NotifyInterrupt implements interrupt.Receiver.NotifyInterrupt.
//
//go:nosplit
func (c *vCPU) NotifyInterrupt() {
	c.BounceToKernel()
}

// pid is used below in bounce.
var pid = unix.Getpid()

// bounce forces a return to the kernel or to host mode.
//
// This effectively unwinds the state machine.
func (c *vCPU) bounce(forceGuestExit bool) {
	origGuestExits := atomic.LoadUint64(&c.guestExits)
	origUserExits := atomic.LoadUint64(&c.userExits)
	for {
		switch state := atomic.LoadUint32(&c.state); state {
		case vCPUReady, vCPUWaiter:
			// There is nothing to be done, we're already in the
			// kernel pre-acquisition. The Bounce criteria have
			// been satisfied.
			return
		case vCPUUser:
			// We need to register a waiter for the actual guest
			// transition. When the transition takes place, then we
			// can inject an interrupt to ensure a return to host
			// mode.
			atomic.CompareAndSwapUint32(&c.state, state, state|vCPUWaiter)
		case vCPUUser | vCPUWaiter:
			// Wait for the transition to guest mode. This should
			// come from the bluepill handler.
			c.waitUntilNot(state)
		case vCPUGuest, vCPUUser | vCPUGuest:
			if state == vCPUGuest && !forceGuestExit {
				// The vCPU is already not acquired, so there's
				// no need to do a fresh injection here.
				return
			}
			// The vCPU is in user or kernel mode. Attempt to
			// register a notification on change.
			if !atomic.CompareAndSwapUint32(&c.state, state, state|vCPUWaiter) {
				break // Retry.
			}
			for {
				// We need to spin here until the signal is
				// delivered, because Tgkill can return EAGAIN
				// under memory pressure. Since we already
				// marked ourselves as a waiter, we need to
				// ensure that a signal is actually delivered.
				if err := unix.Tgkill(pid, int(atomic.LoadUint64(&c.tid)), bounceSignal); err == nil {
					break
				} else if err.(unix.Errno) == unix.EAGAIN {
					continue
				} else {
					// Nothing else should be returned by tgkill.
					panic(fmt.Sprintf("unexpected tgkill error: %v", err))
				}
			}
		case vCPUGuest | vCPUWaiter, vCPUUser | vCPUGuest | vCPUWaiter:
			if state == vCPUGuest|vCPUWaiter && !forceGuestExit {
				// See above.
				return
			}
			// Wait for the transition. This again should happen
			// from the bluepill handler, but on the way out.
			c.waitUntilNot(state)
		default:
			// Should not happen: the above is exhaustive.
			panic("invalid state")
		}

		// Check if we've missed the state transition, but
		// we can safely return at this point in time.
		newGuestExits := atomic.LoadUint64(&c.guestExits)
		newUserExits := atomic.LoadUint64(&c.userExits)
		if newUserExits != origUserExits && (!forceGuestExit || newGuestExits != origGuestExits) {
			return
		}
	}
}

// BounceToKernel ensures that the vCPU bounces back to the kernel.
//
//go:nosplit
func (c *vCPU) BounceToKernel() {
	c.bounce(false)
}

// BounceToHost ensures that the vCPU is in host mode.
//
//go:nosplit
func (c *vCPU) BounceToHost() {
	c.bounce(true)
}

// setSystemTimeLegacy calibrates and sets an approximate system time.
func (c *vCPU) setSystemTimeLegacy() error {
	const minIterations = 10
	minimum := uint64(0)
	for iter := 0; ; iter++ {
		// Try to set the TSC to an estimate of where it will be
		// on the host during a "fast" system call iteration.
		start := uint64(ktime.Rdtsc())
		if err := c.setTSC(start + (minimum / 2)); err != nil {
			return err
		}
		// See if this is our new minimum call time. Note that this
		// serves two functions: one, we make sure that we are
		// accurately predicting the offset we need to set. Second, we
		// don't want to do the final set on a slow call, which could
		// produce a really bad result.
		end := uint64(ktime.Rdtsc())
		if end < start {
			continue // Totally bogus: unstable TSC?
		}
		current := end - start
		if current < minimum || iter == 0 {
			minimum = current // Set our new minimum.
		}
		// Is this past minIterations and within ~10% of minimum?
		upperThreshold := (((minimum << 3) + minimum) >> 3)
		if iter >= minIterations && current <= upperThreshold {
			return nil
		}
	}
}

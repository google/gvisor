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

package slimvm

import (
	"fmt"
	"runtime"
	"sync"
	"syscall"

	"gvisor.dev/gvisor/pkg/atomicbitops"
	"gvisor.dev/gvisor/pkg/bitmap"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/hosttid"
	"gvisor.dev/gvisor/pkg/ring0"
	"gvisor.dev/gvisor/pkg/ring0/pagetables"
)

// machine contains state associated with the VM as a whole.
type machine struct {
	// upperSharedPageTables tracks the read-only shared upper of all the pagetables.
	upperSharedPageTables *pagetables.PageTables

	// kernel is the set of global structures.
	kernel ring0.Kernel

	// mappingCache is used for mapPhysical.
	mappingCache sync.Map

	// mu protects vCPUs.
	mu sync.RWMutex

	// available is notified when vCPUs are available.
	available sync.Cond

	// vCPUs are the machine vCPUs.
	//
	// These are populated dynamically.
	vCPUs map[uint64]*vCPU

	// allocatedVCPUIDs tracks IDs assigned to active vCPUs.
	// It is protected by mu.
	allocatedVCPUIDs bitmap.Bitmap

	// maxVCPUs is the maximum number of vCPUs, set by getMaxVCPU. vCPUs are
	// created lazily up to this limit.
	maxVCPUs int

	// applicationCores is used to compute maxVCPUs.
	applicationCores int

	memoryRegions []userMemoryRegion

	// sandboxID is the sandbox identifier passed to the host kernel module.
	sandboxID int64
}

type slimvmConfig struct {
	userRegs          userRegs
	sysRegs           systemRegs
	sandboxID         int64
	status            int64
	vcpu              uint64
	pagefaultPhysical uint64
	memoryRegionNum   uint64
	memoryRegionAddr  uintptr
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

// vCPU is a single SlimVM vCPU.
type vCPU struct {
	// CPU is the kernel CPU data.
	//
	// This must be the first element of this structure, it is referenced
	// by the bluepill code (see bluepill_amd64.s).
	ring0.CPU

	// id is the vCPU id.
	id int

	// tid is the last set tid.
	tid atomicbitops.Uint64

	// userExits is the count of user exits.
	userExits atomicbitops.Uint64

	// guestExits is the count of guest to host world switches.
	guestExits atomicbitops.Uint64

	// state is the vCPU state.
	//
	// This is a bitmask of the three fields (vCPU*) described above.
	state atomicbitops.Uint32

	vmxConfig slimvmConfig

	// machine associated with this vCPU.
	machine *machine

	// active is the current addressSpace: this is set and read atomically,
	// it is used to elide unnecessary interrupts due to invalidations.
	active atomicAddressSpace

	// vCPUArchState is the architecture-specific state.
	vCPUArchState

	// active PCIDs on this vCPU.
	activePCIDs pcidBitmap

	// CPUID Faulting enable flag.
	cpuidFaultingEnable int

	// Count the OOM happened recently.
	OOMCount  int
	OOMLastTS int64

	// FullRestore indicates whether this vCPU need
	// iret-based restore before enter guest.
	FullRestore bool
}

// newVCPU creates and returns a new vCPU. It returns nil when the per-machine
// vCPU limit (m.maxVCPUs) is exhausted.
//
// Precondtion: mu must be held.
func (m *machine) newVCPU() *vCPU {
	id, ok := m.allocateVCPUID()
	if !ok {
		return nil
	}
	allocatedID := true
	defer func() {
		if allocatedID {
			m.freeVCPUID(id)
		}
	}()

	// Create the vCPU.
	c := &vCPU{
		machine: m,
		id:      id,
	}
	c.CPU.Init(&m.kernel, c.id, c)

	// SlimVM platform support VMCALL
	c.CPU.EnableVMCALL()

	// Ensure the signal mask is correct.
	if err := c.setSignalMask(); err != nil {
		panic(fmt.Sprintf("error setting signal mask: %v", err))
	}

	// Initialize architecture state.
	if err := c.initArchState(); err != nil {
		panic(fmt.Sprintf("error initialization vCPU state: %v", err))
	}

	hostID, errno := c.createVCPU(m.memoryRegions)
	if errno != 0 {
		panic(fmt.Sprintf("error creating new vCPU: %v", errno))
	}

	c.vmxConfig.vcpu = uint64(hostID)

	c.vmxConfig.sandboxID = m.sandboxID

	allocatedID = false
	return c // Done.
}

// allocateVCPUID allocates an unused vCPU ID, bounded by m.maxVCPUs.
//
// Precondition: mu must be held.
func (m *machine) allocateVCPUID() (int, bool) {
	id, err := m.allocatedVCPUIDs.FirstZero(0)
	if err != nil || id >= uint32(m.maxVCPUs) {
		return 0, false
	}
	m.allocatedVCPUIDs.Add(id)
	return int(id), true
}

// freeVCPUID releases a vCPU ID after the vCPU is destroyed.
//
// Precondition: mu must be held.
func (m *machine) freeVCPUID(id int) {
	if id < 0 || id >= _SLIMVM_NR_VCPUS {
		panic(fmt.Sprintf("invalid vCPU ID: %d", id))
	}
	m.allocatedVCPUIDs.Remove(uint32(id))
}

// newMachine returns a new VM context.
func newMachine(sandboxID int64, applicationCores int) (*machine, error) {
	// Create the machine.
	m := &machine{
		vCPUs:            make(map[uint64]*vCPU),
		allocatedVCPUIDs: bitmap.New(_SLIMVM_NR_VCPUS),
		sandboxID:        sandboxID,
		applicationCores: applicationCores,
	}
	m.available.L = &m.mu

	// The ID bitmap is sized at the _SLIMVM_NR_VCPUS hard cap, which bounds
	// maxVCPUs, so any allocated ID always fits.
	m.getMaxVCPU()

	m.kernel.Init(m.maxVCPUs)

	// Create the upper shared pagetables and kernel(sentry) pagetables.
	m.upperSharedPageTables = pagetables.New(newAllocator())
	m.mapUpperHalf(m.upperSharedPageTables)
	m.upperSharedPageTables.Allocator.(allocator).base.Drain()
	m.upperSharedPageTables.MarkReadOnlyShared()
	m.kernel.PageTables = pagetables.NewWithUpper(newAllocator(), m.upperSharedPageTables, ring0.KernelStartAddress)

	// Apply the physical mappings. Note that these mappings may point to
	// guest physical addresses that are not actually available. These
	// physical pages are mapped on demand, see bluepill_unsafe.go.
	applyPhysicalRegions(func(pr physicalRegion) bool {
		// Map everything in the lower half.
		m.kernel.PageTables.Map(
			hostarch.Addr(pr.virtual),
			pr.length,
			pagetables.MapOpts{AccessType: hostarch.AnyAccess},
			pr.physical)

		m.mapPhysical(pr.physical, pr.length)

		return true // Keep iterating.
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

// mapPhysical checks for the mapping of a physical range, and installs one if
// not available. This attempts to be efficient for calls in the hot path.
//
// This panics on error.
func (m *machine) mapPhysical(physical, length uintptr) {
	for end := physical + length; physical < end; {
		virtualStart, physicalStart, length, ok := calculateBluepillFault(physical)
		if !ok {
			// Should never happen.
			panic("mapPhysical on unknown physical address")
		}

		if _, ok := m.mappingCache.LoadOrStore(physicalStart, true); !ok {
			// Not present in the cache; requires setting the slot.
			m.memoryRegions = append(m.memoryRegions, userMemoryRegion{
				guestPhysAddr: uint64(physicalStart),
				memorySize:    uint64(length),
				userspaceAddr: uint64(virtualStart),
			})
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

	// Disable VMCALL forwarding before bouncing. A vCPU parked in guest
	// mode inside a VMCALL-forwarded blocking syscall (e.g. a Go runtime
	// futex) cannot be bounced out: the bounce signal only interrupts the
	// forwarded syscall, which is retried via VMCALL and re-parks, so
	// BounceToHost would spin forever. Disabling VMCALL forces the retry
	// down the HLT path, yielding a real VM exit back to host.
	for _, c := range m.vCPUs {
		c.CPU.DisableVMCALL()
	}

	// Destroy vCPUs.
	for _, c := range m.vCPUs {
		// Ensure the vCPU is not still running in guest mode. This is
		// possible iff teardown has been done by other threads, and
		// somehow a single thread has not executed any system calls.
		c.BounceToHost()
	}

	// vCPUs are gone: teardown machine state.
	if err := slimvmFile.Close(); err != nil {
		panic(fmt.Sprintf("error closing VM fd: %v", err))
	}
}

// Get gets an available vCPU.
func (m *machine) Get() *vCPU {
	m.mu.RLock()
	runtime.LockOSThread()
	tid := hosttid.Current()

	// Check for an exact match.
	if c := m.vCPUs[tid]; c != nil {
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
	tid = hosttid.Current()

	// Check for an exact match again, as we may have switched to another
	// thread now.
	if c := m.vCPUs[tid]; c != nil {
		c.lock()
		m.mu.Unlock()
		return c
	}

	for {
		// Create a new vCPU (lazily) until we reach the limit.
		if c := m.newVCPU(); c != nil {
			c.lock()
			m.vCPUs[tid] = c
			m.mu.Unlock()
			c.loadSegments(tid)
			return c
		}

		// At the limit: steal an idle (vCPUReady) vCPU from another tid,
		// rebinding it to ours.
		for origTID, c := range m.vCPUs {
			if c.state.CompareAndSwap(vCPUReady, vCPUUser) {
				delete(m.vCPUs, origTID)
				m.vCPUs[tid] = c
				m.mu.Unlock()
				c.loadSegments(tid)
				return c
			}
		}

		// Nothing available; wait for a Put to signal.
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
	origState := atomicbitops.CompareAndSwapUint32(&c.state, vCPUUser|vCPUGuest, vCPUGuest)
	if origState == vCPUUser|vCPUGuest {
		// Happy path: no exits are forced, and we can continue
		// executing on our merry way with a single atomic access.
		return
	}

	// Clear the lock.
	for {
		state := atomicbitops.CompareAndSwapUint32(&c.state, origState, origState&^vCPUUser)
		if state == origState {
			break
		}
		origState = state
	}
	switch origState {
	case vCPUUser:
		// Normal state.
	case vCPUUser | vCPUGuest | vCPUWaiter:
		// Force a transition: this must trigger a notification when we
		// return from guest mode.
		// Mainly for BounceToKernel which will make vCPU quit from guest
		// ring3 to guest ring0, we need clear vCPUWaiter bit here, cause
		// when next time this vCPU enter guest ring3, bit of vCPUWaiter
		// may not be cleard, this will cause the following BounceToKernel
		// to this vCPU hang at waitUntilNot.
		// Halt may workaroud this issue, because halt process will reset
		// vCPU status into vCPUUser, and notify all waiter for vCPU state
		// change, but if there is no exception or syscall in this period,
		// BounceToKernel will hang at waitUntilNot.
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
var pid = syscall.Getpid()

func (c *vCPU) sendSignal() {
	for {
		// We need to spin here until the signal is
		// delivered, because Tgkill can return EAGAIN
		// under memory pressure. Since we already
		// marked ourselves as a waiter, we need to
		// ensure that a signal is actually delivered.
		c.PrefaultIDT()
		if err := syscall.Tgkill(pid, int(c.tid.Load()), bounceSignal); err == nil {
			break
		} else if err.(syscall.Errno) == syscall.EAGAIN {
			continue
		} else if err.(syscall.Errno) == syscall.ESRCH {
			// The target thread has already exited. Unlike KVM, a
			// SlimVM vCPU is bound to whichever host thread last ran
			// it (see loadSegments), and that thread may be gone by
			// the time an asynchronous BounceToKernel fires. A dead
			// thread is no longer in guest mode, so there is nothing
			// left to bounce.
			break
		} else {
			// Nothing else should be returned by tgkill.
			panic(fmt.Sprintf("unexpected tgkill error: %v", err))
		}
	}
}

// bounce forces a return to the kernel or to host mode.
//
// This effectively unwinds the state machine.
func (c *vCPU) bounce(forceGuestExit bool) {
	origGuestExits := c.guestExits.Load()
	origUserExits := c.userExits.Load()
	timeouts := 0
	for {
		switch state := c.state.Load(); state {
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
			c.state.CompareAndSwap(state, state|vCPUWaiter)
		case vCPUUser | vCPUWaiter:
			// Wait for the transition to guest mode. This should
			// come from the bluepill handler.
			if timeout := c.waitUntilNot(state); timeout {
				timeouts++
			}
		case vCPUGuest:
			if !forceGuestExit {
				// The vCPU is already not acquired, so there's
				// no need to do a fresh injection here.
				return
			}
			// vCPUGuest indicates the vCPU is in guest mode. The
			// vCPU is in or about to enter HR0 syscall, or change
			// state from vCPUGuest to vCPUGuest|vCPUUser and then
			// enter user mode. Don't set vCPUWaiter state while
			// the vCPU may stay in HR0 syscall for quite a long
			// time (e.g. PPOLL syscall) without interruption.
			// However, successive bounce signal could interrupt
			// those HR0 syscall until state changed.
			for {
				// We need to spin here until the signal is
				// delivered, because Tgkill can return EAGAIN
				// under memory pressure. We need to ensure that
				// a signal is actually delivered.
				c.PrefaultIDT()
				if err := syscall.Tgkill(pid, int(c.tid.Load()), bounceSignal); err == nil {
					break
				} else if err.(syscall.Errno) == syscall.EAGAIN {
					continue
				} else if err.(syscall.Errno) == syscall.ESRCH {
					// The target thread has already exited; see
					// the note in sendSignal. Nothing to bounce.
					break
				} else {
					// Nothing else should be returned by tgkill.
					panic(fmt.Sprintf("unexpected tgkill error: %v", err))
				}
			}
		case vCPUUser | vCPUGuest:
			// The vCPU is in user or kernel mode. Attempt to
			// register a notification on change.
			c.state.CompareAndSwap(state, state|vCPUWaiter)
			c.sendSignal()
		case vCPUGuest | vCPUWaiter, vCPUUser | vCPUGuest | vCPUWaiter:
			if state == vCPUGuest|vCPUWaiter && !forceGuestExit {
				// See above.
				return
			}
			// Wait for the transition. This again should happen
			// from the bluepill handler, but on the way out.
			if timeout := c.waitUntilNot(state); timeout {
				timeouts++
			}
		default:
			// Should not happen: the above is exhaustive.
			panic("invalid state")
		}

		// Check if we've missed the state transition, but
		// we can safely return at this point in time.
		newGuestExits := c.guestExits.Load()
		newUserExits := c.userExits.Load()
		if newUserExits != origUserExits && (!forceGuestExit || newGuestExits != origGuestExits) {
			return
		}

		if timeouts > 0 {
			c.sendSignal()
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

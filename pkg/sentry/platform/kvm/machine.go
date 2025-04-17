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
	gosync "sync"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/atomicbitops"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/hostsyscall"
	"gvisor.dev/gvisor/pkg/hosttid"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/metric"
	"gvisor.dev/gvisor/pkg/ring0"
	"gvisor.dev/gvisor/pkg/ring0/pagetables"
	"gvisor.dev/gvisor/pkg/seccomp"
	ktime "gvisor.dev/gvisor/pkg/sentry/time"
	"gvisor.dev/gvisor/pkg/sighandling"
	"gvisor.dev/gvisor/pkg/sync"
)

// machine contains state associated with the VM as a whole.
type machine struct {
	// fd is the vm fd.
	fd int

	// machinePoolIndex is the index in the machinePool array.
	machinePoolIndex uint32

	// nextSlot is the next slot for setMemoryRegion.
	//
	// If nextSlot is ^uint32(0), then slots are currently being updated, and the
	// caller should retry.
	nextSlot atomicbitops.Uint32

	// upperSharedPageTables tracks the read-only shared upper of all the pagetables.
	upperSharedPageTables *pagetables.PageTables

	// kernel is the set of global structures.
	kernel ring0.Kernel

	// vCPUsByTID are the machine vCPUs.
	//
	// These are populated dynamically.
	vCPUsByTID vCPUsByTIDAtomicPtrMap

	// availableWaiters is the number of goroutines waiting for a vCPU to
	// become ready.
	availableWaiters atomicbitops.Int32

	// availableSeq is incremented whenever a vCPU becomes ready.
	availableSeq atomicbitops.Uint32

	// vCPUsByID are the machine vCPUs, can be indexed by the vCPU's ID.
	vCPUsByID []*vCPU

	// usedVCPUs is the number of vCPUs that have been used from the
	// vCPUsByID pool.
	usedVCPUs atomicbitops.Int32

	// maxVCPUs is the maximum number of vCPUs supported by the machine.
	maxVCPUs int

	// maxSlots is the maximum number of memory slots supported by the machine.
	maxSlots int

	// tscControl checks whether cpu supports TSC scaling
	tscControl bool

	// usedSlots is the set of used physical addresses (not sorted).
	usedSlots []uintptr
}

// Bits in vCPU.state:
const (
	// vCPUReady is an alias for all the below clear.
	vCPUReady = 0

	// vCPUser indicates that the vCPU is in or about to enter user mode.
	vCPUUser = 1 << 0

	// vCPUGuest indicates the vCPU is in guest mode.
	vCPUGuest = 1 << 1

	// vCPUWaiter indicates that there is a waiter.
	//
	// If this is set, then notify must be called on any state transitions.
	vCPUWaiter = 1 << 2

	vCPUTIDShift  = 32
	vCPUStateMask = (uint64(1) << vCPUTIDShift) - 1
	vCPUTIDMask   = ^vCPUStateMask
)

// Field values for the get_vcpu metric acquisition path used.
var (
	getVCPUAcquisitionFastReused = metric.FieldValue{"fast_reused"}
	getVCPUAcquisitionReused     = metric.FieldValue{"reused"}
	getVCPUAcquisitionUnused     = metric.FieldValue{"unused"}
	getVCPUAcquisitionStolen     = metric.FieldValue{"stolen"}
)

var (
	// hostExitCounter is a metric that tracks how many times the sentry
	// performed a host to guest world switch.
	hostExitCounter = KVMProfiling.MustCreateNewUint64Metric(
		"/kvm/host_exits",
		metric.Uint64Metadata{
			Cumulative:  true,
			Description: "KVM host-to-guest world switch by Sentry.",
		})

	// userExitCounter is a metric that tracks how many times the sentry has
	// had an exit from userspace. Analogous to vCPU.userExits.
	userExitCounter = KVMProfiling.MustCreateNewUint64Metric(
		"/kvm/user_exits",
		metric.Uint64Metadata{
			Cumulative:  true,
			Description: "KVM sentry exits from userspace.",
		})

	// interruptCounter is a metric that tracks how many times execution returned
	// to the KVM host to handle a pending signal.
	interruptCounter = KVMProfiling.MustCreateNewUint64Metric(
		"/kvm/interrupts",
		metric.Uint64Metadata{
			Cumulative:  true,
			Description: "KVM signal handler invocations.",
		})

	// mmapCallCounter is a metric that tracks how many times the function
	// seccompMmapSyscall has been called.
	mmapCallCounter = KVMProfiling.MustCreateNewUint64Metric(
		"/kvm/mmap_calls",
		metric.Uint64Metadata{
			Cumulative:  true,
			Description: "KVM seccompMmapSyscall calls.",
		})

	// getVCPUCounter is a metric that tracks how many times different paths of
	// machine.Get() are triggered.
	getVCPUCounter = KVMProfiling.MustCreateNewUint64Metric(
		"/kvm/get_vcpu",
		metric.Uint64Metadata{
			Cumulative:  true,
			Description: "KVM machine.Get() calls per CPU acquisition path.",
			Fields: []metric.Field{
				metric.NewField("acquisition_type", &getVCPUAcquisitionFastReused, &getVCPUAcquisitionReused, &getVCPUAcquisitionUnused, &getVCPUAcquisitionStolen),
			},
		})

	// asInvalidateDuration are durations of calling addressSpace.invalidate().
	asInvalidateDuration = KVMProfiling.MustCreateNewTimerMetric("/kvm/address_space_invalidate",
		metric.NewExponentialBucketer(15, uint64(time.Nanosecond*100), 1, 2),
		"Duration of KVM addressSpace.invalidate().")
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

	// userExits is the count of user exits.
	userExits atomicbitops.Uint64

	// guestExits is the count of guest to host world switches.
	guestExits atomicbitops.Uint64

	// faults is a count of world faults (informational only).
	faults uint32

	// The bottom 32 bits of state is a bitset of state fields; see vCPUUser
	// and company above. If vCPUGuest or vCPUUser are set, then the top 32
	// bits of state are the thread ID of the thread that has set them.
	state atomicbitops.Uint64

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

// createVCPU creates and returns a new vCPU.
//
// Precondition: mu must be held.
func (m *machine) createVCPU(id int) *vCPU {
	// Create the vCPU.
	fd, errno := hostsyscall.RawSyscall(unix.SYS_IOCTL, uintptr(m.fd), KVM_CREATE_VCPU, uintptr(id))
	if errno != 0 {
		panic(fmt.Sprintf("error creating new vCPU(id=%d): %v", id, errno))
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
		panic(fmt.Sprintf("error setting signal mask for vCPU(id=%d): %v", id, err))
	}

	// Map the run data.
	runData, err := mapRunData(int(fd))
	if err != nil {
		panic(fmt.Sprintf("error mapping run data for vCPU(id=%d): %v", id, err))
	}
	c.runData = runData

	// Initialize architecture state.
	if err := c.initArchState(); err != nil {
		panic(fmt.Sprintf("error initializing vCPU(id=%d) state: %v", id, err))
	}

	return c // Done.
}

// forceMappingEntireAddressSpace forces mapping the entire process address
// space to the VM.
var forceMappingEntireAddressSpace = false

// newMachine returns a new VM context.
func newMachine(vm int, config *Config) (*machine, error) {
	// Create the machine.
	m := &machine{fd: vm}

	if err := m.applyConfig(config); err != nil {
		panic(fmt.Sprintf("error setting config parameters: %s", err))
	}

	// Pull the maximum vCPUs.
	m.getMaxVCPU()
	log.Debugf("The maximum number of vCPUs is %d.", m.maxVCPUs)
	m.vCPUsByID = make([]*vCPU, m.maxVCPUs)
	m.kernel.Init(m.maxVCPUs)

	// Pull the maximum slots.
	maxSlots, errno := hostsyscall.RawSyscall(unix.SYS_IOCTL, uintptr(m.fd), KVM_CHECK_EXTENSION, _KVM_CAP_MAX_MEMSLOTS)
	if errno != 0 {
		m.maxSlots = _KVM_NR_MEMSLOTS
	} else {
		m.maxSlots = int(maxSlots)
	}
	log.Debugf("The maximum number of slots is %d.", m.maxSlots)
	m.usedSlots = make([]uintptr, m.maxSlots)

	// Check TSC Scaling
	hasTSCControl, errno := hostsyscall.RawSyscall(unix.SYS_IOCTL, uintptr(m.fd), KVM_CHECK_EXTENSION, _KVM_CAP_TSC_CONTROL)
	m.tscControl = errno == 0 && hasTSCControl == 1
	log.Debugf("TSC scaling support: %t.", m.tscControl)

	// Create the upper shared pagetables and kernel(sentry) pagetables.
	m.upperSharedPageTables = pagetables.New(newAllocator())
	m.mapUpperHalf(m.upperSharedPageTables)
	m.upperSharedPageTables.Allocator.(*allocator).base.Drain()
	m.upperSharedPageTables.MarkReadOnlyShared()
	m.kernel.PageTables = pagetables.NewWithUpper(newAllocator(), m.upperSharedPageTables, ring0.KernelStartAddress)

	// On x86_64, we prefer not to map the entire sentry address space into
	// the VM due to memory overhead. It is about 3MB for a 40-bit address
	// space and about 250MB for 46-bit address spaces (modern CPUs).
	//
	// Before version 6.9, the memory overhead was two bytes per page.
	// This issue was fixed by commit a364c014a2c1 ("kvm/x86: allocate the
	// write-tracking metadata on-demand").
	//
	// If the entire address space isn't mapped into the VM, we need to
	// trap mmap system calls and map sentry memory regions on demand. This
	// introduces some overhead for mmap system calls, but considering that
	// mmap isn't called frequently, it seems better than the memory and
	// startup time overhead introduced by mapping the entire address
	// space.
	mapEntireAddressSpace := forceMappingEntireAddressSpace ||
		runtime.GOARCH != "amd64"
	if mapEntireAddressSpace {
		// Increase faultBlockSize to be sure that we will not reach the limit.
		// faultBlockSize has to equal or less than KVM_MEM_MAX_NR_PAGES.
		faultBlockSize = uintptr(1) << 42
		faultBlockMask = ^uintptr(faultBlockSize - 1)
	} else {
		// Install seccomp rules to trap runtime mmap system calls. They will
		// be handled by seccompMmapHandler.
		seccompMmapRules(m)
	}

	// Apply the physical mappings. Note that these mappings may point to
	// guest physical addresses that are not actually available. These
	// physical pages are mapped on demand, see kernel_unsafe.go.
	applyPhysicalRegions(func(pr physicalRegion) bool {
		// Map everything in the lower half.
		m.kernel.PageTables.Map(
			hostarch.Addr(pr.virtual),
			pr.length,
			pagetables.MapOpts{AccessType: hostarch.ReadWrite},
			pr.physical)

		return true // Keep iterating.
	})

	// Ensure that the currently mapped virtual regions are actually
	// available in the VM. Note that this doesn't guarantee no future
	// faults, however it should guarantee that everything is available to
	// ensure successful vCPU entry.
	mapRegion := func(vr virtualRegion, flags uint32) {
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
			// Update page tables for executable mappings.
			if vr.accessType.Execute {
				if vr.accessType.Write {
					panic(fmt.Sprintf("executable mapping can't be writable: %#v", vr))
				}
				m.kernel.PageTables.Map(
					hostarch.Addr(virtual),
					length,
					pagetables.MapOpts{AccessType: vr.accessType},
					physical)
			}

			// Ensure the physical range is mapped.
			m.mapPhysical(physical, length)
			virtual += length
		}
	}

	// handleBluepillFault takes the slot spinlock and it is called from
	// seccompMmapHandler, so here we have to guarantee that mmap is not
	// called while we hold the slot spinlock.
	disableAsyncPreemption()

	applyVirtualRegions(func(vr virtualRegion) {
		if excludeVirtualRegion(vr) {
			return // skip region.
		}
		// Take into account that the stack can grow down.
		if vr.filename == "[stack]" {
			vr.virtual -= 1 << 20
			vr.length += 1 << 20
		}

		mapRegion(vr, 0)

	})
	if mapEntireAddressSpace {
		for _, r := range physicalRegions {
			m.mapPhysical(r.physical, r.length)
		}
	}
	enableAsyncPreemption()
	// Initialize architecture state.
	if err := m.initArchState(); err != nil {
		m.Destroy()
		return nil, err
	}

	// Ensure the machine is cleaned up properly.
	runtime.SetFinalizer(m, (*machine).Destroy)
	return m, nil
}

// hasSlot returns true if the given address is mapped.
//
// This must be done via a linear scan.
//
//go:nosplit
func (m *machine) hasSlot(physical uintptr) bool {
	slotLen := int(m.nextSlot.Load())
	// When slots are being updated, nextSlot is ^uint32(0). As this situation
	// is less likely happen, we just set the slotLen to m.maxSlots, and scan
	// the whole usedSlots array.
	if slotLen == int(^uint32(0)) {
		slotLen = m.maxSlots
	}
	for i := 0; i < slotLen; i++ {
		if p := atomic.LoadUintptr(&m.usedSlots[i]); p == physical {
			return true
		}
	}
	return false
}

// mapPhysical checks for the mapping of a physical range, and installs one if
// not available. This attempts to be efficient for calls in the hot path.
//
// This throws on error.
//
//go:nosplit
func (m *machine) mapPhysical(physical, length uintptr) {
	for end := physical + length; physical < end; {
		virtualStart, physicalStart, length, pr := calculateBluepillFault(physical)
		if pr == nil {
			// Should never happen.
			throw("mapPhysical on unknown physical address")
		}

		// Is this already mapped? Check the usedSlots.
		if !m.hasSlot(physicalStart) {
			m.mapMemorySlot(virtualStart, physicalStart, length, pr.readOnly)
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

	machinePool[m.machinePoolIndex].Store(nil)
	seccompMmapSync()

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
// the current context in guest, the vCPU of it must be the same as what
// Get() returns.
func (m *machine) Get() *vCPU {
	runtime.LockOSThread()
	tid := hosttid.Current()

	// Check for an exact match.
	if c := m.vCPUsByTID.Load(tid); c != nil {
		// If this succeeds, we can ignore vCPUGuest since it just indicates
		// that we're already in guest mode.
		if state := c.state.Load(); state>>vCPUTIDShift == tid && c.state.CompareAndSwap(state, state|vCPUUser) {
			getVCPUCounter.Increment(&getVCPUAcquisitionFastReused)
			return c
		}
	}

	// Get vCPU from the m.vCPUsByID pool.
	owned := (tid << vCPUTIDShift) | vCPUUser
	for {
		usedVCPUs := m.usedVCPUs.Load()
		if int(usedVCPUs) >= m.maxVCPUs {
			break
		}
		// XXX switch to Add
		if !m.usedVCPUs.CompareAndSwap(usedVCPUs, usedVCPUs+1) {
			continue
		}
		c := m.vCPUsByID[usedVCPUs]
		c.state.Store(owned)
		m.vCPUsByTID.Store(tid, c)
		c.loadSegments()
		getVCPUCounter.Increment(&getVCPUAcquisitionUnused)
		return c
	}

	// Scan for an available vCPU.
	for origTID, c := range m.vCPUsByTID.RangeRepeatable {
		// We can't steal vCPUs from other threads that are in guest mode.
		if state := c.state.Load(); state&vCPUStateMask == vCPUReady && c.state.CompareAndSwap(state, owned) {
			m.vCPUsByTID.CompareAndSwap(origTID, c, nil)
			m.vCPUsByTID.Store(tid, c)
			c.loadSegments()
			getVCPUCounter.Increment(&getVCPUAcquisitionUnused)
			return c
		}
	}

	// Wait for an available vCPU.
	m.availableWaiters.Add(1)
	for {
		epoch := m.availableSeq.Load()
		for origTID, c := range m.vCPUsByTID.RangeRepeatable {
			if state := c.state.Load(); state&vCPUStateMask == vCPUReady && c.state.CompareAndSwap(state, owned) {
				m.vCPUsByTID.CompareAndSwap(origTID, c, nil)
				m.vCPUsByTID.Store(tid, c)
				m.availableWaiters.Add(-1)
				c.loadSegments()
				getVCPUCounter.Increment(&getVCPUAcquisitionUnused)
				return c
			}
		}

		// All vCPUs are already in guest mode. Wait until a vCPU becomes
		// available. m.availableWait() blocks in the host, but unlocking the
		// OS thread still makes waking up less expensive if sysmon steals our
		// P while we're blocked.
		runtime.UnlockOSThread()
		m.availableWait(epoch)
		runtime.LockOSThread()
		tid = hosttid.Current()
		owned = (tid << vCPUTIDShift) | vCPUUser

		// Recheck for an exact match.
		if c := m.vCPUsByTID.Load(tid); c != nil {
			if state := c.state.Load(); state>>vCPUTIDShift == tid && c.state.CompareAndSwap(state, state|vCPUUser) {
				m.availableWaiters.Add(-1)
				getVCPUCounter.Increment(&getVCPUAcquisitionReused)
				return c
			}
		}
	}
}

// Put puts the current vCPU.
func (m *machine) Put(c *vCPU) {
	// Fast path:
	if c.stateLower().CompareAndSwap(vCPUUser|vCPUGuest, vCPUGuest) {
		runtime.UnlockOSThread()
		return
	}

	var (
		oldState uint64
		newState uint64
	)
	// Unset vCPUUser and vCPUWaiter; notify waiters. This needs to CAS since
	// we might leave guest mode between c.state.Load() and
	// c.state.CompareAndSwap().
	for {
		oldState = c.state.Load()
		if oldState&vCPUUser == 0 {
			panic("putting vCPU not locked by Get")
		}
		newState = oldState &^ (vCPUUser | vCPUWaiter)
		if c.state.CompareAndSwap(oldState, newState) {
			break
		}
	}
	runtime.UnlockOSThread()
	if newState&vCPUStateMask == vCPUReady {
		m.availableNotify()
	}
	if oldState&vCPUWaiter != 0 {
		c.notify()
	}
}

// newDirtySet returns a new dirty set.
func (m *machine) newDirtySet() *dirtySet {
	return &dirtySet{
		vCPUMasks: make([]atomicbitops.Uint64,
			(m.maxVCPUs+63)/64, (m.maxVCPUs+63)/64),
	}
}

// dropPageTables drops cached page table entries.
func (m *machine) dropPageTables(pt *pagetables.PageTables) {
	// Clear from all PCIDs.
	for _, c := range m.vCPUsByID {
		if c != nil && c.PCIDs != nil {
			c.PCIDs.Drop(pt)
		}
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
	origGuestExits := c.guestExits.Load()
	origUserExits := c.userExits.Load()
	for {
		switch state := c.state.Load(); state & vCPUStateMask {
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
			c.waitUntilNot(state)
		case vCPUGuest, vCPUUser | vCPUGuest:
			if state&vCPUStateMask == vCPUGuest && !forceGuestExit {
				// The vCPU is already not acquired, so there's
				// no need to do a fresh injection here.
				return
			}
			// The vCPU is in user or kernel mode. Attempt to
			// register a notification on change.
			if !c.state.CompareAndSwap(state, state|vCPUWaiter) {
				break // Retry.
			}
			for {
				// We need to spin here until the signal is
				// delivered, because Tgkill can return EAGAIN
				// under memory pressure. Since we already
				// marked ourselves as a waiter, we need to
				// ensure that a signal is actually delivered.
				if err := unix.Tgkill(pid, int(state>>vCPUTIDShift), bounceSignal); err == nil {
					break
				} else if err.(unix.Errno) == unix.EAGAIN {
					continue
				} else {
					// Nothing else should be returned by tgkill.
					panic(fmt.Sprintf("unexpected tgkill error: %v", err))
				}
			}
		case vCPUGuest | vCPUWaiter, vCPUUser | vCPUGuest | vCPUWaiter:
			if state&vCPUStateMask == vCPUGuest|vCPUWaiter && !forceGuestExit {
				// See above.
				return
			}
			// Wait for the transition. This again should happen
			// from the bluepill handler, but on the way out.
			c.waitUntilNot(state)
		default:
			// Should not happen: the above is exhaustive.
			panic("invalid state in kvm.vCPU.bounce")
		}

		// Check if we've missed the state transition, but
		// we can safely return at this point in time.
		newGuestExits := c.guestExits.Load()
		newUserExits := c.userExits.Load()
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

const machinePoolSize = 16

// machinePool is enumerated from the seccompMmapHandler signal handler
var (
	machinePool          [machinePoolSize]machineAtomicPtr
	machinePoolLen       atomicbitops.Uint32
	machinePoolMu        sync.Mutex
	seccompMmapRulesOnce gosync.Once
)

func sigsysHandler()
func addrOfSigsysHandler() uintptr

// seccompMmapRules adds seccomp rules to trap mmap system calls that will be
// handled in seccompMmapHandler.
func seccompMmapRules(m *machine) {
	seccompMmapRulesOnce.Do(func() {
		// Install the handler.
		if err := sighandling.ReplaceSignalHandler(unix.SIGSYS, addrOfSigsysHandler(), &savedSigsysHandler); err != nil {
			panic(fmt.Sprintf("Unable to set handler for signal %d: %v", unix.SIGSYS, err))
		}
		rules := []seccomp.RuleSet{
			// Trap mmap system calls and handle them in sigsysGoHandler
			{
				Rules: seccomp.MakeSyscallRules(map[uintptr]seccomp.SyscallRule{
					unix.SYS_MMAP: seccomp.PerArg{
						seccomp.AnyValue{},
						seccomp.AnyValue{},
						seccomp.MaskedEqual(unix.PROT_EXEC, 0),
						/* MAP_DENYWRITE is ignored and used only for filtering. */
						seccomp.MaskedEqual(unix.MAP_DENYWRITE, 0),
					},
				}),
				Action: linux.SECCOMP_RET_TRAP,
			},
		}
		instrs, _, err := seccomp.BuildProgram(rules, seccomp.ProgramOptions{
			DefaultAction: linux.SECCOMP_RET_ALLOW,
			BadArchAction: linux.SECCOMP_RET_ALLOW,
		})
		if err != nil {
			panic(fmt.Sprintf("failed to build rules: %v", err))
		}
		// Perform the actual installation.
		if err := seccomp.SetFilter(instrs); err != nil {
			panic(fmt.Sprintf("failed to set filter: %v", err))
		}
	})

	machinePoolMu.Lock()
	n := machinePoolLen.Load()
	i := uint32(0)
	for ; i < n; i++ {
		if machinePool[i].Load() == nil {
			break
		}
	}
	if i == n {
		if i == machinePoolSize {
			machinePoolMu.Unlock()
			panic("machinePool is full")
		}
		machinePoolLen.Add(1)
	}
	machinePool[i].Store(m)
	m.machinePoolIndex = i
	machinePoolMu.Unlock()
}

type kvmEnableCap struct {
	capability uint32
	flags      uint32
	args       [4]uint64
	pad        [64]uint8
}

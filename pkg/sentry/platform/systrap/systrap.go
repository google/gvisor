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

// Package systrap provides a seccomp-based implementation of the platform
// interface.
//
// In a nutshell, it works as follows:
//
// The creation of a new address space creates a new child processes.
//
// The creation of a new stub thread creates a new system thread with a
// specified address space. To initialize this thread, the following action
// will be done:
//   - install a signal stack which is shared with the Sentry.
//   - install a signal handler for SYS, BUS, FPE, CHLD, TRAP, SEGV signals.
//     This signal handler is a key part of the systrap platform. Any stub event
//     which has to be handled in a privilege mode (by the Sentry) triggers one of
//     previous signals. The signal handler is running on the separate stack which
//     is shared with the Sentry. There is the sysmsg structure to synchronize the
//     Sentry and a stub thread.
//   - install seccomp filters to trap user system calls.
//   - send a fake SIGSEGV to stop the thread in the signal handler.
//
// A context is just a collection of temporary variables. Calling Switch on a
// context does the following:
//
//	Set up proper registers and an FPU state on a stub signal frame.
//	Wake up a stub thread by changing sysmsg->stage and calling FUTEX_WAKE.
//	Wait for new stub event by polling sysmsg->stage.
//
// Lock order:
//
//	subprocessPool.mu
//		subprocess.mu
//			context.mu
//
// +checkalignedignore
package systrap

import (
	"fmt"
	"os"
	"sync"

	"gvisor.dev/gvisor/pkg/abi/linux"
	pkgcontext "gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/memutil"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/pgalloc"
	"gvisor.dev/gvisor/pkg/sentry/platform"
	"gvisor.dev/gvisor/pkg/sentry/platform/interrupt"
	"gvisor.dev/gvisor/pkg/sentry/platform/systrap/sysmsg"
	"gvisor.dev/gvisor/pkg/sentry/platform/systrap/usertrap"
)

var (
	// stubStart is the link address for our stub, and determines the
	// maximum user address. This is valid only after a call to stubInit.
	//
	// We attempt to link the stub here, and adjust downward as needed.
	stubStart uintptr = stubInitAddress

	stubInitProcess uintptr

	// Memory region to store thread specific stacks.
	stubSysmsgStack uintptr
	stubSysmsgStart uintptr
	stubSysmsgEnd   uintptr
	// Memory region to store the contextQueue.
	stubContextQueueRegion    uintptr
	stubContextQueueRegionLen uintptr
	// Memory region to store instances of sysmsg.ThreadContext.
	stubContextRegion    uintptr
	stubContextRegionLen uintptr
	// The memory blob with precompiled seccomp rules.
	stubSysmsgRules    uintptr
	stubSysmsgRulesLen uintptr

	stubSpinningThreadQueueAddr uintptr
	stubSpinningThreadQueueSize uintptr

	// stubROMapEnd is the end address of the read-only stub region that
	// contains the code and precompiled seccomp rules.
	stubROMapEnd uintptr

	// stubEnd is the first byte past the end of the stub, as with
	// stubStart this is valid only after a call to stubInit.
	stubEnd uintptr

	// stubInitialized controls one-time stub initialization.
	stubInitialized sync.Once

	// latencyMonitoring controls one-time initialization of the fastpath
	// control goroutine.
	latencyMonitoring sync.Once

	// archState stores architecture-specific details used in the platform.
	archState sysmsg.ArchState
)

// context is an implementation of the platform context.
type context struct {
	// signalInfo is the signal info, if and when a signal is received.
	signalInfo linux.SignalInfo

	// interrupt is the interrupt context.
	interrupt interrupt.Forwarder

	// sharedContext is everything related to this context that is resident in
	// shared memory with the stub thread.
	// sharedContext is only accessed on the Task goroutine, therefore it is not
	// mutex protected.
	sharedContext *sharedContext

	// mu protects the following fields.
	mu sync.Mutex

	// If lastFaultSP is non-nil, the last context switch was due to a fault
	// received while executing lastFaultSP. Only context.Switch may set
	// lastFaultSP to a non-nil value.
	lastFaultSP *subprocess

	// lastFaultAddr is the last faulting address; this is only meaningful if
	// lastFaultSP is non-nil.
	lastFaultAddr hostarch.Addr

	// lastFaultIP is the address of the last faulting instruction;
	// this is also only meaningful if lastFaultSP is non-nil.
	lastFaultIP hostarch.Addr

	// needRestoreFPState indicates that the FPU state has been changed by
	// the Sentry and has to be updated on the stub thread.
	needRestoreFPState bool

	// needToPullFullState indicates that the Sentry doesn't have a full
	// state of the thread.
	needToPullFullState bool
}

// PullFullState implements platform.Context.PullFullState.
func (c *context) PullFullState(as platform.AddressSpace, ac *arch.Context64) error {
	if !c.needToPullFullState {
		return nil
	}
	s := as.(*subprocess)
	if err := s.PullFullState(c, ac); err != nil {
		return err
	}
	c.needToPullFullState = false
	return nil
}

// FullStateChanged implements platform.Context.FullStateChanged.
func (c *context) FullStateChanged() {
	c.needRestoreFPState = true
	c.needToPullFullState = false
}

// Switch runs the provided context in the given address space.
func (c *context) Switch(ctx pkgcontext.Context, mm platform.MemoryManager, ac *arch.Context64, cpu int32) (*linux.SignalInfo, hostarch.AccessType, error) {
	as := mm.AddressSpace()
	s := as.(*subprocess)
	if err := s.activateContext(c); err != nil {
		return nil, hostarch.NoAccess, err
	}

restart:
	isSyscall, needPatch, err := s.switchToApp(c, ac)
	if err != nil {
		return nil, hostarch.NoAccess, err
	}
	if needPatch {
		restart, _ := s.usertrap.PatchSyscall(ctx, ac, mm)
		if restart {
			goto restart
		}
	}
	if !isSyscall && linux.Signal(c.signalInfo.Signo) == linux.SIGILL {
		err := s.usertrap.HandleFault(ctx, ac, mm)
		if err == usertrap.ErrFaultSyscall {
			isSyscall = true
		} else if err == usertrap.ErrFaultRestart {
			goto restart
		} else if err != nil {
			ctx.Warningf("usertrap.HandleFault failed: %v", err)
		}
	}
	var (
		faultSP   *subprocess
		faultAddr hostarch.Addr
		faultIP   hostarch.Addr
	)
	if !isSyscall && linux.Signal(c.signalInfo.Signo) == linux.SIGSEGV {
		faultSP = s
		faultAddr = hostarch.Addr(c.signalInfo.Addr())
		faultIP = hostarch.Addr(ac.IP())
	}

	// Update the context to reflect the outcome of this context switch.
	c.mu.Lock()
	lastFaultSP := c.lastFaultSP
	lastFaultAddr := c.lastFaultAddr
	lastFaultIP := c.lastFaultIP
	// At this point, c may not yet be in s.faultedContexts, so c.lastFaultSP won't
	// be updated by s.Unmap(). This is fine; we only need to synchronize with
	// calls to s.Unmap() that occur after the handling of this fault.
	c.lastFaultSP = faultSP
	c.lastFaultAddr = faultAddr
	c.lastFaultIP = faultIP
	c.mu.Unlock()

	// Update subprocesses to reflect the outcome of this context switch.
	if lastFaultSP != faultSP {
		if lastFaultSP != nil {
			lastFaultSP.mu.Lock()
			delete(lastFaultSP.faultedContexts, c)
			lastFaultSP.mu.Unlock()
		}
		if faultSP != nil {
			faultSP.mu.Lock()
			faultSP.faultedContexts[c] = struct{}{}
			faultSP.mu.Unlock()
		}
	}

	if isSyscall {
		return nil, hostarch.NoAccess, nil
	}

	si := c.signalInfo
	if faultSP == nil {
		// Non-fault signal.
		return &si, hostarch.NoAccess, platform.ErrContextSignal
	}

	// See if this can be handled as a CPUID exception.
	if linux.Signal(si.Signo) == linux.SIGSEGV && platform.TryCPUIDEmulate(ctx, mm, ac) {
		goto restart
	}

	// Got a page fault. Ideally, we'd get real fault type here, but ptrace
	// doesn't expose this information. Instead, we use a simple heuristic:
	//
	// It was an instruction fault iff the faulting addr == instruction
	// pointer.
	//
	// It was a write fault if the fault is immediately repeated.
	at := hostarch.Read
	if faultAddr == faultIP {
		at.Execute = true
	}
	if lastFaultSP == faultSP &&
		lastFaultAddr == faultAddr &&
		lastFaultIP == faultIP {
		at.Write = true
	}

	// Handle as a signal.
	return &si, at, platform.ErrContextSignal
}

// Interrupt interrupts the running guest application associated with this context.
func (c *context) Interrupt() {
	c.interrupt.NotifyInterrupt()
}

// Release releases all platform resources used by the context.
func (c *context) Release() {
	if c.sharedContext != nil {
		c.sharedContext.release()
		c.sharedContext = nil
	}
}

// PrepareSleep implements platform.Context.platform.PrepareSleep.
func (c *context) PrepareSleep() {
	ctx := c.sharedContext
	if ctx == nil {
		return
	}
	if !ctx.sleeping {
		ctx.sleeping = true
		ctx.subprocess.decAwakeContexts()
	}
}

// Systrap represents a collection of seccomp subprocesses.
type Systrap struct {
	platform.NoCPUPreemptionDetection
	platform.UseHostGlobalMemoryBarrier
	platform.DoesNotOwnPageTables
	platform.HottestSyscallsNotSpecified

	// memoryFile is used to create a stub sysmsg stack
	// which is shared with the Sentry.
	memoryFile *pgalloc.MemoryFile
}

// MinUserAddress implements platform.MinUserAddress.
func (*Systrap) MinUserAddress() hostarch.Addr {
	return platform.SystemMMapMinAddr()
}

// New returns a new seccomp-based implementation of the platform interface.
func New() (*Systrap, error) {
	// CPUID information has been initialized at this point.
	archState.Init()

	mf, err := createMemoryFile()
	if err != nil {
		return nil, err
	}

	stubInitialized.Do(func() {
		// Initialize the stub.
		stubInit()

		// Create the source process for the global pool. This must be
		// done before initializing any other processes.
		source, err := newSubprocess(createStub, mf)
		if err != nil {
			// Should never happen.
			panic("unable to initialize systrap source: " + err.Error())
		}
		// The source subprocess is never released explicitly by a MM.
		source.DecRef(nil)

		globalPool.source = source

		initSysmsgThreadPriority()
	})

	latencyMonitoring.Do(func() {
		go controlFastPath()
	})

	return &Systrap{memoryFile: mf}, nil
}

// SupportsAddressSpaceIO implements platform.Platform.SupportsAddressSpaceIO.
func (*Systrap) SupportsAddressSpaceIO() bool {
	return false
}

// CooperativelySchedulesAddressSpace implements platform.Platform.CooperativelySchedulesAddressSpace.
func (*Systrap) CooperativelySchedulesAddressSpace() bool {
	return false
}

// MapUnit implements platform.Platform.MapUnit.
func (*Systrap) MapUnit() uint64 {
	// The host kernel manages page tables and arbitrary-sized mappings
	// have effectively the same cost.
	return 0
}

// MaxUserAddress returns the first address that may not be used by user
// applications.
func (*Systrap) MaxUserAddress() hostarch.Addr {
	return hostarch.Addr(maxStubUserAddress)
}

// NewAddressSpace returns a new subprocess.
func (p *Systrap) NewAddressSpace(any) (platform.AddressSpace, <-chan struct{}, error) {
	as, err := newSubprocess(globalPool.source.createStub, p.memoryFile)
	return as, nil, err
}

// NewContext returns an interruptible context.
func (*Systrap) NewContext(ctx pkgcontext.Context) platform.Context {
	return &context{
		needRestoreFPState:  true,
		needToPullFullState: false,
	}
}

type constructor struct{}

func (*constructor) New(_ *os.File) (platform.Platform, error) {
	return New()
}

func (*constructor) OpenDevice(_ string) (*os.File, error) {
	return nil, nil
}

// Requirements implements platform.Constructor.Requirements().
func (*constructor) Requirements() platform.Requirements {
	// TODO(b/75837838): Also set a new PID namespace so that we limit
	// access to other host processes.
	return platform.Requirements{
		RequiresCapSysPtrace: true,
		RequiresCurrentPIDNS: true,
	}
}

func init() {
	platform.Register("systrap", &constructor{})
}

func createMemoryFile() (*pgalloc.MemoryFile, error) {
	const memfileName = "systrap-memory"
	fd, err := memutil.CreateMemFD(memfileName, 0)
	if err != nil {
		return nil, fmt.Errorf("error creating memfd: %v", err)
	}
	memfile := os.NewFile(uintptr(fd), memfileName)
	mf, err := pgalloc.NewMemoryFile(memfile, pgalloc.MemoryFileOpts{})
	if err != nil {
		memfile.Close()
		return nil, fmt.Errorf("error creating pgalloc.MemoryFile: %v", err)
	}
	return mf, nil
}

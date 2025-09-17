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
// A platformContext is just a collection of temporary variables. Calling Switch on a
// platformContext does the following:
//
//	Set up proper registers and an FPU state on a stub signal frame.
//	Wake up a stub thread by changing sysmsg->stage and calling FUTEX_WAKE.
//	Wait for new stub event by polling sysmsg->stage.
//
// Lock order:
//
//	subprocessPool.mu
//		subprocess.mu
//			platformContext.mu
//
// +checkalignedignore
package systrap

import (
	"fmt"
	"os"
	"runtime"
	"sync"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	pkgcontext "gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/fd"
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
	stubSysmsgRules     uintptr
	stubSysmsgRulesLen  uintptr
	stubSyscallRules    uintptr
	stubSyscallRulesLen uintptr

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

	// disableSyscallPatching controls if Systrap is allowed to patch
	// syscall invocation sites.
	//
	// This is a hacky global and is not toggleable at runtime! Once it has
	// been flipped for one Systrap instance, it will apply to all previously
	// created and future instances too.
	disableSyscallPatching bool
)

// platformContext is an implementation of the platform context.
type platformContext struct {
	// signalInfo is the signal info, if and when a signal is received.
	signalInfo linux.SignalInfo

	// interrupt is the interrupt platformContext.
	interrupt interrupt.Forwarder

	// sharedContext is everything related to this platformContext that is resident in
	// shared memory with the stub thread.
	// sharedContext is only accessed on the Task goroutine, therefore it is not
	// mutex protected.
	sharedContext *sharedContext

	// needRestoreFPState indicates that the FPU state has been changed by
	// the Sentry and has to be updated on the stub thread.
	needRestoreFPState bool

	// needToPullFullState indicates that the Sentry doesn't have a full
	// state of the thread.
	needToPullFullState bool
}

// PullFullState implements platform.Context.PullFullState.
func (c *platformContext) PullFullState(as platform.AddressSpace, ac *arch.Context64) error {
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
func (c *platformContext) FullStateChanged() {
	c.needRestoreFPState = true
	c.needToPullFullState = false
}

// Switch runs the provided platformContext in the given address space.
func (c *platformContext) Switch(ctx pkgcontext.Context, mm platform.MemoryManager, ac *arch.Context64, cpu int32) (*linux.SignalInfo, hostarch.AccessType, error) {
	as := mm.AddressSpace()
	s := as.(*subprocess)
	if err := s.activateContext(c); err != nil {
		return nil, hostarch.NoAccess, err
	}

restart:
	isSyscall, needPatch, at, err := s.switchToApp(c, ac)
	if err != nil {
		return nil, hostarch.NoAccess, err
	}
	if needPatch {
		s.usertrap.PatchSyscall(ctx, ac, mm)
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

	if isSyscall {
		return nil, hostarch.NoAccess, nil
	}

	si := c.signalInfo

	// See if this can be handled as a CPUID exception.
	if linux.Signal(si.Signo) == linux.SIGSEGV && platform.TryCPUIDEmulate(ctx, mm, ac) {
		goto restart
	}

	// Handle as a signal.
	return &si, at, platform.ErrContextSignal
}

// Interrupt interrupts the running guest application associated with this platformContext.
func (c *platformContext) Interrupt() {
	c.interrupt.NotifyInterrupt()
}

// Preempt implements platform.Context.Preempt.
func (c *platformContext) Preempt() {}

// Release releases all platform resources used by the platformContext.
func (c *platformContext) Release() {
	if c.sharedContext != nil {
		c.sharedContext.release()
		c.sharedContext = nil
	}
}

// PrepareSleep implements platform.Context.platform.PrepareSleep.
func (c *platformContext) PrepareSleep() {
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

	// memoryFile is used to create a stub sysmsg stack which is shared with
	// the Sentry. Since memoryFile is platform-private, it is never restored,
	// so it is safe to call memoryFile.FD() rather than memoryFile.DataFD().
	memoryFile *pgalloc.MemoryFile
}

// MinUserAddress implements platform.MinUserAddress.
func (*Systrap) MinUserAddress() hostarch.Addr {
	return platform.SystemMMapMinAddr()
}

// New returns a new seccomp-based implementation of the platform interface.
func New(opts platform.Options) (*Systrap, error) {
	if !disableSyscallPatching {
		disableSyscallPatching = opts.DisableSyscallPatching
	}

	if maxSysmsgThreads == 0 {
		// CPUID information has been initialized at this point.
		archState.Init()
		// GOMAXPROCS has been set at this point.
		maxSysmsgThreads = runtime.GOMAXPROCS(0)
		// Account for syscall thread.
		maxChildThreads = maxSysmsgThreads + 1
	}

	mf, err := createMemoryFile()
	if err != nil {
		return nil, err
	}

	var stubErr error
	stubInitialized.Do(func() {
		// Don't use sentry and stub fast paths if here is just one cpu.
		neverEnableFastPath = min(runtime.NumCPU(), runtime.GOMAXPROCS(0)) == 1

		// Initialize the stub.
		stubInit()

		// Create the source process for the global pool. This must be
		// done before initializing any other processes.
		source, err := newSubprocess(createStub, mf, false)
		if err != nil {
			stubErr = fmt.Errorf("initialize systrap: %w", err)
			return
		}
		// The source subprocess is never released explicitly by a MM.
		source.DecRef(nil)

		globalPool.source = source

		initSysmsgThreadPriority()

		initSeccompNotify()
	})
	if stubErr != nil {
		mf.Destroy()
		return nil, stubErr
	}

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
	as, err := newSubprocess(globalPool.source.createStub, p.memoryFile, true)
	return as, nil, err
}

// NewContext returns an interruptible platformContext.
func (*Systrap) NewContext(ctx pkgcontext.Context) platform.Context {
	return &platformContext{
		needRestoreFPState:  true,
		needToPullFullState: false,
	}
}

// ConcurrencyCount implements platform.Platform.ConcurrencyCount.
func (*Systrap) ConcurrencyCount() int {
	return maxSysmsgThreads
}

type constructor struct{}

func (*constructor) New(opts platform.Options) (platform.Platform, error) {
	return New(opts)
}

func (*constructor) OpenDevice(_ string) (*fd.FD, error) {
	return nil, nil
}

// Requirements implements platform.Constructor.Requirements().
func (*constructor) Requirements() platform.Requirements {
	return platform.Requirements{
		RequiresCapSysPtrace: true,
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

func corruptedSharedMemoryErr(additional string) *platform.ContextError {
	return &platform.ContextError{
		Err:   fmt.Errorf("systrap corrupted memory: %s", additional),
		Errno: unix.EPERM,
	}
}

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

// Package platform provides a Platform abstraction.
//
// See Platform for more information.
package platform

import (
	"fmt"
	"os"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/seccomp"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/hostmm"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/usermem"
)

// Platform provides abstractions for execution contexts (Context,
// AddressSpace).
type Platform interface {
	// SupportsAddressSpaceIO returns true if AddressSpaces returned by this
	// Platform support AddressSpaceIO methods.
	//
	// The value returned by SupportsAddressSpaceIO is guaranteed to remain
	// unchanged over the lifetime of the Platform.
	SupportsAddressSpaceIO() bool

	// CooperativelySchedulesAddressSpace returns true if the Platform has a
	// limited number of AddressSpaces, such that mm.MemoryManager.Deactivate
	// should call AddressSpace.Release when there are no goroutines that
	// require the mm.MemoryManager to have an active AddressSpace.
	//
	// The value returned by CooperativelySchedulesAddressSpace is guaranteed
	// to remain unchanged over the lifetime of the Platform.
	CooperativelySchedulesAddressSpace() bool

	// DetectsCPUPreemption returns true if Contexts returned by the Platform
	// can reliably return ErrContextCPUPreempted.
	DetectsCPUPreemption() bool

	// HaveGlobalMemoryBarrier returns true if the GlobalMemoryBarrier method
	// is supported.
	HaveGlobalMemoryBarrier() bool

	// MapUnit returns the alignment used for optional mappings into this
	// platform's AddressSpaces. Higher values indicate lower per-page costs
	// for AddressSpace.MapFile. As a special case, a MapUnit of 0 indicates
	// that the cost of AddressSpace.MapFile is effectively independent of the
	// number of pages mapped. If MapUnit is non-zero, it must be a power-of-2
	// multiple of hostarch.PageSize.
	MapUnit() uint64

	// MinUserAddress returns the minimum mappable address on this
	// platform.
	MinUserAddress() hostarch.Addr

	// MaxUserAddress returns the maximum mappable address on this
	// platform.
	MaxUserAddress() hostarch.Addr

	// NewAddressSpace returns a new memory context for this platform.
	//
	// If mappingsID is not nil, the platform may assume that (1) all calls
	// to NewAddressSpace with the same mappingsID represent the same
	// (mutable) set of mappings, and (2) the set of mappings has not
	// changed since the last time AddressSpace.Release was called on an
	// AddressSpace returned by a call to NewAddressSpace with the same
	// mappingsID.
	//
	// If a new AddressSpace cannot be created immediately, a nil
	// AddressSpace is returned, along with channel that is closed when
	// the caller should retry a call to NewAddressSpace.
	//
	// In general, this blocking behavior only occurs when
	// CooperativelySchedulesAddressSpace (above) returns false.
	NewAddressSpace(mappingsID interface{}) (AddressSpace, <-chan struct{}, error)

	// NewContext returns a new execution context.
	NewContext() Context

	// PreemptAllCPUs causes all concurrent calls to Context.Switch(), as well
	// as the first following call to Context.Switch() for each Context, to
	// return ErrContextCPUPreempted.
	//
	// PreemptAllCPUs is only supported if DetectsCPUPremption() == true.
	// Platforms for which this does not hold may panic if PreemptAllCPUs is
	// called.
	PreemptAllCPUs() error

	// GlobalMemoryBarrier blocks until all threads running application code
	// (via Context.Switch) and all task goroutines "have passed through a
	// state where all memory accesses to user-space addresses match program
	// order between entry to and return from [GlobalMemoryBarrier]", as for
	// membarrier(2).
	//
	// Preconditions: HaveGlobalMemoryBarrier() == true.
	GlobalMemoryBarrier() error

	// SyscallFilters returns syscalls made exclusively by this platform.
	SyscallFilters() seccomp.SyscallRules
}

// NoCPUPreemptionDetection implements Platform.DetectsCPUPreemption and
// dependent methods for Platforms that do not support this feature.
type NoCPUPreemptionDetection struct{}

// DetectsCPUPreemption implements Platform.DetectsCPUPreemption.
func (NoCPUPreemptionDetection) DetectsCPUPreemption() bool {
	return false
}

// PreemptAllCPUs implements Platform.PreemptAllCPUs.
func (NoCPUPreemptionDetection) PreemptAllCPUs() error {
	panic("This platform does not support CPU preemption detection")
}

// UseHostGlobalMemoryBarrier implements Platform.HaveGlobalMemoryBarrier and
// Platform.GlobalMemoryBarrier by invoking equivalent functionality on the
// host.
type UseHostGlobalMemoryBarrier struct{}

// HaveGlobalMemoryBarrier implements Platform.HaveGlobalMemoryBarrier.
func (UseHostGlobalMemoryBarrier) HaveGlobalMemoryBarrier() bool {
	return hostmm.HaveGlobalMemoryBarrier()
}

// GlobalMemoryBarrier implements Platform.GlobalMemoryBarrier.
func (UseHostGlobalMemoryBarrier) GlobalMemoryBarrier() error {
	return hostmm.GlobalMemoryBarrier()
}

// UseHostProcessMemoryBarrier implements Platform.HaveGlobalMemoryBarrier and
// Platform.GlobalMemoryBarrier by invoking a process-local memory barrier.
// This is faster than UseHostGlobalMemoryBarrier, but is only appropriate for
// platforms for which application code executes while using the sentry's
// mm_struct.
type UseHostProcessMemoryBarrier struct{}

// HaveGlobalMemoryBarrier implements Platform.HaveGlobalMemoryBarrier.
func (UseHostProcessMemoryBarrier) HaveGlobalMemoryBarrier() bool {
	// Fall back to a global memory barrier if a process-local one isn't
	// available.
	return hostmm.HaveProcessMemoryBarrier() || hostmm.HaveGlobalMemoryBarrier()
}

// GlobalMemoryBarrier implements Platform.GlobalMemoryBarrier.
func (UseHostProcessMemoryBarrier) GlobalMemoryBarrier() error {
	if hostmm.HaveProcessMemoryBarrier() {
		return hostmm.ProcessMemoryBarrier()
	}
	return hostmm.GlobalMemoryBarrier()
}

// MemoryManager represents an abstraction above the platform address space
// which manages memory mappings and their contents.
type MemoryManager interface {
	//usermem.IO provides access to the contents of a virtual memory space.
	usermem.IO
	// MMap establishes a memory mapping.
	MMap(ctx context.Context, opts memmap.MMapOpts) (hostarch.Addr, error)
	// AddressSpace returns the AddressSpace bound to mm.
	AddressSpace() AddressSpace
}

// Context represents the execution context for a single thread.
type Context interface {
	// Switch resumes execution of the thread specified by the arch.Context
	// in the provided address space. This call will block while the thread
	// is executing.
	//
	// If cpu is non-negative, and it is not the number of the CPU that the
	// thread executes on, Context should return ErrContextCPUPreempted. cpu
	// can only be non-negative if Platform.DetectsCPUPreemption() is true;
	// Contexts from Platforms for which this does not hold may ignore cpu, or
	// panic if cpu is non-negative.
	//
	// Switch may return one of the following special errors:
	//
	// - nil: The Context invoked a system call.
	//
	// - ErrContextSignal: The Context was interrupted by a signal. The
	// returned *linux.SignalInfo contains information about the signal. If
	// linux.SignalInfo.Signo == SIGSEGV, the returned hostarch.AccessType
	// contains the access type of the triggering fault. The caller owns
	// the returned SignalInfo.
	//
	// - ErrContextInterrupt: The Context was interrupted by a call to
	// Interrupt(). Switch() may return ErrContextInterrupt spuriously. In
	// particular, most implementations of Interrupt() will cause the first
	// following call to Switch() to return ErrContextInterrupt if there is no
	// concurrent call to Switch().
	//
	// - ErrContextCPUPreempted: See the definition of that error for details.
	Switch(ctx context.Context, mm MemoryManager, ac arch.Context, cpu int32) (*linux.SignalInfo, hostarch.AccessType, error)

	// PullFullState() pulls a full state of the application thread.
	//
	// A platform can support lazy loading/restoring of a thread state
	// which includes registers and a floating point state.
	//
	// For example, when the Sentry handles a system call, it may have only
	// syscall arguments without other registers and a floating point
	// state. And in this case, if the Sentry will need to construct a
	// signal frame to call a signal handler, it will need to call
	// PullFullState() to load all registers and FPU state.
	//
	// Preconditions: The caller must be running on the task goroutine.
	PullFullState(as AddressSpace, ac arch.Context)

	// FullStateChanged() indicates that a thread state has been changed by
	// the Sentry. This happens in case of the rt_sigreturn, execve, etc.
	//
	// First, it indicates that the Sentry has the full state of the thread
	// and PullFullState() has to do nothing if it is called after
	// FullStateChanged().
	//
	// Second, it forces restoring the full state of the application
	// thread. A platform can support lazy loading/restoring of a thread
	// state. This means that if the Sentry has not changed a thread state,
	// the platform may not restore it.
	//
	// Preconditions: The caller must be running on the task goroutine.
	FullStateChanged()

	// Interrupt interrupts a concurrent call to Switch(), causing it to return
	// ErrContextInterrupt.
	Interrupt()

	// Release() releases any resources associated with this context.
	Release()
}

var (
	// ErrContextSignal is returned by Context.Switch() to indicate that the
	// Context was interrupted by a signal.
	ErrContextSignal = fmt.Errorf("interrupted by signal")

	// ErrContextSignalCPUID is equivalent to ErrContextSignal, except that
	// a check should be done for execution of the CPUID instruction. If
	// the current instruction pointer is a CPUID instruction, then this
	// should be emulated appropriately. If not, then the given signal
	// should be handled per above.
	ErrContextSignalCPUID = fmt.Errorf("interrupted by signal, possible CPUID")

	// ErrContextInterrupt is returned by Context.Switch() to indicate that the
	// Context was interrupted by a call to Context.Interrupt().
	ErrContextInterrupt = fmt.Errorf("interrupted by platform.Context.Interrupt()")

	// ErrContextCPUPreempted is returned by Context.Switch() to indicate that
	// one of the following occurred:
	//
	// - The CPU executing the Context is not the CPU passed to
	// Context.Switch().
	//
	// - The CPU executing the Context may have executed another Context since
	// the last time it executed this one; or the CPU has previously executed
	// another Context, and has never executed this one.
	//
	// - Platform.PreemptAllCPUs() was called since the last return from
	// Context.Switch().
	ErrContextCPUPreempted = fmt.Errorf("interrupted by CPU preemption")
)

// SignalInterrupt is a signal reserved for use by implementations of
// Context.Interrupt(). The sentry guarantees that it will ignore delivery of
// this signal both to Contexts and to the sentry itself, under the assumption
// that they originate from races with Context.Interrupt().
//
// NOTE(b/23420492): The Go runtime only guarantees that a small subset
// of signals will be always be unblocked on all threads, one of which
// is SIGCHLD.
const SignalInterrupt = linux.SIGCHLD

// AddressSpace represents a virtual address space in which a Context can
// execute.
type AddressSpace interface {
	// MapFile creates a shared mapping of offsets fr from f at address addr.
	// Any existing overlapping mappings are silently replaced.
	//
	// If precommit is true, the platform should eagerly commit resources (e.g.
	// physical memory) to the mapping. The precommit flag is advisory and
	// implementations may choose to ignore it.
	//
	// Preconditions:
	// * addr and fr must be page-aligned.
	// * fr.Length() > 0.
	// * at.Any() == true.
	// * At least one reference must be held on all pages in fr, and must
	//   continue to be held as long as pages are mapped.
	MapFile(addr hostarch.Addr, f memmap.File, fr memmap.FileRange, at hostarch.AccessType, precommit bool) error

	// Unmap unmaps the given range.
	//
	// Preconditions:
	// * addr is page-aligned.
	// * length > 0.
	Unmap(addr hostarch.Addr, length uint64)

	// Release releases this address space. After releasing, a new AddressSpace
	// must be acquired via platform.NewAddressSpace().
	Release()

	// PreFork() is called before creating a copy of AddressSpace. This
	// guarantees that this address space will be in a consistent state.
	PreFork()

	// PostFork() is called after creating a copy of AddressSpace.
	PostFork()

	// AddressSpaceIO methods are supported iff the associated platform's
	// Platform.SupportsAddressSpaceIO() == true. AddressSpaces for which this
	// does not hold may panic if AddressSpaceIO methods are invoked.
	AddressSpaceIO
}

// AddressSpaceIO supports IO through the memory mappings installed in an
// AddressSpace.
//
// AddressSpaceIO implementors are responsible for ensuring that address ranges
// are application-mappable.
type AddressSpaceIO interface {
	// CopyOut copies len(src) bytes from src to the memory mapped at addr. It
	// returns the number of bytes copied. If the number of bytes copied is <
	// len(src), it returns a non-nil error explaining why.
	CopyOut(addr hostarch.Addr, src []byte) (int, error)

	// CopyIn copies len(dst) bytes from the memory mapped at addr to dst.
	// It returns the number of bytes copied. If the number of bytes copied is
	// < len(dst), it returns a non-nil error explaining why.
	CopyIn(addr hostarch.Addr, dst []byte) (int, error)

	// ZeroOut sets toZero bytes to 0, starting at addr. It returns the number
	// of bytes zeroed. If the number of bytes zeroed is < toZero, it returns a
	// non-nil error explaining why.
	ZeroOut(addr hostarch.Addr, toZero uintptr) (uintptr, error)

	// SwapUint32 atomically sets the uint32 value at addr to new and returns
	// the previous value.
	//
	// Preconditions: addr must be aligned to a 4-byte boundary.
	SwapUint32(addr hostarch.Addr, new uint32) (uint32, error)

	// CompareAndSwapUint32 atomically compares the uint32 value at addr to
	// old; if they are equal, the value in memory is replaced by new. In
	// either case, the previous value stored in memory is returned.
	//
	// Preconditions: addr must be aligned to a 4-byte boundary.
	CompareAndSwapUint32(addr hostarch.Addr, old, new uint32) (uint32, error)

	// LoadUint32 atomically loads the uint32 value at addr and returns it.
	//
	// Preconditions: addr must be aligned to a 4-byte boundary.
	LoadUint32(addr hostarch.Addr) (uint32, error)
}

// NoAddressSpaceIO implements AddressSpaceIO methods by panicking.
type NoAddressSpaceIO struct{}

// CopyOut implements AddressSpaceIO.CopyOut.
func (NoAddressSpaceIO) CopyOut(addr hostarch.Addr, src []byte) (int, error) {
	panic("This platform does not support AddressSpaceIO")
}

// CopyIn implements AddressSpaceIO.CopyIn.
func (NoAddressSpaceIO) CopyIn(addr hostarch.Addr, dst []byte) (int, error) {
	panic("This platform does not support AddressSpaceIO")
}

// ZeroOut implements AddressSpaceIO.ZeroOut.
func (NoAddressSpaceIO) ZeroOut(addr hostarch.Addr, toZero uintptr) (uintptr, error) {
	panic("This platform does not support AddressSpaceIO")
}

// SwapUint32 implements AddressSpaceIO.SwapUint32.
func (NoAddressSpaceIO) SwapUint32(addr hostarch.Addr, new uint32) (uint32, error) {
	panic("This platform does not support AddressSpaceIO")
}

// CompareAndSwapUint32 implements AddressSpaceIO.CompareAndSwapUint32.
func (NoAddressSpaceIO) CompareAndSwapUint32(addr hostarch.Addr, old, new uint32) (uint32, error) {
	panic("This platform does not support AddressSpaceIO")
}

// LoadUint32 implements AddressSpaceIO.LoadUint32.
func (NoAddressSpaceIO) LoadUint32(addr hostarch.Addr) (uint32, error) {
	panic("This platform does not support AddressSpaceIO")
}

// SegmentationFault is an error returned by AddressSpaceIO methods when IO
// fails due to access of an unmapped page, or a mapped page with insufficient
// permissions.
type SegmentationFault struct {
	// Addr is the address at which the fault occurred.
	Addr hostarch.Addr
}

// Error implements error.Error.
func (f SegmentationFault) Error() string {
	return fmt.Sprintf("segmentation fault at %#x", f.Addr)
}

// Requirements is used to specify platform specific requirements.
type Requirements struct {
	// RequiresCurrentPIDNS indicates that the sandbox has to be started in the
	// current pid namespace.
	RequiresCurrentPIDNS bool
	// RequiresCapSysPtrace indicates that the sandbox has to be started with
	// the CAP_SYS_PTRACE capability.
	RequiresCapSysPtrace bool
}

// Constructor represents a platform type.
type Constructor interface {
	// New returns a new platform instance.
	//
	// Arguments:
	//
	// * deviceFile - the device file (e.g. /dev/kvm for the KVM platform).
	New(deviceFile *os.File) (Platform, error)
	OpenDevice() (*os.File, error)

	// Requirements returns platform specific requirements.
	Requirements() Requirements
}

// platforms contains all available platform types.
var platforms = map[string]Constructor{}

// Register registers a new platform type.
func Register(name string, platform Constructor) {
	platforms[name] = platform
}

// Lookup looks up the platform constructor by name.
func Lookup(name string) (Constructor, error) {
	p, ok := platforms[name]
	if !ok {
		return nil, fmt.Errorf("unknown platform: %v", name)
	}
	return p, nil
}

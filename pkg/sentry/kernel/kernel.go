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

// Package kernel provides an emulation of the Linux kernel.
//
// See README.md for a detailed overview.
//
// Lock order (outermost locks must be taken first):
//
//	Kernel.extMu
//		ThreadGroup.timerMu
//		  ktime.Timer.mu (for IntervalTimer) and Kernel.cpuClockMu
//		    TaskSet.mu
//		      SignalHandlers.mu
//		        Task.mu
//		    runningTasksMu
//
// Locking SignalHandlers.mu in multiple SignalHandlers requires locking
// TaskSet.mu exclusively first. Locking Task.mu in multiple Tasks at the same
// time requires locking all of their signal mutexes first.
package kernel

import (
	"errors"
	"fmt"
	"path/filepath"
	"time"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/atomicbitops"
	"gvisor.dev/gvisor/pkg/cleanup"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/cpuid"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/eventchannel"
	"gvisor.dev/gvisor/pkg/fspath"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/pipefs"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/sockfs"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/timerfd"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/tmpfs"
	"gvisor.dev/gvisor/pkg/sentry/hostcpu"
	"gvisor.dev/gvisor/pkg/sentry/inet"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/kernel/futex"
	"gvisor.dev/gvisor/pkg/sentry/kernel/ipc"
	"gvisor.dev/gvisor/pkg/sentry/kernel/sched"
	ktime "gvisor.dev/gvisor/pkg/sentry/kernel/time"
	"gvisor.dev/gvisor/pkg/sentry/limits"
	"gvisor.dev/gvisor/pkg/sentry/loader"
	"gvisor.dev/gvisor/pkg/sentry/mm"
	"gvisor.dev/gvisor/pkg/sentry/pgalloc"
	"gvisor.dev/gvisor/pkg/sentry/platform"
	"gvisor.dev/gvisor/pkg/sentry/socket/netlink/port"
	sentrytime "gvisor.dev/gvisor/pkg/sentry/time"
	"gvisor.dev/gvisor/pkg/sentry/unimpl"
	uspb "gvisor.dev/gvisor/pkg/sentry/unimpl/unimplemented_syscall_go_proto"
	"gvisor.dev/gvisor/pkg/sentry/uniqueid"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/state"
	"gvisor.dev/gvisor/pkg/state/wire"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/tcpip"
)

// LISAFSEnabled is set to true when lisafs protocol is enabled. Added as a
// global to allow easy access everywhere.
//
// TODO(gvisor.dev/issue/7911): Remove when 9P is deleted.
var LISAFSEnabled = false

// userCounters is a set of user counters.
//
// +stateify savable
type userCounters struct {
	uid auth.KUID

	rlimitNProc atomicbitops.Uint64
}

// incRLimitNProc increments the rlimitNProc counter.
func (uc *userCounters) incRLimitNProc(ctx context.Context) error {
	lim := limits.FromContext(ctx).Get(limits.ProcessCount)
	creds := auth.CredentialsFromContext(ctx)
	nproc := uc.rlimitNProc.Add(1)
	if nproc > lim.Cur &&
		!creds.HasCapability(linux.CAP_SYS_ADMIN) &&
		!creds.HasCapability(linux.CAP_SYS_RESOURCE) {
		uc.rlimitNProc.Add(^uint64(0))
		return linuxerr.EAGAIN
	}
	return nil
}

// decRLimitNProc decrements the rlimitNProc counter.
func (uc *userCounters) decRLimitNProc() {
	uc.rlimitNProc.Add(^uint64(0))
}

// Kernel represents an emulated Linux kernel. It must be initialized by calling
// Init() or LoadFrom().
//
// +stateify savable
type Kernel struct {
	// extMu serializes external changes to the Kernel with calls to
	// Kernel.SaveTo. (Kernel.SaveTo requires that the state of the Kernel
	// remains frozen for the duration of the call; it requires that the Kernel
	// is paused as a precondition, which ensures that none of the tasks
	// running within the Kernel can affect its state, but extMu is required to
	// ensure that concurrent users of the Kernel *outside* the Kernel's
	// control cannot affect its state by calling e.g.
	// Kernel.SendExternalSignal.)
	extMu sync.Mutex `state:"nosave"`

	// started is true if Start has been called. Unless otherwise specified,
	// all Kernel fields become immutable once started becomes true.
	started bool `state:"nosave"`

	// All of the following fields are immutable unless otherwise specified.

	// Platform is the platform that is used to execute tasks in the created
	// Kernel. See comment on pgalloc.MemoryFileProvider for why Platform is
	// embedded anonymously (the same issue applies).
	platform.Platform `state:"nosave"`

	// mf provides application memory.
	mf *pgalloc.MemoryFile `state:"nosave"`

	// See InitKernelArgs for the meaning of these fields.
	featureSet                  cpuid.FeatureSet
	timekeeper                  *Timekeeper
	tasks                       *TaskSet
	rootUserNamespace           *auth.UserNamespace
	rootNetworkNamespace        *inet.Namespace
	applicationCores            uint
	useHostCores                bool
	extraAuxv                   []arch.AuxEntry
	vdso                        *loader.VDSO
	rootUTSNamespace            *UTSNamespace
	rootIPCNamespace            *IPCNamespace
	rootAbstractSocketNamespace *AbstractSocketNamespace

	// futexes is the "root" futex.Manager, from which all others are forked.
	// This is necessary to ensure that shared futexes are coherent across all
	// tasks, including those created by CreateProcess.
	futexes *futex.Manager

	// globalInit is the thread group whose leader has ID 1 in the root PID
	// namespace. globalInit is stored separately so that it is accessible even
	// after all tasks in the thread group have exited, such that ID 1 is no
	// longer mapped.
	//
	// globalInit is mutable until it is assigned by the first successful call
	// to CreateProcess, and is protected by extMu.
	globalInit *ThreadGroup

	// syslog is the kernel log.
	syslog syslog

	runningTasksMu runningTasksMutex `state:"nosave"`

	// runningTasks is the total count of tasks currently in
	// TaskGoroutineRunningSys or TaskGoroutineRunningApp. i.e., they are
	// not blocked or stopped.
	//
	// runningTasks must be accessed atomically. Increments from 0 to 1 are
	// further protected by runningTasksMu (see incRunningTasks).
	runningTasks atomicbitops.Int64

	// runningTasksCond is signaled when runningTasks is incremented from 0 to 1.
	//
	// Invariant: runningTasksCond.L == &runningTasksMu.
	runningTasksCond sync.Cond `state:"nosave"`

	// cpuClock is incremented every linux.ClockTick by a goroutine running
	// kernel.runCPUClockTicker() while runningTasks != 0.
	//
	// cpuClock is used to measure task CPU usage, since sampling monotonicClock
	// twice on every syscall turns out to be unreasonably expensive. This is
	// similar to how Linux does task CPU accounting on x86
	// (CONFIG_IRQ_TIME_ACCOUNTING), although Linux also uses scheduler timing
	// information to improve resolution
	// (kernel/sched/cputime.c:cputime_adjust()), which we can't do since
	// "preeemptive" scheduling is managed by the Go runtime, which doesn't
	// provide this information.
	//
	// cpuClock is mutable, and is accessed using atomic memory operations.
	cpuClock atomicbitops.Uint64

	// cpuClockTickTimer drives increments of cpuClock.
	cpuClockTickTimer *time.Timer `state:"nosave"`

	// cpuClockMu is used to make increments of cpuClock, and updates of timers
	// based on cpuClock, atomic.
	cpuClockMu cpuClockMutex `state:"nosave"`

	// cpuClockTickerRunning is true if the goroutine that increments cpuClock is
	// running and false if it is blocked in runningTasksCond.Wait() or if it
	// never started.
	//
	// cpuClockTickerRunning is protected by runningTasksMu.
	cpuClockTickerRunning bool

	// cpuClockTickerWakeCh is sent to to wake the goroutine that increments
	// cpuClock if it's sleeping between ticks.
	cpuClockTickerWakeCh chan struct{} `state:"nosave"`

	// cpuClockTickerStopCond is broadcast when cpuClockTickerRunning transitions
	// from true to false.
	//
	// Invariant: cpuClockTickerStopCond.L == &runningTasksMu.
	cpuClockTickerStopCond sync.Cond `state:"nosave"`

	// uniqueID is used to generate unique identifiers.
	//
	// uniqueID is mutable, and is accessed using atomic memory operations.
	uniqueID atomicbitops.Uint64

	// nextInotifyCookie is a monotonically increasing counter used for
	// generating unique inotify event cookies.
	//
	// nextInotifyCookie is mutable.
	nextInotifyCookie atomicbitops.Uint32

	// netlinkPorts manages allocation of netlink socket port IDs.
	netlinkPorts *port.Manager

	// saveStatus is nil if the sandbox has not been saved, errSaved or
	// errAutoSaved if it has been saved successfully, or the error causing the
	// sandbox to exit during save.
	// It is protected by extMu.
	saveStatus error `state:"nosave"`

	// danglingEndpoints is used to save / restore tcpip.DanglingEndpoints.
	danglingEndpoints struct{} `state:".([]tcpip.Endpoint)"`

	// sockets records all network sockets in the system. Protected by extMu.
	sockets map[*vfs.FileDescription]*SocketRecord

	// nextSocketRecord is the next entry number to use in sockets. Protected
	// by extMu.
	nextSocketRecord uint64

	// deviceRegistry is used to save/restore device.SimpleDevices.
	deviceRegistry struct{} `state:".(*device.Registry)"`

	// unimplementedSyscallEmitterOnce is used in the initialization of
	// unimplementedSyscallEmitter.
	unimplementedSyscallEmitterOnce sync.Once `state:"nosave"`

	// unimplementedSyscallEmitter is used to emit unimplemented syscall
	// events. This is initialized lazily on the first unimplemented
	// syscall.
	unimplementedSyscallEmitter eventchannel.Emitter `state:"nosave"`

	// SpecialOpts contains special kernel options.
	SpecialOpts

	// vfs keeps the filesystem state used across the kernel.
	vfs vfs.VirtualFilesystem

	// hostMount is the Mount used for file descriptors that were imported
	// from the host.
	hostMount *vfs.Mount

	// pipeMount is the Mount used for pipes created by the pipe() and pipe2()
	// syscalls (as opposed to named pipes created by mknod()).
	pipeMount *vfs.Mount

	// shmMount is the Mount used for anonymous files created by the
	// memfd_create() syscalls. It is analogous to Linux's shm_mnt.
	shmMount *vfs.Mount

	// socketMount is the Mount used for sockets created by the socket() and
	// socketpair() syscalls. There are several cases where a socket dentry will
	// not be contained in socketMount:
	// 1. Socket files created by mknod()
	// 2. Socket fds imported from the host (Kernel.hostMount is used for these)
	// 3. Socket files created by binding Unix sockets to a file path
	socketMount *vfs.Mount

	// If set to true, report address space activation waits as if the task is in
	// external wait so that the watchdog doesn't report the task stuck.
	SleepForAddressSpaceActivation bool

	// Exceptions to YAMA ptrace restrictions. Each key-value pair represents a
	// tracee-tracer relationship. The key is a process (technically, the thread
	// group leader) that can be traced by any thread that is a descendant of the
	// value. If the value is nil, then anyone can trace the process represented by
	// the key.
	//
	// ptraceExceptions is protected by the TaskSet mutex.
	ptraceExceptions map[*Task]*Task

	// YAMAPtraceScope is the current level of YAMA ptrace restrictions.
	YAMAPtraceScope atomicbitops.Int32

	// cgroupRegistry contains the set of active cgroup controllers on the
	// system. It is controller by cgroupfs. Nil if cgroupfs is unavailable on
	// the system.
	cgroupRegistry *CgroupRegistry

	// userCountersMap maps auth.KUID into a set of user counters.
	userCountersMap   map[auth.KUID]*userCounters
	userCountersMapMu userCountersMutex `state:"nosave"`
}

// InitKernelArgs holds arguments to Init.
type InitKernelArgs struct {
	// FeatureSet is the emulated CPU feature set.
	FeatureSet cpuid.FeatureSet

	// Timekeeper manages time for all tasks in the system.
	Timekeeper *Timekeeper

	// RootUserNamespace is the root user namespace.
	RootUserNamespace *auth.UserNamespace

	// RootNetworkNamespace is the root network namespace. If nil, no networking
	// will be available.
	RootNetworkNamespace *inet.Namespace

	// ApplicationCores is the number of logical CPUs visible to sandboxed
	// applications. The set of logical CPU IDs is [0, ApplicationCores); thus
	// ApplicationCores is analogous to Linux's nr_cpu_ids, the index of the
	// most significant bit in cpu_possible_mask + 1.
	ApplicationCores uint

	// If UseHostCores is true, Task.CPU() returns the task goroutine's CPU
	// instead of a virtualized CPU number, and Task.CopyToCPUMask() is a
	// no-op. If ApplicationCores is less than hostcpu.MaxPossibleCPU(), it
	// will be overridden.
	UseHostCores bool

	// ExtraAuxv contains additional auxiliary vector entries that are added to
	// each process by the ELF loader.
	ExtraAuxv []arch.AuxEntry

	// Vdso holds the VDSO and its parameter page.
	Vdso *loader.VDSO

	// RootUTSNamespace is the root UTS namespace.
	RootUTSNamespace *UTSNamespace

	// RootIPCNamespace is the root IPC namespace.
	RootIPCNamespace *IPCNamespace

	// RootAbstractSocketNamespace is the root Abstract Socket namespace.
	RootAbstractSocketNamespace *AbstractSocketNamespace

	// PIDNamespace is the root PID namespace.
	PIDNamespace *PIDNamespace
}

// Init initialize the Kernel with no tasks.
//
// Callers must manually set Kernel.Platform and call Kernel.SetMemoryFile
// before calling Init.
func (k *Kernel) Init(args InitKernelArgs) error {
	if args.Timekeeper == nil {
		return fmt.Errorf("args.Timekeeper is nil")
	}
	if args.Timekeeper.clocks == nil {
		return fmt.Errorf("must call Timekeeper.SetClocks() before Kernel.Init()")
	}
	if args.RootUserNamespace == nil {
		return fmt.Errorf("args.RootUserNamespace is nil")
	}
	if args.ApplicationCores == 0 {
		return fmt.Errorf("args.ApplicationCores is 0")
	}

	k.featureSet = args.FeatureSet
	k.timekeeper = args.Timekeeper
	k.tasks = newTaskSet(args.PIDNamespace)
	k.rootUserNamespace = args.RootUserNamespace
	k.rootUTSNamespace = args.RootUTSNamespace
	k.rootIPCNamespace = args.RootIPCNamespace
	k.rootAbstractSocketNamespace = args.RootAbstractSocketNamespace
	k.rootNetworkNamespace = args.RootNetworkNamespace
	if k.rootNetworkNamespace == nil {
		k.rootNetworkNamespace = inet.NewRootNamespace(nil, nil)
	}
	k.runningTasksCond.L = &k.runningTasksMu
	k.cpuClockTickerWakeCh = make(chan struct{}, 1)
	k.cpuClockTickerStopCond.L = &k.runningTasksMu
	k.applicationCores = args.ApplicationCores
	if args.UseHostCores {
		k.useHostCores = true
		maxCPU, err := hostcpu.MaxPossibleCPU()
		if err != nil {
			return fmt.Errorf("failed to get maximum CPU number: %v", err)
		}
		minAppCores := uint(maxCPU) + 1
		if k.applicationCores < minAppCores {
			log.Infof("UseHostCores enabled: increasing ApplicationCores from %d to %d", k.applicationCores, minAppCores)
			k.applicationCores = minAppCores
		}
	}
	k.extraAuxv = args.ExtraAuxv
	k.vdso = args.Vdso
	k.futexes = futex.NewManager()
	k.netlinkPorts = port.New()
	k.ptraceExceptions = make(map[*Task]*Task)
	k.YAMAPtraceScope = atomicbitops.FromInt32(linux.YAMA_SCOPE_RELATIONAL)
	k.userCountersMap = make(map[auth.KUID]*userCounters)

	ctx := k.SupervisorContext()
	if err := k.vfs.Init(ctx); err != nil {
		return fmt.Errorf("failed to initialize VFS: %v", err)
	}

	err := k.rootIPCNamespace.InitPosixQueues(ctx, &k.vfs, auth.CredentialsFromContext(ctx))
	if err != nil {
		return fmt.Errorf("failed to create mqfs filesystem: %v", err)
	}

	pipeFilesystem, err := pipefs.NewFilesystem(&k.vfs)
	if err != nil {
		return fmt.Errorf("failed to create pipefs filesystem: %v", err)
	}
	defer pipeFilesystem.DecRef(ctx)
	pipeMount := k.vfs.NewDisconnectedMount(pipeFilesystem, nil, &vfs.MountOptions{})
	k.pipeMount = pipeMount

	tmpfsFilesystem, tmpfsRoot, err := tmpfs.NewFilesystem(ctx, &k.vfs, auth.NewRootCredentials(k.rootUserNamespace))
	if err != nil {
		return fmt.Errorf("failed to create tmpfs filesystem: %v", err)
	}
	defer tmpfsFilesystem.DecRef(ctx)
	defer tmpfsRoot.DecRef(ctx)
	k.shmMount = k.vfs.NewDisconnectedMount(tmpfsFilesystem, tmpfsRoot, &vfs.MountOptions{})

	socketFilesystem, err := sockfs.NewFilesystem(&k.vfs)
	if err != nil {
		return fmt.Errorf("failed to create sockfs filesystem: %v", err)
	}
	defer socketFilesystem.DecRef(ctx)
	k.socketMount = k.vfs.NewDisconnectedMount(socketFilesystem, nil, &vfs.MountOptions{})

	k.sockets = make(map[*vfs.FileDescription]*SocketRecord)

	k.cgroupRegistry = newCgroupRegistry()
	return nil
}

// SaveTo saves the state of k to w.
//
// Preconditions: The kernel must be paused throughout the call to SaveTo.
func (k *Kernel) SaveTo(ctx context.Context, w wire.Writer) error {
	saveStart := time.Now()

	// Do not allow other Kernel methods to affect it while it's being saved.
	k.extMu.Lock()
	defer k.extMu.Unlock()

	// Stop time.
	k.pauseTimeLocked(ctx)
	defer k.resumeTimeLocked(ctx)

	// Evict all evictable MemoryFile allocations.
	k.mf.StartEvictions()
	k.mf.WaitForEvictions()

	// Discard unsavable mappings, such as those for host file descriptors.
	if err := k.invalidateUnsavableMappings(ctx); err != nil {
		return fmt.Errorf("failed to invalidate unsavable mappings: %v", err)
	}

	// Prepare filesystems for saving. This must be done after
	// invalidateUnsavableMappings(), since dropping memory mappings may
	// affect filesystem state (e.g. page cache reference counts).
	if err := k.vfs.PrepareSave(ctx); err != nil {
		return err
	}

	// Save the CPUID FeatureSet before the rest of the kernel so we can
	// verify its compatibility on restore before attempting to restore the
	// entire kernel, which may fail on an incompatible machine.
	//
	// N.B. This will also be saved along with the full kernel save below.
	cpuidStart := time.Now()
	if _, err := state.Save(ctx, w, &k.featureSet); err != nil {
		return err
	}
	log.Infof("CPUID save took [%s].", time.Since(cpuidStart))

	// Save the timekeeper's state.

	if rootNS := k.rootNetworkNamespace; rootNS != nil && rootNS.Stack() != nil {
		// Pause the network stack.
		netstackPauseStart := time.Now()
		log.Infof("Pausing root network namespace")
		k.rootNetworkNamespace.Stack().Pause()
		defer k.rootNetworkNamespace.Stack().Resume()
		log.Infof("Pausing root network namespace took [%s].", time.Since(netstackPauseStart))
	}

	// Save the kernel state.
	kernelStart := time.Now()
	stats, err := state.Save(ctx, w, k)
	if err != nil {
		return err
	}
	log.Infof("Kernel save stats: %s", stats.String())
	log.Infof("Kernel save took [%s].", time.Since(kernelStart))

	// Save the memory file's state.
	memoryStart := time.Now()
	if err := k.mf.SaveTo(ctx, w); err != nil {
		return err
	}
	log.Infof("Memory save took [%s].", time.Since(memoryStart))

	log.Infof("Overall save took [%s].", time.Since(saveStart))

	return nil
}

// Preconditions: The kernel must be paused.
func (k *Kernel) invalidateUnsavableMappings(ctx context.Context) error {
	invalidated := make(map[*mm.MemoryManager]struct{})
	k.tasks.mu.RLock()
	defer k.tasks.mu.RUnlock()
	for t := range k.tasks.Root.tids {
		// We can skip locking Task.mu here since the kernel is paused.
		if memMgr := t.image.MemoryManager; memMgr != nil {
			if _, ok := invalidated[memMgr]; !ok {
				if err := memMgr.InvalidateUnsavable(ctx); err != nil {
					return err
				}
				invalidated[memMgr] = struct{}{}
			}
		}
		// I really wish we just had a sync.Map of all MMs...
		if r, ok := t.runState.(*runSyscallAfterExecStop); ok {
			if err := r.image.MemoryManager.InvalidateUnsavable(ctx); err != nil {
				return err
			}
		}
	}
	return nil
}

// LoadFrom returns a new Kernel loaded from args.
func (k *Kernel) LoadFrom(ctx context.Context, r wire.Reader, timeReady chan struct{}, net inet.Stack, clocks sentrytime.Clocks, vfsOpts *vfs.CompleteRestoreOptions) error {
	loadStart := time.Now()

	k.runningTasksCond.L = &k.runningTasksMu
	k.cpuClockTickerWakeCh = make(chan struct{}, 1)
	k.cpuClockTickerStopCond.L = &k.runningTasksMu

	initAppCores := k.applicationCores

	// Load the pre-saved CPUID FeatureSet.
	//
	// N.B. This was also saved along with the full kernel below, so we
	// don't need to explicitly install it in the Kernel.
	cpuidStart := time.Now()
	if _, err := state.Load(ctx, r, &k.featureSet); err != nil {
		return err
	}
	log.Infof("CPUID load took [%s].", time.Since(cpuidStart))

	// Verify that the FeatureSet is usable on this host. We do this before
	// Kernel load so that the explicit CPUID mismatch error has priority
	// over floating point state restore errors that may occur on load on
	// an incompatible machine.
	if err := k.featureSet.CheckHostCompatible(); err != nil {
		return err
	}

	// Load the kernel state.
	kernelStart := time.Now()
	stats, err := state.Load(ctx, r, k)
	if err != nil {
		return err
	}
	log.Infof("Kernel load stats: %s", stats.String())
	log.Infof("Kernel load took [%s].", time.Since(kernelStart))

	// rootNetworkNamespace should be populated after loading the state file.
	// Restore the root network stack.
	k.rootNetworkNamespace.RestoreRootStack(net)

	// Load the memory file's state.
	memoryStart := time.Now()
	if err := k.mf.LoadFrom(ctx, r); err != nil {
		return err
	}
	log.Infof("Memory load took [%s].", time.Since(memoryStart))

	log.Infof("Overall load took [%s]", time.Since(loadStart))

	k.Timekeeper().SetClocks(clocks)

	if timeReady != nil {
		close(timeReady)
	}

	if net != nil {
		net.Resume()
	}

	if err := k.vfs.CompleteRestore(ctx, vfsOpts); err != nil {
		return err
	}

	tcpip.AsyncLoading.Wait()

	log.Infof("Overall load took [%s] after async work", time.Since(loadStart))

	// Applications may size per-cpu structures based on k.applicationCores, so
	// it can't change across save/restore. When we are virtualizing CPU
	// numbers, this isn't a problem. However, when we are exposing host CPU
	// assignments, we can't tolerate an increase in the number of host CPUs,
	// which could result in getcpu(2) returning CPUs that applications expect
	// not to exist.
	if k.useHostCores && initAppCores > k.applicationCores {
		return fmt.Errorf("UseHostCores enabled: can't increase ApplicationCores from %d to %d after restore", k.applicationCores, initAppCores)
	}

	return nil
}

// UniqueID returns a unique identifier.
func (k *Kernel) UniqueID() uint64 {
	id := k.uniqueID.Add(1)
	if id == 0 {
		panic("unique identifier generator wrapped around")
	}
	return id
}

// CreateProcessArgs holds arguments to kernel.CreateProcess.
type CreateProcessArgs struct {
	// Filename is the filename to load as the init binary.
	//
	// If this is provided as "", File will be checked, then the file will be
	// guessed via Argv[0].
	Filename string

	// File is a passed host FD pointing to a file to load as the init binary.
	//
	// This is checked if and only if Filename is "".
	File *vfs.FileDescription

	// Argvv is a list of arguments.
	Argv []string

	// Envv is a list of environment variables.
	Envv []string

	// WorkingDirectory is the initial working directory.
	//
	// This defaults to the root if empty.
	WorkingDirectory string

	// Credentials is the initial credentials.
	Credentials *auth.Credentials

	// FDTable is the initial set of file descriptors. If CreateProcess succeeds,
	// it takes a reference on FDTable.
	FDTable *FDTable

	// Umask is the initial umask.
	Umask uint

	// Limits is the initial resource limits.
	Limits *limits.LimitSet

	// MaxSymlinkTraversals is the maximum number of symlinks to follow
	// during resolution.
	MaxSymlinkTraversals uint

	// UTSNamespace is the initial UTS namespace.
	UTSNamespace *UTSNamespace

	// IPCNamespace is the initial IPC namespace.
	IPCNamespace *IPCNamespace

	// PIDNamespace is the initial PID Namespace.
	PIDNamespace *PIDNamespace

	// AbstractSocketNamespace is the initial Abstract Socket namespace.
	AbstractSocketNamespace *AbstractSocketNamespace

	// MountNamespace optionally contains the mount namespace for this
	// process. If nil, the init process's mount namespace is used.
	//
	// Anyone setting MountNamespace must donate a reference (i.e.
	// increment it).
	MountNamespace *vfs.MountNamespace

	// ContainerID is the container that the process belongs to.
	ContainerID string
}

// NewContext returns a context.Context that represents the task that will be
// created by args.NewContext(k).
func (args *CreateProcessArgs) NewContext(k *Kernel) context.Context {
	return &createProcessContext{
		Context: context.Background(),
		kernel:  k,
		args:    args,
	}
}

// createProcessContext is a context.Context that represents the context
// associated with a task that is being created.
type createProcessContext struct {
	context.Context
	kernel *Kernel
	args   *CreateProcessArgs
}

// Value implements context.Context.Value.
func (ctx *createProcessContext) Value(key any) any {
	switch key {
	case CtxKernel:
		return ctx.kernel
	case CtxPIDNamespace:
		return ctx.args.PIDNamespace
	case CtxUTSNamespace:
		return ctx.args.UTSNamespace
	case ipc.CtxIPCNamespace:
		ipcns := ctx.args.IPCNamespace
		ipcns.IncRef()
		return ipcns
	case auth.CtxCredentials:
		return ctx.args.Credentials
	case vfs.CtxRoot:
		if ctx.args.MountNamespace == nil {
			return nil
		}
		root := ctx.args.MountNamespace.Root()
		root.IncRef()
		return root
	case vfs.CtxMountNamespace:
		if ctx.kernel.globalInit == nil {
			return nil
		}
		mntns := ctx.kernel.GlobalInit().Leader().MountNamespace()
		mntns.IncRef()
		return mntns
	case inet.CtxStack:
		return ctx.kernel.RootNetworkNamespace().Stack()
	case ktime.CtxRealtimeClock:
		return ctx.kernel.RealtimeClock()
	case limits.CtxLimits:
		return ctx.args.Limits
	case pgalloc.CtxMemoryFile:
		return ctx.kernel.mf
	case pgalloc.CtxMemoryFileProvider:
		return ctx.kernel
	case platform.CtxPlatform:
		return ctx.kernel
	case uniqueid.CtxGlobalUniqueID:
		return ctx.kernel.UniqueID()
	case uniqueid.CtxGlobalUniqueIDProvider:
		return ctx.kernel
	case uniqueid.CtxInotifyCookie:
		return ctx.kernel.GenerateInotifyCookie()
	case unimpl.CtxEvents:
		return ctx.kernel
	default:
		return nil
	}
}

// CreateProcess creates a new task in a new thread group with the given
// options. The new task has no parent and is in the root PID namespace.
//
// If k.Start() has already been called, then the created process must be
// started by calling kernel.StartProcess(tg).
//
// If k.Start() has not yet been called, then the created task will begin
// running when k.Start() is called.
//
// CreateProcess has no analogue in Linux; it is used to create the initial
// application task, as well as processes started by the control server.
func (k *Kernel) CreateProcess(args CreateProcessArgs) (*ThreadGroup, ThreadID, error) {
	k.extMu.Lock()
	defer k.extMu.Unlock()
	log.Infof("EXEC: %v", args.Argv)

	ctx := args.NewContext(k)
	mntns := args.MountNamespace
	if mntns == nil {
		if k.globalInit == nil {
			return nil, 0, fmt.Errorf("mount namespace is nil")
		}
		// Add a reference to the namespace, which is transferred to the new process.
		mntns = k.globalInit.Leader().MountNamespace()
		mntns.IncRef()
	}
	// Get the root directory from the MountNamespace.
	root := mntns.Root()
	root.IncRef()
	defer root.DecRef(ctx)

	// Grab the working directory.
	wd := root // Default.
	if args.WorkingDirectory != "" {
		pop := vfs.PathOperation{
			Root:               root,
			Start:              wd,
			Path:               fspath.Parse(args.WorkingDirectory),
			FollowFinalSymlink: true,
		}
		// NOTE(b/236028361): Do not set CheckSearchable flag to true.
		// Application is allowed to start with a working directory that it can
		// not access/search. This is consistent with Docker and VFS1. Runc
		// explicitly allows for this in 6ce2d63a5db6 ("libct/init_linux: retry
		// chdir to fix EPERM"). As described in the commit, runc unintentionally
		// allowed this behavior in a couple of releases and applications started
		// relying on it. So they decided to allow it for backward compatibility.
		var err error
		wd, err = k.VFS().GetDentryAt(ctx, args.Credentials, &pop, &vfs.GetDentryOptions{})
		if err != nil {
			return nil, 0, fmt.Errorf("failed to find initial working directory %q: %v", args.WorkingDirectory, err)
		}
		defer wd.DecRef(ctx)
	}
	fsContext := NewFSContext(root, wd, args.Umask)

	tg := k.NewThreadGroup(args.PIDNamespace, NewSignalHandlers(), linux.SIGCHLD, args.Limits)
	cu := cleanup.Make(func() {
		tg.Release(ctx)
	})
	defer cu.Clean()

	// Check which file to start from.
	switch {
	case args.Filename != "":
		// If a filename is given, take that.
		// Set File to nil so we resolve the path in LoadTaskImage.
		args.File = nil
	case args.File != nil:
		// If File is set, take the File provided directly.
		args.Filename = args.File.MappedName(ctx)
	default:
		// Otherwise look at Argv and see if the first argument is a valid path.
		if len(args.Argv) == 0 {
			return nil, 0, fmt.Errorf("no filename or command provided")
		}
		if !filepath.IsAbs(args.Argv[0]) {
			return nil, 0, fmt.Errorf("'%s' is not an absolute path", args.Argv[0])
		}
		args.Filename = args.Argv[0]
	}

	// Create a fresh task context.
	remainingTraversals := args.MaxSymlinkTraversals
	loadArgs := loader.LoadArgs{
		Root:                root,
		WorkingDir:          wd,
		RemainingTraversals: &remainingTraversals,
		ResolveFinal:        true,
		Filename:            args.Filename,
		File:                args.File,
		CloseOnExec:         false,
		Argv:                args.Argv,
		Envv:                args.Envv,
		Features:            k.featureSet,
	}

	image, se := k.LoadTaskImage(ctx, loadArgs)
	if se != nil {
		return nil, 0, errors.New(se.String())
	}

	// Take a reference on the FDTable, which will be transferred to
	// TaskSet.NewTask().
	args.FDTable.IncRef()

	// Create the task.
	config := &TaskConfig{
		Kernel:                  k,
		ThreadGroup:             tg,
		TaskImage:               image,
		FSContext:               fsContext,
		FDTable:                 args.FDTable,
		Credentials:             args.Credentials,
		NetworkNamespace:        k.RootNetworkNamespace(),
		AllowedCPUMask:          sched.NewFullCPUSet(k.applicationCores),
		UTSNamespace:            args.UTSNamespace,
		IPCNamespace:            args.IPCNamespace,
		AbstractSocketNamespace: args.AbstractSocketNamespace,
		MountNamespace:          mntns,
		ContainerID:             args.ContainerID,
		UserCounters:            k.GetUserCounters(args.Credentials.RealKUID),
	}
	config.NetworkNamespace.IncRef()
	t, err := k.tasks.NewTask(ctx, config)
	if err != nil {
		return nil, 0, err
	}
	t.traceExecEvent(image) // Simulate exec for tracing.

	// Success.
	cu.Release()
	tgid := k.tasks.Root.IDOfThreadGroup(tg)
	if k.globalInit == nil {
		k.globalInit = tg
	}
	return tg, tgid, nil
}

// StartProcess starts running a process that was created with CreateProcess.
func (k *Kernel) StartProcess(tg *ThreadGroup) {
	t := tg.Leader()
	tid := k.tasks.Root.IDOfTask(t)
	t.Start(tid)
}

// Start starts execution of all tasks in k.
//
// Preconditions: Start may be called exactly once.
func (k *Kernel) Start() error {
	k.extMu.Lock()
	defer k.extMu.Unlock()

	if k.started {
		return fmt.Errorf("kernel already started")
	}

	k.started = true
	k.cpuClockTickTimer = time.NewTimer(linux.ClockTick)
	k.runningTasksMu.Lock()
	k.cpuClockTickerRunning = true
	k.runningTasksMu.Unlock()
	go k.runCPUClockTicker()
	// If k was created by LoadKernelFrom, timers were stopped during
	// Kernel.SaveTo and need to be resumed. If k was created by NewKernel,
	// this is a no-op.
	k.resumeTimeLocked(k.SupervisorContext())
	k.tasks.mu.RLock()
	ts := make([]*Task, 0, len(k.tasks.Root.tids))
	for t := range k.tasks.Root.tids {
		ts = append(ts, t)
	}
	k.tasks.mu.RUnlock()
	// Start task goroutines.
	// NOTE(b/235349091): We don't actually need the TaskSet mutex, we just
	// need to make sure we only call t.Start() once for each task. Holding the
	// mutex for each task start may cause a nested locking error.
	for _, t := range ts {
		t.Start(t.ThreadID())
	}
	return nil
}

// pauseTimeLocked pauses all Timers and Timekeeper updates.
//
// Preconditions:
//   - Any task goroutines running in k must be stopped.
//   - k.extMu must be locked.
func (k *Kernel) pauseTimeLocked(ctx context.Context) {
	// Since all task goroutines have been stopped by precondition, the CPU clock
	// ticker should stop on its own; wait for it to do so, waking it up from
	// sleeping betwen ticks if necessary.
	k.runningTasksMu.Lock()
	for k.cpuClockTickerRunning {
		select {
		case k.cpuClockTickerWakeCh <- struct{}{}:
		default:
		}
		k.cpuClockTickerStopCond.Wait()
	}
	k.runningTasksMu.Unlock()

	// By precondition, nothing else can be interacting with PIDNamespace.tids
	// or FDTable.files, so we can iterate them without synchronization. (We
	// can't hold the TaskSet mutex when pausing thread group timers because
	// thread group timers call ThreadGroup.SendSignal, which takes the TaskSet
	// mutex, while holding the Timer mutex.)
	for t := range k.tasks.Root.tids {
		if t == t.tg.leader {
			t.tg.itimerRealTimer.Pause()
			for _, it := range t.tg.timers {
				it.PauseTimer()
			}
		}
		// This means we'll iterate FDTables shared by multiple tasks repeatedly,
		// but ktime.Timer.Pause is idempotent so this is harmless.
		if t.fdTable != nil {
			t.fdTable.forEach(ctx, func(_ int32, fd *vfs.FileDescription, _ FDFlags) {
				if tfd, ok := fd.Impl().(*timerfd.TimerFileDescription); ok {
					tfd.PauseTimer()
				}
			})
		}
	}
	k.timekeeper.PauseUpdates()
}

// resumeTimeLocked resumes all Timers and Timekeeper updates. If
// pauseTimeLocked has not been previously called, resumeTimeLocked has no
// effect.
//
// Preconditions:
//   - Any task goroutines running in k must be stopped.
//   - k.extMu must be locked.
func (k *Kernel) resumeTimeLocked(ctx context.Context) {
	// The CPU clock ticker will automatically resume as task goroutines resume
	// execution.

	k.timekeeper.ResumeUpdates()
	for t := range k.tasks.Root.tids {
		if t == t.tg.leader {
			t.tg.itimerRealTimer.Resume()
			for _, it := range t.tg.timers {
				it.ResumeTimer()
			}
		}
		if t.fdTable != nil {
			t.fdTable.forEach(ctx, func(_ int32, fd *vfs.FileDescription, _ FDFlags) {
				if tfd, ok := fd.Impl().(*timerfd.TimerFileDescription); ok {
					tfd.ResumeTimer()
				}
			})
		}
	}
}

func (k *Kernel) incRunningTasks() {
	for {
		tasks := k.runningTasks.Load()
		if tasks != 0 {
			// Standard case. Simply increment.
			if !k.runningTasks.CompareAndSwap(tasks, tasks+1) {
				continue
			}
			return
		}

		// Transition from 0 -> 1.
		k.runningTasksMu.Lock()
		if k.runningTasks.Load() != 0 {
			// Raced with another transition and lost.
			k.runningTasks.Add(1)
			k.runningTasksMu.Unlock()
			return
		}
		if !k.cpuClockTickerRunning {
			select {
			case tickTime := <-k.cpuClockTickTimer.C:
				// Rearm the timer since we consumed the wakeup. Estimate how much time
				// remains on the current tick so that periodic workloads interact with
				// the (periodic) CPU clock ticker in the same way that they would
				// without the optimization of putting the ticker to sleep.
				missedNS := time.Since(tickTime).Nanoseconds()
				missedTicks := missedNS / linux.ClockTick.Nanoseconds()
				thisTickNS := missedNS - missedTicks*linux.ClockTick.Nanoseconds()
				k.cpuClockTickTimer.Reset(time.Duration(linux.ClockTick.Nanoseconds() - thisTickNS))
				// Increment k.cpuClock on the CPU clock ticker goroutine's behalf.
				// (Whole missed ticks don't matter, and adding them to k.cpuClock will
				// just confuse the watchdog.) At the time the tick occurred, all task
				// goroutines were asleep, so there's nothing else to do. This ensures
				// that our caller (Task.accountTaskGoroutineLeave()) records an
				// updated k.cpuClock in Task.gosched.Timestamp, so that it's correctly
				// accounted as having resumed execution in the sentry during this tick
				// instead of at the end of the previous one.
				k.cpuClock.Add(1)
			default:
			}
			// We are transitioning from idle to active. Set k.cpuClockTickerRunning
			// = true here so that if we transition to idle and then active again
			// before the CPU clock ticker goroutine has a chance to run, the first
			// call to k.incRunningTasks() at the end of that cycle does not try to
			// steal k.cpuClockTickTimer.C again, as this would allow workloads that
			// rapidly cycle between idle and active to starve the CPU clock ticker
			// of chances to observe task goroutines in a running state and account
			// their CPU usage.
			k.cpuClockTickerRunning = true
			k.runningTasksCond.Signal()
		}
		// This store must happen after the increment of k.cpuClock above to ensure
		// that concurrent calls to Task.accountTaskGoroutineLeave() also observe
		// the updated k.cpuClock.
		k.runningTasks.Store(1)
		k.runningTasksMu.Unlock()
		return
	}
}

func (k *Kernel) decRunningTasks() {
	tasks := k.runningTasks.Add(-1)
	if tasks < 0 {
		panic(fmt.Sprintf("Invalid running count %d", tasks))
	}

	// Nothing to do. The next CPU clock tick will disable the timer if
	// there is still nothing running. This provides approximately one tick
	// of slack in which we can switch back and forth between idle and
	// active without an expensive transition.
}

// WaitExited blocks until all tasks in k have exited.
func (k *Kernel) WaitExited() {
	k.tasks.liveGoroutines.Wait()
}

// Kill requests that all tasks in k immediately exit as if group exiting with
// status ws. Kill does not wait for tasks to exit.
func (k *Kernel) Kill(ws linux.WaitStatus) {
	k.extMu.Lock()
	defer k.extMu.Unlock()
	k.tasks.Kill(ws)
}

// Pause requests that all tasks in k temporarily stop executing, and blocks
// until all tasks and asynchronous I/O operations in k have stopped. Multiple
// calls to Pause nest and require an equal number of calls to Unpause to
// resume execution.
func (k *Kernel) Pause() {
	k.extMu.Lock()
	k.tasks.BeginExternalStop()
	k.extMu.Unlock()
	k.tasks.runningGoroutines.Wait()
	k.tasks.aioGoroutines.Wait()
}

// ReceiveTaskStates receives full states for all tasks.
func (k *Kernel) ReceiveTaskStates() {
	k.extMu.Lock()
	k.tasks.PullFullState()
	k.extMu.Unlock()
}

// Unpause ends the effect of a previous call to Pause. If Unpause is called
// without a matching preceding call to Pause, Unpause may panic.
func (k *Kernel) Unpause() {
	k.extMu.Lock()
	defer k.extMu.Unlock()
	k.tasks.EndExternalStop()
}

// SendExternalSignal injects a signal into the kernel.
//
// context is used only for debugging to describe how the signal was received.
//
// Preconditions: Kernel must have an init process.
func (k *Kernel) SendExternalSignal(info *linux.SignalInfo, context string) {
	k.extMu.Lock()
	defer k.extMu.Unlock()
	k.sendExternalSignal(info, context)
}

// SendExternalSignalThreadGroup injects a signal into an specific ThreadGroup.
// This function doesn't skip signals like SendExternalSignal does.
func (k *Kernel) SendExternalSignalThreadGroup(tg *ThreadGroup, info *linux.SignalInfo) error {
	k.extMu.Lock()
	defer k.extMu.Unlock()
	return tg.SendSignal(info)
}

// SendContainerSignal sends the given signal to all processes inside the
// namespace that match the given container ID.
func (k *Kernel) SendContainerSignal(cid string, info *linux.SignalInfo) error {
	k.extMu.Lock()
	defer k.extMu.Unlock()
	k.tasks.mu.RLock()
	defer k.tasks.mu.RUnlock()

	var lastErr error
	for tg := range k.tasks.Root.tgids {
		if tg.leader.ContainerID() == cid {
			tg.signalHandlers.mu.Lock()
			infoCopy := *info
			if err := tg.leader.sendSignalLocked(&infoCopy, true /*group*/); err != nil {
				lastErr = err
			}
			tg.signalHandlers.mu.Unlock()
		}
	}
	return lastErr
}

// RebuildTraceContexts rebuilds the trace context for all tasks.
//
// Unfortunately, if these are built while tracing is not enabled, then we will
// not have meaningful trace data. Rebuilding here ensures that we can do so
// after tracing has been enabled.
func (k *Kernel) RebuildTraceContexts() {
	// We need to pause all task goroutines because Task.rebuildTraceContext()
	// replaces Task.traceContext and Task.traceTask, which are
	// task-goroutine-exclusive (i.e. the task goroutine assumes that it can
	// access them without synchronization) for performance.
	k.Pause()
	defer k.Unpause()

	k.extMu.Lock()
	defer k.extMu.Unlock()
	k.tasks.mu.RLock()
	defer k.tasks.mu.RUnlock()

	for t, tid := range k.tasks.Root.tids {
		t.rebuildTraceContext(tid)
	}
}

// FeatureSet returns the FeatureSet.
func (k *Kernel) FeatureSet() cpuid.FeatureSet {
	return k.featureSet
}

// Timekeeper returns the Timekeeper.
func (k *Kernel) Timekeeper() *Timekeeper {
	return k.timekeeper
}

// TaskSet returns the TaskSet.
func (k *Kernel) TaskSet() *TaskSet {
	return k.tasks
}

// RootUserNamespace returns the root UserNamespace.
func (k *Kernel) RootUserNamespace() *auth.UserNamespace {
	return k.rootUserNamespace
}

// RootUTSNamespace returns the root UTSNamespace.
func (k *Kernel) RootUTSNamespace() *UTSNamespace {
	return k.rootUTSNamespace
}

// RootIPCNamespace takes a reference and returns the root IPCNamespace.
func (k *Kernel) RootIPCNamespace() *IPCNamespace {
	k.rootIPCNamespace.IncRef()
	return k.rootIPCNamespace
}

// RootPIDNamespace returns the root PIDNamespace.
func (k *Kernel) RootPIDNamespace() *PIDNamespace {
	return k.tasks.Root
}

// RootAbstractSocketNamespace returns the root AbstractSocketNamespace.
func (k *Kernel) RootAbstractSocketNamespace() *AbstractSocketNamespace {
	return k.rootAbstractSocketNamespace
}

// RootNetworkNamespace returns the root network namespace, always non-nil.
func (k *Kernel) RootNetworkNamespace() *inet.Namespace {
	return k.rootNetworkNamespace
}

// GlobalInit returns the thread group with ID 1 in the root PID namespace, or
// nil if no such thread group exists. GlobalInit may return a thread group
// containing no tasks if the thread group has already exited.
func (k *Kernel) GlobalInit() *ThreadGroup {
	k.extMu.Lock()
	defer k.extMu.Unlock()
	return k.globalInit
}

// TestOnlySetGlobalInit sets the thread group with ID 1 in the root PID namespace.
func (k *Kernel) TestOnlySetGlobalInit(tg *ThreadGroup) {
	k.globalInit = tg
}

// ApplicationCores returns the number of CPUs visible to sandboxed
// applications.
func (k *Kernel) ApplicationCores() uint {
	return k.applicationCores
}

// RealtimeClock returns the application CLOCK_REALTIME clock.
func (k *Kernel) RealtimeClock() ktime.Clock {
	return k.timekeeper.realtimeClock
}

// MonotonicClock returns the application CLOCK_MONOTONIC clock.
func (k *Kernel) MonotonicClock() ktime.Clock {
	return k.timekeeper.monotonicClock
}

// CPUClockNow returns the current value of k.cpuClock.
func (k *Kernel) CPUClockNow() uint64 {
	return k.cpuClock.Load()
}

// Syslog returns the syslog.
func (k *Kernel) Syslog() *syslog {
	return &k.syslog
}

// GenerateInotifyCookie generates a unique inotify event cookie.
//
// Returned values may overlap with previously returned values if the value
// space is exhausted. 0 is not a valid cookie value, all other values
// representable in a uint32 are allowed.
func (k *Kernel) GenerateInotifyCookie() uint32 {
	id := k.nextInotifyCookie.Add(1)
	// Wrap-around is explicitly allowed for inotify event cookies.
	if id == 0 {
		id = k.nextInotifyCookie.Add(1)
	}
	return id
}

// NetlinkPorts returns the netlink port manager.
func (k *Kernel) NetlinkPorts() *port.Manager {
	return k.netlinkPorts
}

var (
	errSaved     = errors.New("sandbox has been successfully saved")
	errAutoSaved = errors.New("sandbox has been successfully auto-saved")
)

// SaveStatus returns the sandbox save status. If it was saved successfully,
// autosaved indicates whether save was triggered by autosave. If it was not
// saved successfully, err indicates the sandbox error that caused the kernel to
// exit during save.
func (k *Kernel) SaveStatus() (saved, autosaved bool, err error) {
	k.extMu.Lock()
	defer k.extMu.Unlock()
	switch k.saveStatus {
	case nil:
		return false, false, nil
	case errSaved:
		return true, false, nil
	case errAutoSaved:
		return true, true, nil
	default:
		return false, false, k.saveStatus
	}
}

// SetSaveSuccess sets the flag indicating that save completed successfully, if
// no status was already set.
func (k *Kernel) SetSaveSuccess(autosave bool) {
	k.extMu.Lock()
	defer k.extMu.Unlock()
	if k.saveStatus == nil {
		if autosave {
			k.saveStatus = errAutoSaved
		} else {
			k.saveStatus = errSaved
		}
	}
}

// SetSaveError sets the sandbox error that caused the kernel to exit during
// save, if one is not already set.
func (k *Kernel) SetSaveError(err error) {
	k.extMu.Lock()
	defer k.extMu.Unlock()
	if k.saveStatus == nil {
		k.saveStatus = err
	}
}

// SetMemoryFile sets Kernel.mf. SetMemoryFile must be called before Init or
// LoadFrom.
func (k *Kernel) SetMemoryFile(mf *pgalloc.MemoryFile) {
	k.mf = mf
}

// MemoryFile implements pgalloc.MemoryFileProvider.MemoryFile.
func (k *Kernel) MemoryFile() *pgalloc.MemoryFile {
	return k.mf
}

// SupervisorContext returns a Context with maximum privileges in k. It should
// only be used by goroutines outside the control of the emulated kernel
// defined by e.
//
// Callers are responsible for ensuring that the returned Context is not used
// concurrently with changes to the Kernel.
func (k *Kernel) SupervisorContext() context.Context {
	return &supervisorContext{
		Kernel: k,
		Logger: log.Log(),
	}
}

// SocketRecord represents a socket recorded in Kernel.sockets.
//
// +stateify savable
type SocketRecord struct {
	k    *Kernel
	Sock *vfs.FileDescription
	ID   uint64 // Socket table entry number.
}

// RecordSocket adds a socket to the system-wide socket table for
// tracking.
//
// Precondition: Caller must hold a reference to sock.
//
// Note that the socket table will not hold a reference on the
// vfs.FileDescription.
func (k *Kernel) RecordSocket(sock *vfs.FileDescription) {
	k.extMu.Lock()
	if _, ok := k.sockets[sock]; ok {
		panic(fmt.Sprintf("Socket %p added twice", sock))
	}
	id := k.nextSocketRecord
	k.nextSocketRecord++
	s := &SocketRecord{
		k:    k,
		ID:   id,
		Sock: sock,
	}
	k.sockets[sock] = s
	k.extMu.Unlock()
}

// DeleteSocket removes a socket from the system-wide socket table.
func (k *Kernel) DeleteSocket(sock *vfs.FileDescription) {
	k.extMu.Lock()
	delete(k.sockets, sock)
	k.extMu.Unlock()
}

// ListSockets returns a snapshot of all sockets.
//
// Callers of ListSockets() should use SocketRecord.Sock.TryIncRef()
// to get a reference on a socket in the table.
func (k *Kernel) ListSockets() []*SocketRecord {
	k.extMu.Lock()
	var socks []*SocketRecord
	for _, s := range k.sockets {
		socks = append(socks, s)
	}
	k.extMu.Unlock()
	return socks
}

// supervisorContext is a privileged context.
type supervisorContext struct {
	context.NoTask
	log.Logger
	*Kernel
}

// Deadline implements context.Context.Deadline.
func (*Kernel) Deadline() (time.Time, bool) {
	return time.Time{}, false
}

// Done implements context.Context.Done.
func (*Kernel) Done() <-chan struct{} {
	return nil
}

// Err implements context.Context.Err.
func (*Kernel) Err() error {
	return nil
}

// Value implements context.Context.
func (ctx *supervisorContext) Value(key any) any {
	switch key {
	case CtxCanTrace:
		// The supervisor context can trace anything. (None of
		// supervisorContext's users are expected to invoke ptrace, but ptrace
		// permissions are required for certain file accesses.)
		return func(*Task, bool) bool { return true }
	case CtxKernel:
		return ctx.Kernel
	case CtxPIDNamespace:
		return ctx.Kernel.tasks.Root
	case CtxUTSNamespace:
		return ctx.Kernel.rootUTSNamespace
	case ipc.CtxIPCNamespace:
		ipcns := ctx.Kernel.rootIPCNamespace
		ipcns.IncRef()
		return ipcns
	case auth.CtxCredentials:
		// The supervisor context is global root.
		return auth.NewRootCredentials(ctx.Kernel.rootUserNamespace)
	case vfs.CtxRoot:
		if ctx.Kernel.globalInit == nil {
			return vfs.VirtualDentry{}
		}
		root := ctx.Kernel.GlobalInit().Leader().MountNamespace().Root()
		root.IncRef()
		return root
	case vfs.CtxMountNamespace:
		if ctx.Kernel.globalInit == nil {
			return nil
		}
		mntns := ctx.Kernel.GlobalInit().Leader().MountNamespace()
		mntns.IncRef()
		return mntns
	case inet.CtxStack:
		return ctx.Kernel.RootNetworkNamespace().Stack()
	case ktime.CtxRealtimeClock:
		return ctx.Kernel.RealtimeClock()
	case limits.CtxLimits:
		// No limits apply.
		return limits.NewLimitSet()
	case pgalloc.CtxMemoryFile:
		return ctx.Kernel.mf
	case pgalloc.CtxMemoryFileProvider:
		return ctx.Kernel
	case platform.CtxPlatform:
		return ctx.Kernel
	case uniqueid.CtxGlobalUniqueID:
		return ctx.Kernel.UniqueID()
	case uniqueid.CtxGlobalUniqueIDProvider:
		return ctx.Kernel
	case uniqueid.CtxInotifyCookie:
		return ctx.Kernel.GenerateInotifyCookie()
	case unimpl.CtxEvents:
		return ctx.Kernel
	case cpuid.CtxFeatureSet:
		return ctx.Kernel.featureSet
	default:
		return nil
	}
}

// Rate limits for the number of unimplemented syscall events.
const (
	unimplementedSyscallsMaxRate = 100  // events per second
	unimplementedSyscallBurst    = 1000 // events
)

// EmitUnimplementedEvent emits an UnimplementedSyscall event via the event
// channel.
func (k *Kernel) EmitUnimplementedEvent(ctx context.Context) {
	k.unimplementedSyscallEmitterOnce.Do(func() {
		k.unimplementedSyscallEmitter = eventchannel.RateLimitedEmitterFrom(eventchannel.DefaultEmitter, unimplementedSyscallsMaxRate, unimplementedSyscallBurst)
	})

	t := TaskFromContext(ctx)
	_, _ = k.unimplementedSyscallEmitter.Emit(&uspb.UnimplementedSyscall{
		Tid:       int32(t.ThreadID()),
		Registers: t.Arch().StateData().Proto(),
	})
}

// VFS returns the virtual filesystem for the kernel.
func (k *Kernel) VFS() *vfs.VirtualFilesystem {
	return &k.vfs
}

// SetHostMount sets the hostfs mount.
func (k *Kernel) SetHostMount(mnt *vfs.Mount) {
	if k.hostMount != nil {
		panic("Kernel.hostMount cannot be set more than once")
	}
	k.hostMount = mnt
}

// HostMount returns the hostfs mount.
func (k *Kernel) HostMount() *vfs.Mount {
	return k.hostMount
}

// PipeMount returns the pipefs mount.
func (k *Kernel) PipeMount() *vfs.Mount {
	return k.pipeMount
}

// ShmMount returns the tmpfs mount.
func (k *Kernel) ShmMount() *vfs.Mount {
	return k.shmMount
}

// SocketMount returns the sockfs mount.
func (k *Kernel) SocketMount() *vfs.Mount {
	return k.socketMount
}

// CgroupRegistry returns the cgroup registry.
func (k *Kernel) CgroupRegistry() *CgroupRegistry {
	return k.cgroupRegistry
}

// Release releases resources owned by k.
//
// Precondition: This should only be called after the kernel is fully
// initialized, e.g. after k.Start() has been called.
func (k *Kernel) Release() {
	ctx := k.SupervisorContext()
	k.hostMount.DecRef(ctx)
	k.pipeMount.DecRef(ctx)
	k.shmMount.DecRef(ctx)
	k.socketMount.DecRef(ctx)
	k.vfs.Release(ctx)
	k.timekeeper.Destroy()
	k.vdso.Release(ctx)
	k.RootNetworkNamespace().DecRef()
}

// PopulateNewCgroupHierarchy moves all tasks into a newly created cgroup
// hierarchy.
//
// Precondition: root must be a new cgroup with no tasks. This implies the
// controllers for root are also new and currently manage no task, which in turn
// implies the new cgroup can be populated without migrating tasks between
// cgroups.
func (k *Kernel) PopulateNewCgroupHierarchy(root Cgroup) {
	k.tasks.mu.RLock()
	k.tasks.forEachTaskLocked(func(t *Task) {
		if t.exitState != TaskExitNone {
			return
		}
		t.mu.Lock()
		// A task can be in the cgroup if it has been created after the
		// cgroup hierarchy was registered.
		t.enterCgroupIfNotYetLocked(root)
		t.mu.Unlock()
	})
	k.tasks.mu.RUnlock()
}

// ReleaseCgroupHierarchy moves all tasks out of all cgroups belonging to the
// hierarchy with the provided id.  This is intended for use during hierarchy
// teardown, as otherwise the tasks would be orphaned w.r.t to some controllers.
func (k *Kernel) ReleaseCgroupHierarchy(hid uint32) {
	var releasedCGs []Cgroup

	k.tasks.mu.RLock()
	// We'll have one cgroup per hierarchy per task.
	releasedCGs = make([]Cgroup, 0, len(k.tasks.Root.tids))
	k.tasks.forEachTaskLocked(func(t *Task) {
		if t.exitState != TaskExitNone {
			return
		}
		t.mu.Lock()
		for cg := range t.cgroups {
			if cg.HierarchyID() == hid {
				cg.Leave(t)
				delete(t.cgroups, cg)
				releasedCGs = append(releasedCGs, cg)
				// A task can't be part of multiple cgroups from the same
				// hierarchy, so we can skip checking the rest once we find a
				// match.
				break
			}
		}
		t.mu.Unlock()
	})
	k.tasks.mu.RUnlock()

	for _, c := range releasedCGs {
		c.decRef()
	}
}

func (k *Kernel) ReplaceFSContextRoots(ctx context.Context, oldRoot vfs.VirtualDentry, newRoot vfs.VirtualDentry) {
	k.tasks.mu.RLock()
	oldRootDecRefs := 0
	k.tasks.forEachTaskLocked(func(t *Task) {
		t.mu.Lock()
		defer t.mu.Unlock()
		if fsc := t.fsContext; fsc != nil {
			fsc.mu.Lock()
			defer fsc.mu.Unlock()
			if fsc.root == oldRoot {
				newRoot.IncRef()
				oldRootDecRefs++
				fsc.root = newRoot
			}
			if fsc.cwd == oldRoot {
				newRoot.IncRef()
				oldRootDecRefs++
				fsc.cwd = newRoot
			}
		}
	})
	k.tasks.mu.RUnlock()
	for i := 0; i < oldRootDecRefs; i++ {
		oldRoot.DecRef(ctx)
	}
}

func (k *Kernel) GetUserCounters(uid auth.KUID) *userCounters {
	k.userCountersMapMu.Lock()
	defer k.userCountersMapMu.Unlock()

	if uc, ok := k.userCountersMap[uid]; ok {
		return uc
	}

	uc := &userCounters{}
	k.userCountersMap[uid] = uc
	return uc
}

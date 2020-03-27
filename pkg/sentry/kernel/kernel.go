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
// Kernel.extMu
//   ThreadGroup.timerMu
//     ktime.Timer.mu (for kernelCPUClockTicker and IntervalTimer)
//       TaskSet.mu
//         SignalHandlers.mu
//           Task.mu
//       runningTasksMu
//
// Locking SignalHandlers.mu in multiple SignalHandlers requires locking
// TaskSet.mu exclusively first. Locking Task.mu in multiple Tasks at the same
// time requires locking all of their signal mutexes first.
package kernel

import (
	"errors"
	"fmt"
	"path/filepath"
	"sync/atomic"
	"time"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/cleanup"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/cpuid"
	"gvisor.dev/gvisor/pkg/eventchannel"
	"gvisor.dev/gvisor/pkg/fspath"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/refs"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/fs"
	oldtimerfd "gvisor.dev/gvisor/pkg/sentry/fs/timerfd"
	"gvisor.dev/gvisor/pkg/sentry/fsbridge"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/pipefs"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/sockfs"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/timerfd"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/tmpfs"
	"gvisor.dev/gvisor/pkg/sentry/hostcpu"
	"gvisor.dev/gvisor/pkg/sentry/inet"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/kernel/epoll"
	"gvisor.dev/gvisor/pkg/sentry/kernel/futex"
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

// VFS2Enabled is set to true when VFS2 is enabled. Added as a global for allow
// easy access everywhere. To be removed once VFS2 becomes the default.
var VFS2Enabled = false

// FUSEEnabled is set to true when FUSE is enabled. Added as a global for allow
// easy access everywhere. To be removed once FUSE is completed.
var FUSEEnabled = false

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
	featureSet                  *cpuid.FeatureSet
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

	// containerInit is the thread group whose leader has ID 1 in the container's
	// PID namespace. This is needed on restore time to recreate loader.processes
	containerInit []*ThreadGroup

	// realtimeClock is a ktime.Clock based on timekeeper's Realtime.
	realtimeClock *timekeeperClock

	// monotonicClock is a ktime.Clock based on timekeeper's Monotonic.
	monotonicClock *timekeeperClock

	// syslog is the kernel log.
	syslog syslog

	// runningTasksMu synchronizes disable/enable of cpuClockTicker when
	// the kernel is idle (runningTasks == 0).
	//
	// runningTasksMu is used to exclude critical sections when the timer
	// disables itself and when the first active task enables the timer,
	// ensuring that tasks always see a valid cpuClock value.
	runningTasksMu sync.Mutex `state:"nosave"`

	// runningTasks is the total count of tasks currently in
	// TaskGoroutineRunningSys or TaskGoroutineRunningApp. i.e., they are
	// not blocked or stopped.
	//
	// runningTasks must be accessed atomically. Increments from 0 to 1 are
	// further protected by runningTasksMu (see incRunningTasks).
	runningTasks int64

	// cpuClock is incremented every linux.ClockTick. cpuClock is used to
	// measure task CPU usage, since sampling monotonicClock twice on every
	// syscall turns out to be unreasonably expensive. This is similar to how
	// Linux does task CPU accounting on x86 (CONFIG_IRQ_TIME_ACCOUNTING),
	// although Linux also uses scheduler timing information to improve
	// resolution (kernel/sched/cputime.c:cputime_adjust()), which we can't do
	// since "preeemptive" scheduling is managed by the Go runtime, which
	// doesn't provide this information.
	//
	// cpuClock is mutable, and is accessed using atomic memory operations.
	cpuClock uint64

	// cpuClockTicker increments cpuClock.
	cpuClockTicker *ktime.Timer `state:"nosave"`

	// cpuClockTickerDisabled indicates that cpuClockTicker has been
	// disabled because no tasks are running.
	//
	// cpuClockTickerDisabled is protected by runningTasksMu.
	cpuClockTickerDisabled bool

	// cpuClockTickerSetting is the ktime.Setting of cpuClockTicker at the
	// point it was disabled. It is cached here to avoid a lock ordering
	// violation with cpuClockTicker.mu when runningTaskMu is held.
	//
	// cpuClockTickerSetting is only valid when cpuClockTickerDisabled is
	// true.
	//
	// cpuClockTickerSetting is protected by runningTasksMu.
	cpuClockTickerSetting ktime.Setting

	// uniqueID is used to generate unique identifiers.
	//
	// uniqueID is mutable, and is accessed using atomic memory operations.
	uniqueID uint64

	// nextInotifyCookie is a monotonically increasing counter used for
	// generating unique inotify event cookies.
	//
	// nextInotifyCookie is mutable, and is accessed using atomic memory
	// operations.
	nextInotifyCookie uint32

	// netlinkPorts manages allocation of netlink socket port IDs.
	netlinkPorts *port.Manager

	// saveStatus is nil if the sandbox has not been saved, errSaved or
	// errAutoSaved if it has been saved successfully, or the error causing the
	// sandbox to exit during save.
	// It is protected by extMu.
	saveStatus error `state:"nosave"`

	// danglingEndpoints is used to save / restore tcpip.DanglingEndpoints.
	danglingEndpoints struct{} `state:".([]tcpip.Endpoint)"`

	// sockets is the list of all network sockets in the system.
	// Protected by extMu.
	// TODO(gvisor.dev/issue/1624): Only used by VFS1.
	sockets socketList

	// socketsVFS2 records all network sockets in the system. Protected by
	// extMu.
	socketsVFS2 map[*vfs.FileDescription]*SocketRecord

	// nextSocketRecord is the next entry number to use in sockets. Protected
	// by extMu.
	nextSocketRecord uint64

	// deviceRegistry is used to save/restore device.SimpleDevices.
	deviceRegistry struct{} `state:".(*device.Registry)"`

	// DirentCacheLimiter controls the number of total dirent entries can be in
	// caches. Not all caches use it, only the caches that use host resources use
	// the limiter. It may be nil if disabled.
	DirentCacheLimiter *fs.DirentCacheLimiter

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
	// memfd_create() syscalls. It is analagous to Linux's shm_mnt.
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
}

// InitKernelArgs holds arguments to Init.
type InitKernelArgs struct {
	// FeatureSet is the emulated CPU feature set.
	FeatureSet *cpuid.FeatureSet

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
	if args.FeatureSet == nil {
		return fmt.Errorf("FeatureSet is nil")
	}
	if args.Timekeeper == nil {
		return fmt.Errorf("Timekeeper is nil")
	}
	if args.Timekeeper.clocks == nil {
		return fmt.Errorf("must call Timekeeper.SetClocks() before Kernel.Init()")
	}
	if args.RootUserNamespace == nil {
		return fmt.Errorf("RootUserNamespace is nil")
	}
	if args.ApplicationCores == 0 {
		return fmt.Errorf("ApplicationCores is 0")
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
	k.realtimeClock = &timekeeperClock{tk: args.Timekeeper, c: sentrytime.Realtime}
	k.monotonicClock = &timekeeperClock{tk: args.Timekeeper, c: sentrytime.Monotonic}
	k.futexes = futex.NewManager()
	k.netlinkPorts = port.New()

	if VFS2Enabled {
		ctx := k.SupervisorContext()
		if err := k.vfs.Init(ctx); err != nil {
			return fmt.Errorf("failed to initialize VFS: %v", err)
		}

		pipeFilesystem, err := pipefs.NewFilesystem(&k.vfs)
		if err != nil {
			return fmt.Errorf("failed to create pipefs filesystem: %v", err)
		}
		defer pipeFilesystem.DecRef(ctx)
		pipeMount, err := k.vfs.NewDisconnectedMount(pipeFilesystem, nil, &vfs.MountOptions{})
		if err != nil {
			return fmt.Errorf("failed to create pipefs mount: %v", err)
		}
		k.pipeMount = pipeMount

		tmpfsFilesystem, tmpfsRoot, err := tmpfs.NewFilesystem(ctx, &k.vfs, auth.NewRootCredentials(k.rootUserNamespace))
		if err != nil {
			return fmt.Errorf("failed to create tmpfs filesystem: %v", err)
		}
		defer tmpfsFilesystem.DecRef(ctx)
		defer tmpfsRoot.DecRef(ctx)
		shmMount, err := k.vfs.NewDisconnectedMount(tmpfsFilesystem, tmpfsRoot, &vfs.MountOptions{})
		if err != nil {
			return fmt.Errorf("failed to create tmpfs mount: %v", err)
		}
		k.shmMount = shmMount

		socketFilesystem, err := sockfs.NewFilesystem(&k.vfs)
		if err != nil {
			return fmt.Errorf("failed to create sockfs filesystem: %v", err)
		}
		defer socketFilesystem.DecRef(ctx)
		socketMount, err := k.vfs.NewDisconnectedMount(socketFilesystem, nil, &vfs.MountOptions{})
		if err != nil {
			return fmt.Errorf("failed to create sockfs mount: %v", err)
		}
		k.socketMount = socketMount

		k.socketsVFS2 = make(map[*vfs.FileDescription]*SocketRecord)
	}

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

	if VFS2Enabled {
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
	} else {
		// Flush cached file writes to backing storage. This must come after
		// MemoryFile eviction since eviction may cause file writes.
		if err := k.flushWritesToFiles(ctx); err != nil {
			return err
		}

		// Remove all epoll waiter objects from underlying wait queues.
		// NOTE: for programs to resume execution in future snapshot scenarios,
		// we will need to re-establish these waiter objects after saving.
		k.tasks.unregisterEpollWaiters(ctx)

		// Clear the dirent cache before saving because Dirents must be Loaded in a
		// particular order (parents before children), and Loading dirents from a cache
		// breaks that order.
		if err := k.flushMountSourceRefs(ctx); err != nil {
			return err
		}

		// Ensure that all inode and mount release operations have completed.
		fs.AsyncBarrier()

		// Once all fs work has completed (flushed references have all been released),
		// reset mount mappings. This allows individual mounts to save how inodes map
		// to filesystem resources. Without this, fs.Inodes cannot be restored.
		fs.SaveInodeMappings()

		// Discard unsavable mappings, such as those for host file descriptors.
		// This must be done after waiting for "asynchronous fs work", which
		// includes async I/O that may touch application memory.
		//
		// TODO(gvisor.dev/issue/1624): This rationale is believed to be
		// obsolete since AIO callbacks are now waited-for by Kernel.Pause(),
		// but this order is conservatively retained for VFS1.
		if err := k.invalidateUnsavableMappings(ctx); err != nil {
			return fmt.Errorf("failed to invalidate unsavable mappings: %v", err)
		}
	}

	// Save the CPUID FeatureSet before the rest of the kernel so we can
	// verify its compatibility on restore before attempting to restore the
	// entire kernel, which may fail on an incompatible machine.
	//
	// N.B. This will also be saved along with the full kernel save below.
	cpuidStart := time.Now()
	if _, err := state.Save(ctx, w, k.FeatureSet()); err != nil {
		return err
	}
	log.Infof("CPUID save took [%s].", time.Since(cpuidStart))

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

// flushMountSourceRefs flushes the MountSources for all mounted filesystems
// and open FDs.
//
// Preconditions: !VFS2Enabled.
func (k *Kernel) flushMountSourceRefs(ctx context.Context) error {
	// Flush all mount sources for currently mounted filesystems in each task.
	flushed := make(map[*fs.MountNamespace]struct{})
	k.tasks.mu.RLock()
	k.tasks.forEachThreadGroupLocked(func(tg *ThreadGroup) {
		if _, ok := flushed[tg.mounts]; ok {
			// Already flushed.
			return
		}
		tg.mounts.FlushMountSourceRefs()
		flushed[tg.mounts] = struct{}{}
	})
	k.tasks.mu.RUnlock()

	// There may be some open FDs whose filesystems have been unmounted. We
	// must flush those as well.
	return k.tasks.forEachFDPaused(ctx, func(file *fs.File, _ *vfs.FileDescription) error {
		file.Dirent.Inode.MountSource.FlushDirentRefs()
		return nil
	})
}

// forEachFDPaused applies the given function to each open file descriptor in
// each task.
//
// Precondition: Must be called with the kernel paused.
func (ts *TaskSet) forEachFDPaused(ctx context.Context, f func(*fs.File, *vfs.FileDescription) error) (err error) {
	ts.mu.RLock()
	defer ts.mu.RUnlock()
	for t := range ts.Root.tids {
		// We can skip locking Task.mu here since the kernel is paused.
		if t.fdTable == nil {
			continue
		}
		t.fdTable.forEach(ctx, func(_ int32, file *fs.File, fileVFS2 *vfs.FileDescription, _ FDFlags) {
			if lastErr := f(file, fileVFS2); lastErr != nil && err == nil {
				err = lastErr
			}
		})
	}
	return err
}

// Preconditions: !VFS2Enabled.
func (k *Kernel) flushWritesToFiles(ctx context.Context) error {
	return k.tasks.forEachFDPaused(ctx, func(file *fs.File, _ *vfs.FileDescription) error {
		if flags := file.Flags(); !flags.Write {
			return nil
		}
		if sattr := file.Dirent.Inode.StableAttr; !fs.IsFile(sattr) && !fs.IsDir(sattr) {
			return nil
		}
		// Here we need all metadata synced.
		syncErr := file.Fsync(ctx, 0, fs.FileMaxOffset, fs.SyncAll)
		if err := fs.SaveFileFsyncError(syncErr); err != nil {
			name, _ := file.Dirent.FullName(nil /* root */)
			// Wrap this error in ErrSaveRejection so that it will trigger a save
			// error, rather than a panic. This also allows us to distinguish Fsync
			// errors from state file errors in state.Save.
			return fs.ErrSaveRejection{
				Err: fmt.Errorf("%q was not sufficiently synced: %v", name, err),
			}
		}
		return nil
	})
}

// Preconditions: !VFS2Enabled.
func (ts *TaskSet) unregisterEpollWaiters(ctx context.Context) {
	ts.mu.RLock()
	defer ts.mu.RUnlock()

	// Tasks that belong to the same process could potentially point to the
	// same FDTable. So we retain a map of processed ones to avoid
	// processing the same FDTable multiple times.
	processed := make(map[*FDTable]struct{})
	for t := range ts.Root.tids {
		// We can skip locking Task.mu here since the kernel is paused.
		if t.fdTable == nil {
			continue
		}
		if _, ok := processed[t.fdTable]; ok {
			continue
		}
		t.fdTable.forEach(ctx, func(_ int32, file *fs.File, _ *vfs.FileDescription, _ FDFlags) {
			if e, ok := file.FileOperations.(*epoll.EventPoll); ok {
				e.UnregisterEpollWaiters()
			}
		})
		processed[t.fdTable] = struct{}{}
	}
}

// Preconditions: The kernel must be paused.
func (k *Kernel) invalidateUnsavableMappings(ctx context.Context) error {
	invalidated := make(map[*mm.MemoryManager]struct{})
	k.tasks.mu.RLock()
	defer k.tasks.mu.RUnlock()
	for t := range k.tasks.Root.tids {
		// We can skip locking Task.mu here since the kernel is paused.
		if mm := t.image.MemoryManager; mm != nil {
			if _, ok := invalidated[mm]; !ok {
				if err := mm.InvalidateUnsavable(ctx); err != nil {
					return err
				}
				invalidated[mm] = struct{}{}
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
func (k *Kernel) LoadFrom(ctx context.Context, r wire.Reader, net inet.Stack, clocks sentrytime.Clocks, vfsOpts *vfs.CompleteRestoreOptions) error {
	loadStart := time.Now()

	initAppCores := k.applicationCores

	// Load the pre-saved CPUID FeatureSet.
	//
	// N.B. This was also saved along with the full kernel below, so we
	// don't need to explicitly install it in the Kernel.
	cpuidStart := time.Now()
	var features cpuid.FeatureSet
	if _, err := state.Load(ctx, r, &features); err != nil {
		return err
	}
	log.Infof("CPUID load took [%s].", time.Since(cpuidStart))

	// Verify that the FeatureSet is usable on this host. We do this before
	// Kernel load so that the explicit CPUID mismatch error has priority
	// over floating point state restore errors that may occur on load on
	// an incompatible machine.
	if err := features.CheckHostCompatible(); err != nil {
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
	if net != nil {
		net.Resume()
	}

	if VFS2Enabled {
		if err := k.vfs.CompleteRestore(ctx, vfsOpts); err != nil {
			return err
		}
	} else {
		// Ensure that all pending asynchronous work is complete:
		//   - namedpipe opening
		//   - inode file opening
		if err := fs.AsyncErrorBarrier(); err != nil {
			return err
		}
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
	id := atomic.AddUint64(&k.uniqueID, 1)
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
	File fsbridge.File

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
	MountNamespace *fs.MountNamespace

	// MountNamespaceVFS2 optionally contains the mount namespace for this
	// process. If nil, the init process's mount namespace is used.
	//
	// Anyone setting MountNamespaceVFS2 must donate a reference (i.e.
	// increment it).
	MountNamespaceVFS2 *vfs.MountNamespace

	// ContainerIndex is the container that the process belongs to.
	ContainerIndex int
}

// NewContext returns a context.Context that represents the task that will be
// created by args.NewContext(k).
func (args *CreateProcessArgs) NewContext(k *Kernel) *createProcessContext {
	return &createProcessContext{
		Logger: log.Log(),
		k:      k,
		args:   args,
	}
}

// createProcessContext is a context.Context that represents the context
// associated with a task that is being created.
type createProcessContext struct {
	context.NoopSleeper
	log.Logger
	k    *Kernel
	args *CreateProcessArgs
}

// Value implements context.Context.Value.
func (ctx *createProcessContext) Value(key interface{}) interface{} {
	switch key {
	case CtxKernel:
		return ctx.k
	case CtxPIDNamespace:
		return ctx.args.PIDNamespace
	case CtxUTSNamespace:
		return ctx.args.UTSNamespace
	case CtxIPCNamespace:
		ipcns := ctx.args.IPCNamespace
		ipcns.IncRef()
		return ipcns
	case auth.CtxCredentials:
		return ctx.args.Credentials
	case fs.CtxRoot:
		if ctx.args.MountNamespace != nil {
			// MountNamespace.Root() will take a reference on the root dirent for us.
			return ctx.args.MountNamespace.Root()
		}
		return nil
	case vfs.CtxRoot:
		if ctx.args.MountNamespaceVFS2 == nil {
			return nil
		}
		root := ctx.args.MountNamespaceVFS2.Root()
		root.IncRef()
		return root
	case vfs.CtxMountNamespace:
		if ctx.k.globalInit == nil {
			return nil
		}
		mntns := ctx.k.GlobalInit().Leader().MountNamespaceVFS2()
		mntns.IncRef()
		return mntns
	case fs.CtxDirentCacheLimiter:
		return ctx.k.DirentCacheLimiter
	case inet.CtxStack:
		return ctx.k.RootNetworkNamespace().Stack()
	case ktime.CtxRealtimeClock:
		return ctx.k.RealtimeClock()
	case limits.CtxLimits:
		return ctx.args.Limits
	case pgalloc.CtxMemoryFile:
		return ctx.k.mf
	case pgalloc.CtxMemoryFileProvider:
		return ctx.k
	case platform.CtxPlatform:
		return ctx.k
	case uniqueid.CtxGlobalUniqueID:
		return ctx.k.UniqueID()
	case uniqueid.CtxGlobalUniqueIDProvider:
		return ctx.k
	case uniqueid.CtxInotifyCookie:
		return ctx.k.GenerateInotifyCookie()
	case unimpl.CtxEvents:
		return ctx.k
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

	var (
		opener    fsbridge.Lookup
		fsContext *FSContext
		mntns     *fs.MountNamespace
		mntnsVFS2 *vfs.MountNamespace
	)

	if VFS2Enabled {
		mntnsVFS2 = args.MountNamespaceVFS2
		if mntnsVFS2 == nil {
			// Add a reference to the namespace, which is transferred to the new process.
			mntnsVFS2 = k.globalInit.Leader().MountNamespaceVFS2()
			mntnsVFS2.IncRef()
		}
		// Get the root directory from the MountNamespace.
		root := mntnsVFS2.Root()
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
			var err error
			wd, err = k.VFS().GetDentryAt(ctx, args.Credentials, &pop, &vfs.GetDentryOptions{
				CheckSearchable: true,
			})
			if err != nil {
				return nil, 0, fmt.Errorf("failed to find initial working directory %q: %v", args.WorkingDirectory, err)
			}
			defer wd.DecRef(ctx)
		}
		opener = fsbridge.NewVFSLookup(mntnsVFS2, root, wd)
		fsContext = NewFSContextVFS2(root, wd, args.Umask)

	} else {
		mntns = args.MountNamespace
		if mntns == nil {
			mntns = k.GlobalInit().Leader().MountNamespace()
			mntns.IncRef()
		}
		// Get the root directory from the MountNamespace.
		root := mntns.Root()
		// The call to newFSContext below will take a reference on root, so we
		// don't need to hold this one.
		defer root.DecRef(ctx)

		// Grab the working directory.
		remainingTraversals := args.MaxSymlinkTraversals
		wd := root // Default.
		if args.WorkingDirectory != "" {
			var err error
			wd, err = mntns.FindInode(ctx, root, nil, args.WorkingDirectory, &remainingTraversals)
			if err != nil {
				return nil, 0, fmt.Errorf("failed to find initial working directory %q: %v", args.WorkingDirectory, err)
			}
			defer wd.DecRef(ctx)
		}
		opener = fsbridge.NewFSLookup(mntns, root, wd)
		fsContext = newFSContext(root, wd, args.Umask)
	}

	tg := k.NewThreadGroup(mntns, args.PIDNamespace, NewSignalHandlers(), linux.SIGCHLD, args.Limits)
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
		Opener:              opener,
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
		MountNamespaceVFS2:      mntnsVFS2,
		ContainerIndex:          args.ContainerIndex,
	}
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
		k.containerInit = append(k.containerInit, tg)
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

	if k.globalInit == nil {
		return fmt.Errorf("kernel contains no tasks")
	}
	if k.started {
		return fmt.Errorf("kernel already started")
	}

	k.started = true
	k.cpuClockTicker = ktime.NewTimer(k.monotonicClock, newKernelCPUClockTicker(k))
	k.cpuClockTicker.Swap(ktime.Setting{
		Enabled: true,
		Period:  linux.ClockTick,
	})
	// If k was created by LoadKernelFrom, timers were stopped during
	// Kernel.SaveTo and need to be resumed. If k was created by NewKernel,
	// this is a no-op.
	k.resumeTimeLocked(k.SupervisorContext())
	// Start task goroutines.
	k.tasks.mu.RLock()
	defer k.tasks.mu.RUnlock()
	for t, tid := range k.tasks.Root.tids {
		t.Start(tid)
	}
	return nil
}

// pauseTimeLocked pauses all Timers and Timekeeper updates.
//
// Preconditions:
// * Any task goroutines running in k must be stopped.
// * k.extMu must be locked.
func (k *Kernel) pauseTimeLocked(ctx context.Context) {
	// k.cpuClockTicker may be nil since Kernel.SaveTo() may be called before
	// Kernel.Start().
	if k.cpuClockTicker != nil {
		k.cpuClockTicker.Pause()
	}

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
			t.fdTable.forEach(ctx, func(_ int32, file *fs.File, fd *vfs.FileDescription, _ FDFlags) {
				if VFS2Enabled {
					if tfd, ok := fd.Impl().(*timerfd.TimerFileDescription); ok {
						tfd.PauseTimer()
					}
				} else {
					if tfd, ok := file.FileOperations.(*oldtimerfd.TimerOperations); ok {
						tfd.PauseTimer()
					}
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
// * Any task goroutines running in k must be stopped.
// * k.extMu must be locked.
func (k *Kernel) resumeTimeLocked(ctx context.Context) {
	if k.cpuClockTicker != nil {
		k.cpuClockTicker.Resume()
	}

	k.timekeeper.ResumeUpdates()
	for t := range k.tasks.Root.tids {
		if t == t.tg.leader {
			t.tg.itimerRealTimer.Resume()
			for _, it := range t.tg.timers {
				it.ResumeTimer()
			}
		}
		if t.fdTable != nil {
			t.fdTable.forEach(ctx, func(_ int32, file *fs.File, fd *vfs.FileDescription, _ FDFlags) {
				if VFS2Enabled {
					if tfd, ok := fd.Impl().(*timerfd.TimerFileDescription); ok {
						tfd.ResumeTimer()
					}
				} else {
					if tfd, ok := file.FileOperations.(*oldtimerfd.TimerOperations); ok {
						tfd.ResumeTimer()
					}
				}
			})
		}
	}
}

func (k *Kernel) incRunningTasks() {
	for {
		tasks := atomic.LoadInt64(&k.runningTasks)
		if tasks != 0 {
			// Standard case. Simply increment.
			if !atomic.CompareAndSwapInt64(&k.runningTasks, tasks, tasks+1) {
				continue
			}
			return
		}

		// Transition from 0 -> 1. Synchronize with other transitions and timer.
		k.runningTasksMu.Lock()
		tasks = atomic.LoadInt64(&k.runningTasks)
		if tasks != 0 {
			// We're no longer the first task, no need to
			// re-enable.
			atomic.AddInt64(&k.runningTasks, 1)
			k.runningTasksMu.Unlock()
			return
		}

		if !k.cpuClockTickerDisabled {
			// Timer was never disabled.
			atomic.StoreInt64(&k.runningTasks, 1)
			k.runningTasksMu.Unlock()
			return
		}

		// We need to update cpuClock for all of the ticks missed while we
		// slept, and then re-enable the timer.
		//
		// The Notify in Swap isn't sufficient. kernelCPUClockTicker.Notify
		// always increments cpuClock by 1 regardless of the number of
		// expirations as a heuristic to avoid over-accounting in cases of CPU
		// throttling.
		//
		// We want to cover the normal case, when all time should be accounted,
		// so we increment for all expirations. Throttling is less concerning
		// here because the ticker is only disabled from Notify. This means
		// that Notify must schedule and compensate for the throttled period
		// before the timer is disabled. Throttling while the timer is disabled
		// doesn't matter, as nothing is running or reading cpuClock anyways.
		//
		// S/R also adds complication, as there are two cases. Recall that
		// monotonicClock will jump forward on restore.
		//
		// 1. If the ticker is enabled during save, then on Restore Notify is
		// called with many expirations, covering the time jump, but cpuClock
		// is only incremented by 1.
		//
		// 2. If the ticker is disabled during save, then after Restore the
		// first wakeup will call this function and cpuClock will be
		// incremented by the number of expirations across the S/R.
		//
		// These cause very different value of cpuClock. But again, since
		// nothing was running while the ticker was disabled, those differences
		// don't matter.
		setting, exp := k.cpuClockTickerSetting.At(k.monotonicClock.Now())
		if exp > 0 {
			atomic.AddUint64(&k.cpuClock, exp)
		}

		// Now that cpuClock is updated it is safe to allow other tasks to
		// transition to running.
		atomic.StoreInt64(&k.runningTasks, 1)

		// N.B. we must unlock before calling Swap to maintain lock ordering.
		//
		// cpuClockTickerDisabled need not wait until after Swap to become
		// true. It is sufficient that the timer *will* be enabled.
		k.cpuClockTickerDisabled = false
		k.runningTasksMu.Unlock()

		// This won't call Notify (unless it's been ClockTick since setting.At
		// above). This means we skip the thread group work in Notify. However,
		// since nothing was running while we were disabled, none of the timers
		// could have expired.
		k.cpuClockTicker.Swap(setting)

		return
	}
}

func (k *Kernel) decRunningTasks() {
	tasks := atomic.AddInt64(&k.runningTasks, -1)
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
// status es. Kill does not wait for tasks to exit.
func (k *Kernel) Kill(es ExitStatus) {
	k.extMu.Lock()
	defer k.extMu.Unlock()
	k.tasks.Kill(es)
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
func (k *Kernel) SendExternalSignal(info *arch.SignalInfo, context string) {
	k.extMu.Lock()
	defer k.extMu.Unlock()
	k.sendExternalSignal(info, context)
}

// SendExternalSignalThreadGroup injects a signal into an specific ThreadGroup.
// This function doesn't skip signals like SendExternalSignal does.
func (k *Kernel) SendExternalSignalThreadGroup(tg *ThreadGroup, info *arch.SignalInfo) error {
	k.extMu.Lock()
	defer k.extMu.Unlock()
	return tg.SendSignal(info)
}

// SendContainerSignal sends the given signal to all processes inside the
// namespace that match the given container ID.
func (k *Kernel) SendContainerSignal(cindex int, info *arch.SignalInfo) error {
	k.extMu.Lock()
	defer k.extMu.Unlock()
	k.tasks.mu.RLock()
	defer k.tasks.mu.RUnlock()

	var lastErr error
	for tg := range k.tasks.Root.tgids {
		if tg.leader.ContainerIndex() == cindex {
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
func (k *Kernel) FeatureSet() *cpuid.FeatureSet {
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

// UpdateRootUTSNamespace updates RootUTSNamespace's hostName and domainName
func (k *Kernel) UpdateRootUTSNamespace(hostName string, domainName string) () {
	k.rootUTSNamespace.SetHostName(hostName)
	k.rootUTSNamespace.SetDomainName(domainName)
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

// SetContainerInit sets the thread group with ID 1 in the PID namespace.
func (k *Kernel) SetContainerInit(tg *ThreadGroup) {
	k.extMu.Lock()
	defer k.extMu.Unlock()
	k.containerInit = append(k.containerInit, tg)
}

func (k *Kernel) ContainerInit(cindex int) *ThreadGroup {
	k.extMu.Lock()
	defer k.extMu.Unlock()
	return k.containerInit[cindex]
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
	return k.realtimeClock
}

// MonotonicClock returns the application CLOCK_MONOTONIC clock.
func (k *Kernel) MonotonicClock() ktime.Clock {
	return k.monotonicClock
}

// CPUClockNow returns the current value of k.cpuClock.
func (k *Kernel) CPUClockNow() uint64 {
	return atomic.LoadUint64(&k.cpuClock)
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
	id := atomic.AddUint32(&k.nextInotifyCookie, 1)
	// Wrap-around is explicitly allowed for inotify event cookies.
	if id == 0 {
		id = atomic.AddUint32(&k.nextInotifyCookie, 1)
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

var _ tcpip.Clock = (*Kernel)(nil)

// NowNanoseconds implements tcpip.Clock.NowNanoseconds.
func (k *Kernel) NowNanoseconds() int64 {
	now, err := k.timekeeper.GetTime(sentrytime.Realtime)
	if err != nil {
		panic("Kernel.NowNanoseconds: " + err.Error())
	}
	return now
}

// NowMonotonic implements tcpip.Clock.NowMonotonic.
func (k *Kernel) NowMonotonic() int64 {
	now, err := k.timekeeper.GetTime(sentrytime.Monotonic)
	if err != nil {
		panic("Kernel.NowMonotonic: " + err.Error())
	}
	return now
}

// AfterFunc implements tcpip.Clock.AfterFunc.
func (k *Kernel) AfterFunc(d time.Duration, f func()) tcpip.Timer {
	return ktime.TcpipAfterFunc(k.realtimeClock, d, f)
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
	return supervisorContext{
		Logger: log.Log(),
		k:      k,
	}
}

// SocketRecord represents a socket recorded in Kernel.socketsVFS2.
//
// +stateify savable
type SocketRecord struct {
	k        *Kernel
	Sock     *refs.WeakRef        // TODO(gvisor.dev/issue/1624): Only used by VFS1.
	SockVFS2 *vfs.FileDescription // Only used by VFS2.
	ID       uint64               // Socket table entry number.
}

// SocketRecordVFS1 represents a socket recorded in Kernel.sockets. It implements
// refs.WeakRefUser for sockets stored in the socket table.
//
// +stateify savable
type SocketRecordVFS1 struct {
	socketEntry
	SocketRecord
}

// WeakRefGone implements refs.WeakRefUser.WeakRefGone.
func (s *SocketRecordVFS1) WeakRefGone(context.Context) {
	s.k.extMu.Lock()
	s.k.sockets.Remove(s)
	s.k.extMu.Unlock()
}

// RecordSocket adds a socket to the system-wide socket table for tracking.
//
// Precondition: Caller must hold a reference to sock.
func (k *Kernel) RecordSocket(sock *fs.File) {
	k.extMu.Lock()
	id := k.nextSocketRecord
	k.nextSocketRecord++
	s := &SocketRecordVFS1{
		SocketRecord: SocketRecord{
			k:  k,
			ID: id,
		},
	}
	s.Sock = refs.NewWeakRef(sock, s)
	k.sockets.PushBack(s)
	k.extMu.Unlock()
}

// RecordSocketVFS2 adds a VFS2 socket to the system-wide socket table for
// tracking.
//
// Precondition: Caller must hold a reference to sock.
//
// Note that the socket table will not hold a reference on the
// vfs.FileDescription.
func (k *Kernel) RecordSocketVFS2(sock *vfs.FileDescription) {
	k.extMu.Lock()
	if _, ok := k.socketsVFS2[sock]; ok {
		panic(fmt.Sprintf("Socket %p added twice", sock))
	}
	id := k.nextSocketRecord
	k.nextSocketRecord++
	s := &SocketRecord{
		k:        k,
		ID:       id,
		SockVFS2: sock,
	}
	k.socketsVFS2[sock] = s
	k.extMu.Unlock()
}

// DeleteSocketVFS2 removes a VFS2 socket from the system-wide socket table.
func (k *Kernel) DeleteSocketVFS2(sock *vfs.FileDescription) {
	k.extMu.Lock()
	delete(k.socketsVFS2, sock)
	k.extMu.Unlock()
}

// ListSockets returns a snapshot of all sockets.
//
// Callers of ListSockets() in VFS2 should use SocketRecord.SockVFS2.TryIncRef()
// to get a reference on a socket in the table.
func (k *Kernel) ListSockets() []*SocketRecord {
	k.extMu.Lock()
	var socks []*SocketRecord
	if VFS2Enabled {
		for _, s := range k.socketsVFS2 {
			socks = append(socks, s)
		}
	} else {
		for s := k.sockets.Front(); s != nil; s = s.Next() {
			socks = append(socks, &s.SocketRecord)
		}
	}
	k.extMu.Unlock()
	return socks
}

// supervisorContext is a privileged context.
type supervisorContext struct {
	context.NoopSleeper
	log.Logger
	k *Kernel
}

// Value implements context.Context.
func (ctx supervisorContext) Value(key interface{}) interface{} {
	switch key {
	case CtxCanTrace:
		// The supervisor context can trace anything. (None of
		// supervisorContext's users are expected to invoke ptrace, but ptrace
		// permissions are required for certain file accesses.)
		return func(*Task, bool) bool { return true }
	case CtxKernel:
		return ctx.k
	case CtxPIDNamespace:
		return ctx.k.tasks.Root
	case CtxUTSNamespace:
		return ctx.k.rootUTSNamespace
	case CtxIPCNamespace:
		ipcns := ctx.k.rootIPCNamespace
		ipcns.IncRef()
		return ipcns
	case auth.CtxCredentials:
		// The supervisor context is global root.
		return auth.NewRootCredentials(ctx.k.rootUserNamespace)
	case fs.CtxRoot:
		if ctx.k.globalInit != nil {
			return ctx.k.globalInit.mounts.Root()
		}
		return nil
	case vfs.CtxRoot:
		if ctx.k.globalInit == nil {
			return vfs.VirtualDentry{}
		}
		root := ctx.k.GlobalInit().Leader().MountNamespaceVFS2().Root()
		root.IncRef()
		return root
	case vfs.CtxMountNamespace:
		if ctx.k.globalInit == nil {
			return nil
		}
		mntns := ctx.k.GlobalInit().Leader().MountNamespaceVFS2()
		mntns.IncRef()
		return mntns
	case fs.CtxDirentCacheLimiter:
		return ctx.k.DirentCacheLimiter
	case inet.CtxStack:
		return ctx.k.RootNetworkNamespace().Stack()
	case ktime.CtxRealtimeClock:
		return ctx.k.RealtimeClock()
	case limits.CtxLimits:
		// No limits apply.
		return limits.NewLimitSet()
	case pgalloc.CtxMemoryFile:
		return ctx.k.mf
	case pgalloc.CtxMemoryFileProvider:
		return ctx.k
	case platform.CtxPlatform:
		return ctx.k
	case uniqueid.CtxGlobalUniqueID:
		return ctx.k.UniqueID()
	case uniqueid.CtxGlobalUniqueIDProvider:
		return ctx.k
	case uniqueid.CtxInotifyCookie:
		return ctx.k.GenerateInotifyCookie()
	case unimpl.CtxEvents:
		return ctx.k
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
	k.unimplementedSyscallEmitter.Emit(&uspb.UnimplementedSyscall{
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

// Release releases resources owned by k.
//
// Precondition: This should only be called after the kernel is fully
// initialized, e.g. after k.Start() has been called.
func (k *Kernel) Release() {
	ctx := k.SupervisorContext()
	if VFS2Enabled {
		k.hostMount.DecRef(ctx)
		k.pipeMount.DecRef(ctx)
		k.shmMount.DecRef(ctx)
		k.socketMount.DecRef(ctx)
		k.vfs.Release(ctx)
	}
	k.timekeeper.Destroy()
	k.vdso.Release(ctx)
}

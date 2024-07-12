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

package boot

import (
	"errors"
	"fmt"
	"path"
	"strconv"
	"sync"
	gtime "time"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/cleanup"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/control/server"
	"gvisor.dev/gvisor/pkg/fd"
	"gvisor.dev/gvisor/pkg/fspath"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/control"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/erofs"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/seccheck"
	"gvisor.dev/gvisor/pkg/sentry/socket/netstack"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/state/statefile"
	"gvisor.dev/gvisor/pkg/urpc"
	"gvisor.dev/gvisor/runsc/boot/procfs"
	"gvisor.dev/gvisor/runsc/config"
	"gvisor.dev/gvisor/runsc/specutils"
)

const (
	// ContMgrCheckpoint checkpoints a container.
	ContMgrCheckpoint = "containerManager.Checkpoint"

	// ContMgrCreateSubcontainer creates a sub-container.
	ContMgrCreateSubcontainer = "containerManager.CreateSubcontainer"

	// ContMgrDestroySubcontainer is used to stop a sub-container and free all
	// associated resources in the sandbox.
	ContMgrDestroySubcontainer = "containerManager.DestroySubcontainer"

	// ContMgrEvent gets stats about the container used by "runsc events".
	ContMgrEvent = "containerManager.Event"

	// ContMgrExecuteAsync executes a command in a container.
	ContMgrExecuteAsync = "containerManager.ExecuteAsync"

	// ContMgrPortForward starts port forwarding with the sandbox.
	ContMgrPortForward = "containerManager.PortForward"

	// ContMgrProcesses lists processes running in a container.
	ContMgrProcesses = "containerManager.Processes"

	// ContMgrRestore restores a container from a statefile.
	ContMgrRestore = "containerManager.Restore"

	// ContMgrRestoreSubcontainer restores a container from a statefile.
	ContMgrRestoreSubcontainer = "containerManager.RestoreSubcontainer"

	// ContMgrPause pauses all tasks, blocking until they are stopped.
	ContMgrPause = "containerManager.Pause"

	// ContMgrResume resumes all tasks.
	ContMgrResume = "containerManager.Resume"

	// ContMgrSignal sends a signal to a container.
	ContMgrSignal = "containerManager.Signal"

	// ContMgrStartSubcontainer starts a sub-container inside a running sandbox.
	ContMgrStartSubcontainer = "containerManager.StartSubcontainer"

	// ContMgrWait waits on the init process of the container and returns its
	// ExitStatus.
	ContMgrWait = "containerManager.Wait"

	// ContMgrWaitPID waits on a process with a certain PID in the sandbox and
	// return its ExitStatus.
	ContMgrWaitPID = "containerManager.WaitPID"

	// ContMgrWaitCheckpoint waits for the Kernel to have been successfully
	// checkpointed n-1 times, then waits for either the n-th successful
	// checkpoint (in which case it returns nil) or any number of failed
	// checkpoints (in which case it returns an error returned by any such
	// failure).
	ContMgrWaitCheckpoint = "containerManager.WaitCheckpoint"

	// ContMgrRootContainerStart starts a new sandbox with a root container.
	ContMgrRootContainerStart = "containerManager.StartRoot"

	// ContMgrCreateTraceSession starts a trace session.
	ContMgrCreateTraceSession = "containerManager.CreateTraceSession"

	// ContMgrDeleteTraceSession deletes a trace session.
	ContMgrDeleteTraceSession = "containerManager.DeleteTraceSession"

	// ContMgrListTraceSessions lists a trace session.
	ContMgrListTraceSessions = "containerManager.ListTraceSessions"

	// ContMgrProcfsDump dumps sandbox procfs state.
	ContMgrProcfsDump = "containerManager.ProcfsDump"

	// ContMgrMount mounts a filesystem in a container.
	ContMgrMount = "containerManager.Mount"

	// ContMgrContainerRuntimeState returns the runtime state of a container.
	ContMgrContainerRuntimeState = "containerManager.ContainerRuntimeState"
)

const (
	// NetworkCreateLinksAndRoutes creates links and routes in a network stack.
	NetworkCreateLinksAndRoutes = "Network.CreateLinksAndRoutes"

	// DebugStacks collects sandbox stacks for debugging.
	DebugStacks = "debug.Stacks"
)

// Profiling related commands (see pprof.go for more details).
const (
	ProfileCPU   = "Profile.CPU"
	ProfileHeap  = "Profile.Heap"
	ProfileBlock = "Profile.Block"
	ProfileMutex = "Profile.Mutex"
	ProfileTrace = "Profile.Trace"
)

// Logging related commands (see logging.go for more details).
const (
	LoggingChange = "Logging.Change"
)

// Usage related commands (see usage.go for more details).
const (
	UsageCollect = "Usage.Collect"
	UsageUsageFD = "Usage.UsageFD"
)

// Metrics related commands (see metrics.go).
const (
	MetricsGetRegistered = "Metrics.GetRegisteredMetrics"
	MetricsExport        = "Metrics.Export"
)

// Commands for interacting with cgroupfs within the sandbox.
const (
	CgroupsReadControlFiles  = "Cgroups.ReadControlFiles"
	CgroupsWriteControlFiles = "Cgroups.WriteControlFiles"
)

// controller holds the control server, and is used for communication into the
// sandbox.
type controller struct {
	// srv is the control server.
	srv *server.Server

	// manager holds the containerManager methods.
	manager *containerManager
}

// newController creates a new controller. The caller must call
// controller.srv.StartServing() to start the controller.
func newController(fd int, l *Loader) (*controller, error) {
	srv, err := server.CreateFromFD(fd)
	if err != nil {
		return nil, err
	}

	ctrl := &controller{
		manager: &containerManager{
			startChan:       make(chan struct{}),
			startResultChan: make(chan error),
			l:               l,
		},
		srv: srv,
	}
	ctrl.registerHandlers()
	return ctrl, nil
}

func (c *controller) registerHandlers() {
	l := c.manager.l
	c.srv.Register(c.manager)
	c.srv.Register(&control.Cgroups{Kernel: l.k})
	c.srv.Register(&control.Lifecycle{Kernel: l.k})
	c.srv.Register(&control.Logging{})
	c.srv.Register(&control.Proc{Kernel: l.k})
	c.srv.Register(&control.State{Kernel: l.k})
	c.srv.Register(&control.Usage{Kernel: l.k})
	c.srv.Register(&control.Metrics{})
	c.srv.Register(&debug{})

	if eps, ok := l.k.RootNetworkNamespace().Stack().(*netstack.Stack); ok {
		c.srv.Register(&Network{
			Stack:  eps.Stack,
			Kernel: l.k,
		})
	}
	if l.root.conf.ProfileEnable {
		c.srv.Register(control.NewProfile(l.k))
	}
}

// refreshHandlers resets the server and re-registers all handlers using l.
// Useful when l.k has been replaced (e.g. during a restore).
func (c *controller) refreshHandlers() {
	c.srv.ResetServer()
	c.registerHandlers()
}

// stopRPCTimeout is the time for clients to finish making any RPCs. Note that
// ongoing RPCs after this timeout still run to completion.
const stopRPCTimeout = 15 * gtime.Second

func (c *controller) stop() {
	c.srv.Stop(stopRPCTimeout)
}

// containerManager manages sandbox containers.
type containerManager struct {
	// startChan is used to signal when the root container process should
	// be started.
	startChan chan struct{}

	// startResultChan is used to signal when the root container has
	// started. Any errors encountered during startup will be sent to the
	// channel. A nil value indicates success.
	startResultChan chan error

	// l is the loader that creates containers and sandboxes.
	l *Loader

	// restorer is set when the sandbox in being restored. It stores the state
	// of all containers and perform all actions required by restore.
	restorer *restorer
}

// StartRoot will start the root container process.
func (cm *containerManager) StartRoot(cid *string, _ *struct{}) error {
	log.Debugf("containerManager.StartRoot, cid: %s", *cid)
	// Tell the root container to start and wait for the result.
	return cm.onStart()
}

// onStart notifies that sandbox is ready to start and wait for the result.
func (cm *containerManager) onStart() error {
	cm.startChan <- struct{}{}
	if err := <-cm.startResultChan; err != nil {
		return fmt.Errorf("starting sandbox: %v", err)
	}
	return nil
}

// Processes retrieves information about processes running in the sandbox.
func (cm *containerManager) Processes(cid *string, out *[]*control.Process) error {
	log.Debugf("containerManager.Processes, cid: %s", *cid)
	return control.Processes(cm.l.k, *cid, out)
}

// CreateArgs contains arguments to the Create method.
type CreateArgs struct {
	// CID is the ID of the container to start.
	CID string

	// FilePayload may contain a TTY file for the terminal, if enabled.
	urpc.FilePayload
}

// CreateSubcontainer creates a container within a sandbox.
func (cm *containerManager) CreateSubcontainer(args *CreateArgs, _ *struct{}) error {
	log.Debugf("containerManager.CreateSubcontainer: %s", args.CID)

	if len(args.Files) > 1 {
		return fmt.Errorf("start arguments must have at most 1 files for TTY")
	}
	var tty *fd.FD
	if len(args.Files) == 1 {
		var err error
		tty, err = fd.NewFromFile(args.Files[0])
		if err != nil {
			return fmt.Errorf("error dup'ing TTY file: %w", err)
		}
	}
	return cm.l.createSubcontainer(args.CID, tty)
}

// StartArgs contains arguments to the Start method.
type StartArgs struct {
	// Spec is the spec of the container to start.
	Spec *specs.Spec

	// Config is the runsc-specific configuration for the sandbox.
	Conf *config.Config

	// CID is the ID of the container to start.
	CID string

	// NumGoferFilestoreFDs is the number of gofer filestore FDs donated.
	NumGoferFilestoreFDs int

	// IsDevIoFilePresent indicates whether the dev gofer FD is present.
	IsDevIoFilePresent bool

	// GoferMountConfs contains information about how the gofer mounts have been
	// configured. The first entry is for rootfs and the following entries are
	// for bind mounts in Spec.Mounts (in the same order).
	GoferMountConfs []GoferMountConf

	// FilePayload contains, in order:
	//   * stdin, stdout, and stderr (optional: if terminal is disabled).
	//   * file descriptors to gofer-backing host files (optional).
	//   * file descriptor for /dev gofer connection (optional)
	//   * file descriptors to connect to gofer to serve the root filesystem.
	urpc.FilePayload
}

// StartSubcontainer runs a created container within a sandbox.
func (cm *containerManager) StartSubcontainer(args *StartArgs, _ *struct{}) error {
	// Validate arguments.
	if args == nil {
		return errors.New("start missing arguments")
	}
	log.Debugf("containerManager.StartSubcontainer, cid: %s, args: %+v", args.CID, args)
	if args.Spec == nil {
		return errors.New("start arguments missing spec")
	}
	if args.Conf == nil {
		return errors.New("start arguments missing config")
	}
	if args.CID == "" {
		return errors.New("start argument missing container ID")
	}
	expectedFDs := 1 // At least one FD for the root filesystem.
	expectedFDs += args.NumGoferFilestoreFDs
	if args.IsDevIoFilePresent {
		expectedFDs++
	}
	if !args.Spec.Process.Terminal {
		expectedFDs += 3
	}
	if len(args.Files) < expectedFDs {
		return fmt.Errorf("start arguments must contain at least %d FDs, but only got %d", expectedFDs, len(args.Files))
	}

	// All validation passed, logs the spec for debugging.
	specutils.LogSpecDebug(args.Spec, args.Conf.OCISeccomp)

	goferFiles := args.Files
	var stdios []*fd.FD
	if !args.Spec.Process.Terminal {
		// When not using a terminal, stdios come as the first 3 files in the
		// payload.
		var err error
		stdios, err = fd.NewFromFiles(goferFiles[:3])
		if err != nil {
			return fmt.Errorf("error dup'ing stdio files: %w", err)
		}
		goferFiles = goferFiles[3:]
	}
	defer func() {
		for _, fd := range stdios {
			_ = fd.Close()
		}
	}()

	var goferFilestoreFDs []*fd.FD
	for i := 0; i < args.NumGoferFilestoreFDs; i++ {
		goferFilestoreFD, err := fd.NewFromFile(goferFiles[i])
		if err != nil {
			return fmt.Errorf("error dup'ing gofer filestore file: %w", err)
		}
		goferFilestoreFDs = append(goferFilestoreFDs, goferFilestoreFD)
	}
	goferFiles = goferFiles[args.NumGoferFilestoreFDs:]
	defer func() {
		for _, fd := range goferFilestoreFDs {
			_ = fd.Close()
		}
	}()

	var devGoferFD *fd.FD
	if args.IsDevIoFilePresent {
		var err error
		devGoferFD, err = fd.NewFromFile(goferFiles[0])
		if err != nil {
			return fmt.Errorf("error dup'ing dev gofer file: %w", err)
		}
		goferFiles = goferFiles[1:]
		defer devGoferFD.Close()
	}

	goferFDs, err := fd.NewFromFiles(goferFiles)
	if err != nil {
		return fmt.Errorf("error dup'ing gofer files: %w", err)
	}
	defer func() {
		for _, fd := range goferFDs {
			_ = fd.Close()
		}
	}()

	if err := cm.l.startSubcontainer(args.Spec, args.Conf, args.CID, stdios, goferFDs, goferFilestoreFDs, devGoferFD, args.GoferMountConfs); err != nil {
		log.Debugf("containerManager.StartSubcontainer failed, cid: %s, args: %+v, err: %v", args.CID, args, err)
		return err
	}
	log.Debugf("Container started, cid: %s", args.CID)
	return nil
}

// DestroySubcontainer stops a container if it is still running and cleans up
// its filesystem.
func (cm *containerManager) DestroySubcontainer(cid *string, _ *struct{}) error {
	log.Debugf("containerManager.DestroySubcontainer, cid: %s", *cid)
	return cm.l.destroySubcontainer(*cid)
}

// ExecuteAsync starts running a command on a created or running sandbox. It
// returns the PID of the new process.
func (cm *containerManager) ExecuteAsync(args *control.ExecArgs, pid *int32) error {
	log.Debugf("containerManager.ExecuteAsync, cid: %s, args: %+v", args.ContainerID, args)
	tgid, err := cm.l.executeAsync(args)
	if err != nil {
		log.Debugf("containerManager.ExecuteAsync failed, cid: %s, args: %+v, err: %v", args.ContainerID, args, err)
		return err
	}
	*pid = int32(tgid)
	return nil
}

// Checkpoint pauses a sandbox and saves its state.
func (cm *containerManager) Checkpoint(o *control.SaveOpts, _ *struct{}) error {
	log.Debugf("containerManager.Checkpoint")
	return cm.l.save(o)
}

// PortForwardOpts contains options for port forwarding to a port in a
// container.
type PortForwardOpts struct {
	// FilePayload contains one fd for a UDS (or local port) used for port
	// forwarding.
	urpc.FilePayload

	// ContainerID is the container for the process being executed.
	ContainerID string
	// Port is the port to to forward.
	Port uint16
}

// PortForward initiates a port forward to the container.
func (cm *containerManager) PortForward(opts *PortForwardOpts, _ *struct{}) error {
	log.Debugf("containerManager.PortForward, cid: %s, port: %d", opts.ContainerID, opts.Port)
	if err := cm.l.portForward(opts); err != nil {
		log.Debugf("containerManager.PortForward failed, opts: %+v, err: %v", opts, err)
		return err
	}
	return nil
}

// RestoreOpts contains options related to restoring a container's file system.
type RestoreOpts struct {
	// FilePayload contains the state file to be restored, followed in order by:
	// 1. checkpoint state file.
	// 2. optional checkpoint pages metadata file.
	// 3. optional checkpoint pages file.
	// 4. optional platform device file.
	urpc.FilePayload
	HavePagesFile  bool
	HaveDeviceFile bool
}

// Restore loads a container from a statefile.
// The container's current kernel is destroyed, a restore environment is
// created, and the kernel is recreated with the restore state file. The
// container then sends the signal to start.
func (cm *containerManager) Restore(o *RestoreOpts, _ *struct{}) error {
	log.Debugf("containerManager.Restore")

	if cm.l.state == restoring {
		return fmt.Errorf("restore is already in progress")
	}
	if cm.l.state == started {
		return fmt.Errorf("cannot restore a started container")
	}
	if len(o.Files) == 0 {
		return fmt.Errorf("at least one file must be passed to Restore")
	}

	stateFile, err := o.ReleaseFD(0)
	if err != nil {
		return err
	}

	var stat unix.Stat_t
	if err := unix.Fstat(stateFile.FD(), &stat); err != nil {
		return err
	}
	if stat.Size == 0 {
		return fmt.Errorf("statefile cannot be empty")
	}

	cm.restorer = &restorer{restoreDone: cm.onRestoreDone, stateFile: stateFile}
	cm.l.restoreWaiters = sync.NewCond(&cm.l.mu)
	cm.l.state = restoring

	fileIdx := 1
	if o.HavePagesFile {
		cm.restorer.pagesMetadata, err = o.ReleaseFD(fileIdx)
		if err != nil {
			return err
		}
		fileIdx++

		cm.restorer.pagesFile, err = o.ReleaseFD(fileIdx)
		if err != nil {
			return err
		}
		fileIdx++
	}

	if o.HaveDeviceFile {
		cm.restorer.deviceFile, err = o.ReleaseFD(fileIdx)
		if err != nil {
			return err
		}
		fileIdx++
	}

	if fileIdx < len(o.Files) {
		return fmt.Errorf("more files passed to Restore than expected")
	}

	// Pause the kernel while we build a new one.
	cm.l.k.Pause()

	metadata, err := statefile.MetadataUnsafe(cm.restorer.stateFile)
	if err != nil {
		return fmt.Errorf("reading metadata from statefile: %w", err)
	}
	var count int
	countStr, ok := metadata["container_count"]
	if !ok {
		// TODO(gvisor.dev/issue/1956): Add container count with syscall save
		// trigger. For now, assume that only a single container exists if metadata
		// isn't present.
		//
		// -return errors.New("container count not present in state file")
		count = 1
	} else {
		count, err = strconv.Atoi(countStr)
		if err != nil {
			return fmt.Errorf("invalid container count: %w", err)
		}
		if count < 1 {
			return fmt.Errorf("invalid container count value: %v", count)
		}
	}
	cm.restorer.totalContainers = count
	log.Infof("Restoring a total of %d containers", cm.restorer.totalContainers)

	if _, err := unix.Seek(stateFile.FD(), 0, 0); err != nil {
		return fmt.Errorf("rewinding state file: %w", err)
	}

	return cm.restorer.restoreContainerInfo(cm.l, &cm.l.root)
}

func (cm *containerManager) onRestoreDone() error {
	if err := cm.onStart(); err != nil {
		return err
	}

	cm.l.restoreWaiters.Broadcast()
	cm.restorer = nil
	return nil
}

func (cm *containerManager) RestoreSubcontainer(args *StartArgs, _ *struct{}) error {
	log.Debugf("containerManager.RestoreSubcontainer, cid: %s, args: %+v", args.CID, args)

	if cm.l.state != restoring {
		return fmt.Errorf("sandbox is not being restored, cannot restore subcontainer")
	}

	// Validate arguments.
	if args.Spec == nil {
		return errors.New("start arguments missing spec")
	}
	if args.Conf == nil {
		return errors.New("start arguments missing config")
	}
	if args.CID == "" {
		return errors.New("start argument missing container ID")
	}
	expectedFDs := 1 // At least one FD for the root filesystem.
	expectedFDs += args.NumGoferFilestoreFDs
	if !args.Spec.Process.Terminal {
		expectedFDs += 3
	}
	if len(args.Files) < expectedFDs {
		return fmt.Errorf("restore arguments must contain at least %d FDs, but only got %d", expectedFDs, len(args.Files))
	}

	// All validation passed, logs the spec for debugging.
	specutils.LogSpecDebug(args.Spec, args.Conf.OCISeccomp)

	goferFiles := args.Files
	var stdios []*fd.FD
	if !args.Spec.Process.Terminal {
		// When not using a terminal, stdios come as the first 3 files in the
		// payload.
		var err error
		stdios, err = fd.NewFromFiles(goferFiles[:3])
		if err != nil {
			return fmt.Errorf("error dup'ing stdio files: %w", err)
		}
		goferFiles = goferFiles[3:]
	}

	var goferFilestoreFDs []*fd.FD
	for i := 0; i < args.NumGoferFilestoreFDs; i++ {
		overlayFilestoreFD, err := fd.NewFromFile(goferFiles[i])
		if err != nil {
			return fmt.Errorf("error dup'ing overlay filestore file: %w", err)
		}
		goferFilestoreFDs = append(goferFilestoreFDs, overlayFilestoreFD)
	}
	goferFiles = goferFiles[args.NumGoferFilestoreFDs:]

	var devGoferFD *fd.FD
	if args.IsDevIoFilePresent {
		var err error
		devGoferFD, err = fd.NewFromFile(goferFiles[0])
		if err != nil {
			return fmt.Errorf("error dup'ing dev gofer file: %w", err)
		}
		goferFiles = goferFiles[1:]
	}

	goferFDs, err := fd.NewFromFiles(goferFiles)
	if err != nil {
		return fmt.Errorf("error dup'ing gofer files: %w", err)
	}

	if err := cm.restorer.restoreSubcontainer(args.Spec, args.Conf, cm.l, args.CID, stdios, goferFDs, goferFilestoreFDs, devGoferFD, args.GoferMountConfs); err != nil {
		log.Debugf("containerManager.RestoreSubcontainer failed, cid: %s, args: %+v, err: %v", args.CID, args, err)
		return err
	}
	log.Debugf("Container restored, cid: %s", args.CID)
	return nil
}

// Pause pauses all tasks, blocking until they are stopped.
func (cm *containerManager) Pause(_, _ *struct{}) error {
	cm.l.k.Pause()
	return nil
}

// Resume resumes all tasks.
func (cm *containerManager) Resume(_, _ *struct{}) error {
	cm.l.k.Unpause()
	return postResumeImpl(cm.l.k)
}

// Wait waits for the init process in the given container.
func (cm *containerManager) Wait(cid *string, waitStatus *uint32) error {
	log.Debugf("containerManager.Wait, cid: %s", *cid)
	err := cm.l.waitContainer(*cid, waitStatus)
	log.Debugf("containerManager.Wait returned, cid: %s, waitStatus: %#x, err: %v", *cid, *waitStatus, err)
	return err
}

// WaitPIDArgs are arguments to the WaitPID method.
type WaitPIDArgs struct {
	// PID is the PID in the container's PID namespace.
	PID int32

	// CID is the container ID.
	CID string
}

// WaitPID waits for the process with PID 'pid' in the sandbox.
func (cm *containerManager) WaitPID(args *WaitPIDArgs, waitStatus *uint32) error {
	log.Debugf("containerManager.Wait, cid: %s, pid: %d", args.CID, args.PID)
	err := cm.l.waitPID(kernel.ThreadID(args.PID), args.CID, waitStatus)
	log.Debugf("containerManager.Wait, cid: %s, pid: %d, waitStatus: %#x, err: %v", args.CID, args.PID, *waitStatus, err)
	return err
}

// WaitCheckpoint waits for the Kernel to have been successfully checkpointed
// n-1 times, then waits for either the n-th successful checkpoint (in which
// case it returns nil) or any number of failed checkpoints (in which case it
// returns an error returned by any such failure).
func (cm *containerManager) WaitCheckpoint(n *uint32, _ *struct{}) error {
	err := cm.l.k.WaitCheckpoint(*n)
	log.Debugf("containerManager.WaitCheckpoint, n = %d, err = %v", *n, err)
	return err
}

// SignalDeliveryMode enumerates different signal delivery modes.
type SignalDeliveryMode int

const (
	// DeliverToProcess delivers the signal to the container process with
	// the specified PID. If PID is 0, then the container init process is
	// signaled.
	DeliverToProcess SignalDeliveryMode = iota

	// DeliverToAllProcesses delivers the signal to all processes in the
	// container. PID must be 0.
	DeliverToAllProcesses

	// DeliverToForegroundProcessGroup delivers the signal to the
	// foreground process group in the same TTY session as the specified
	// process. If PID is 0, then the signal is delivered to the foreground
	// process group for the TTY for the init process.
	DeliverToForegroundProcessGroup
)

func (s SignalDeliveryMode) String() string {
	switch s {
	case DeliverToProcess:
		return "Process"
	case DeliverToAllProcesses:
		return "All"
	case DeliverToForegroundProcessGroup:
		return "Foreground Process Group"
	}
	return fmt.Sprintf("unknown signal delivery mode: %d", s)
}

// SignalArgs are arguments to the Signal method.
type SignalArgs struct {
	// CID is the container ID.
	CID string

	// Signo is the signal to send to the process.
	Signo int32

	// PID is the process ID in the given container that will be signaled,
	// relative to the root PID namespace, not the container's.
	// If 0, the root container will be signalled.
	PID int32

	// Mode is the signal delivery mode.
	Mode SignalDeliveryMode
}

// Signal sends a signal to one or more processes in a container. If args.PID
// is 0, then the container init process is used. Depending on the
// args.SignalDeliveryMode option, the signal may be sent directly to the
// indicated process, to all processes in the container, or to the foreground
// process group.
func (cm *containerManager) Signal(args *SignalArgs, _ *struct{}) error {
	log.Debugf("containerManager.Signal: cid: %s, PID: %d, signal: %d, mode: %v", args.CID, args.PID, args.Signo, args.Mode)
	return cm.l.signal(args.CID, args.PID, args.Signo, args.Mode)
}

// CreateTraceSessionArgs are arguments to the CreateTraceSession method.
type CreateTraceSessionArgs struct {
	Config seccheck.SessionConfig
	Force  bool
	urpc.FilePayload
}

// CreateTraceSession creates a new trace session.
func (cm *containerManager) CreateTraceSession(args *CreateTraceSessionArgs, _ *struct{}) error {
	log.Debugf("containerManager.CreateTraceSession: config: %+v", args.Config)
	for i, sinkFile := range args.Files {
		if sinkFile != nil {
			fd, err := fd.NewFromFile(sinkFile)
			if err != nil {
				return err
			}
			args.Config.Sinks[i].FD = fd
		}
	}
	return seccheck.Create(&args.Config, args.Force)
}

// DeleteTraceSession deletes an existing trace session.
func (cm *containerManager) DeleteTraceSession(name *string, _ *struct{}) error {
	log.Debugf("containerManager.DeleteTraceSession: name: %q", *name)
	return seccheck.Delete(*name)
}

// ListTraceSessions lists trace sessions.
func (cm *containerManager) ListTraceSessions(_ *struct{}, out *[]seccheck.SessionConfig) error {
	log.Debugf("containerManager.ListTraceSessions")
	seccheck.List(out)
	return nil
}

// ProcfsDump dumps procfs state of the sandbox.
func (cm *containerManager) ProcfsDump(_ *struct{}, out *[]procfs.ProcessProcfsDump) error {
	log.Debugf("containerManager.ProcfsDump")
	ts := cm.l.k.TaskSet()
	pidns := ts.Root
	*out = make([]procfs.ProcessProcfsDump, 0, len(cm.l.processes))
	for _, tg := range pidns.ThreadGroups() {
		pid := pidns.IDOfThreadGroup(tg)
		procDump, err := procfs.Dump(tg.Leader(), pid, pidns)
		if err != nil {
			log.Warningf("skipping procfs dump for PID %s: %v", pid, err)
			continue
		}
		*out = append(*out, procDump)
	}
	return nil
}

// MountArgs contains arguments to the Mount method.
type MountArgs struct {
	// ContainerID is the container in which we will mount the filesystem.
	ContainerID string

	// Source is the mount source.
	Source string

	// Destination is the mount target.
	Destination string

	// FsType is the filesystem type.
	FsType string

	// FilePayload contains the source image FD, if required by the filesystem.
	urpc.FilePayload
}

const initTID kernel.ThreadID = 1

// Mount mounts a filesystem in a container.
func (cm *containerManager) Mount(args *MountArgs, _ *struct{}) error {
	log.Debugf("containerManager.Mount, cid: %s, args: %+v", args.ContainerID, args)

	var cu cleanup.Cleanup
	defer cu.Clean()

	eid := execID{cid: args.ContainerID}
	ep, ok := cm.l.processes[eid]
	if !ok {
		return fmt.Errorf("container %v is deleted", args.ContainerID)
	}
	if ep.tg == nil {
		return fmt.Errorf("container %v isn't started", args.ContainerID)
	}

	t := ep.tg.PIDNamespace().TaskWithID(initTID)
	if t == nil {
		return fmt.Errorf("failed to find init process")
	}

	source := args.Source
	dest := path.Clean(args.Destination)
	fstype := args.FsType

	if dest[0] != '/' {
		return fmt.Errorf("absolute path must be provided for destination")
	}

	var opts vfs.MountOptions
	switch fstype {
	case erofs.Name:
		if len(args.FilePayload.Files) != 1 {
			return fmt.Errorf("exactly one image file must be provided")
		}

		imageFD, err := unix.Dup(int(args.FilePayload.Files[0].Fd()))
		if err != nil {
			return fmt.Errorf("failed to dup image FD: %v", err)
		}
		cu.Add(func() { unix.Close(imageFD) })

		opts = vfs.MountOptions{
			ReadOnly: true,
			GetFilesystemOptions: vfs.GetFilesystemOptions{
				InternalMount: true,
				Data:          fmt.Sprintf("ifd=%d", imageFD),
			},
		}

	default:
		return fmt.Errorf("unsupported filesystem type: %v", fstype)
	}

	ctx := context.Background()
	root := t.FSContext().RootDirectory()
	defer root.DecRef(ctx)

	pop := vfs.PathOperation{
		Root:  root,
		Start: root,
		Path:  fspath.Parse(dest),
	}

	if _, err := t.Kernel().VFS().MountAt(ctx, t.Credentials(), source, &pop, fstype, &opts); err != nil {
		return err
	}
	log.Infof("Mounted %q to %q type: %s, internal-options: %q, in container %q", source, dest, fstype, opts.GetFilesystemOptions.Data, args.ContainerID)
	cu.Release()
	return nil
}

// ContainerRuntimeState returns the runtime state of a container.
func (cm *containerManager) ContainerRuntimeState(cid *string, state *ContainerRuntimeState) error {
	log.Debugf("containerManager.ContainerRuntimeState: cid: %s", *cid)
	*state = cm.l.containerRuntimeState(*cid)
	return nil
}

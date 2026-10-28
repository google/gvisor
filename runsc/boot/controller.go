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
	"io"
	"path"
	"strconv"
	gtime "time"

	"golang.org/x/sys/unix"

	"gvisor.dev/gvisor/pkg/cleanup"
	"gvisor.dev/gvisor/pkg/control/server"
	"gvisor.dev/gvisor/pkg/fd"
	"gvisor.dev/gvisor/pkg/fspath"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/control"
	"gvisor.dev/gvisor/pkg/sentry/control/controlapi"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/erofs"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/pgalloc"
	"gvisor.dev/gvisor/pkg/sentry/seccheck"
	"gvisor.dev/gvisor/pkg/sentry/socket/netstack"
	"gvisor.dev/gvisor/pkg/sentry/socket/plugin"
	"gvisor.dev/gvisor/pkg/sentry/state"
	"gvisor.dev/gvisor/pkg/sentry/state/checkpointfiles"
	"gvisor.dev/gvisor/pkg/sentry/state/stateio"
	"gvisor.dev/gvisor/pkg/sentry/state/stateipc"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/tcpip/link/fdbased"
	"gvisor.dev/gvisor/pkg/unet"
	"gvisor.dev/gvisor/pkg/urpc"
	"gvisor.dev/gvisor/runsc/boot/procfs"
	"gvisor.dev/gvisor/runsc/boot/sentryapi"
	"gvisor.dev/gvisor/runsc/specutils"
	"gvisor.dev/gvisor/runsc/starttime"
	"gvisor.dev/gvisor/runsc/version"
)

// controller holds the control server, and is used for communication into the
// sandbox.
type controller struct {
	// srv is the control server.
	srv *server.Server

	// manager holds the containerManager methods.
	manager *containerManager

	// stopRPCTimeout is the grace period given to in-flight RPCs when the
	// control server is shut down. See the documentation of urpc.Server.Stop
	// for the precise semantics. Configured via --control-rpc-stop-timeout.
	stopRPCTimeout gtime.Duration
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
		srv:            srv,
		stopRPCTimeout: l.root.conf.ControlRPCStopTimeout,
	}
	ctrl.registerHandlers()
	return ctrl, nil
}

func (c *controller) registerHandlers() {
	l := c.manager.l
	c.srv.Register(c.manager)
	c.srv.Register(&control.Cgroups{Kernel: l.k})
	c.srv.Register(&control.Fs{Kernel: l.k})
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

	if pluginStack, ok := l.k.RootNetworkNamespace().Stack().(plugin.PluginStack); ok {
		c.srv.Register(&Network{PluginStack: pluginStack})
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

func (c *controller) stop() {
	c.srv.Stop(c.stopRPCTimeout)
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
	cm.l.mu.Lock()
	state := cm.l.state
	cm.l.mu.Unlock()
	if state != created {
		return fmt.Errorf("sandbox is not in created state, cannot start root container: state=%s", state)
	}
	defer cm.l.lifecycleCPUs.releaseForRestore()
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
func (cm *containerManager) Processes(cid *string, out *[]*controlapi.Process) error {
	log.Debugf("containerManager.Processes, cid: %s", *cid)
	return control.Processes(cm.l.k, *cid, out)
}

// CreateSubcontainer creates a container within a sandbox.
func (cm *containerManager) CreateSubcontainer(args *sentryapi.CreateArgs, _ *struct{}) error {
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

// StartSubcontainer runs a created container within a sandbox.
func (cm *containerManager) StartSubcontainer(args *sentryapi.StartArgs, _ *struct{}) error {
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
	cm.l.mu.Lock()
	state := cm.l.state
	cm.l.mu.Unlock()
	if state != started && state != restored {
		if state == restoringUnstarted {
			// Translate the `runsc start` to `runsc restore`.
			// TODO(b/441106898): Move this to the shim once single-shim-per-pod is implemented.
			log.Warningf("StartSubcontainer called on a restoring sandbox, restoring subcontainer instead: id=%s", args.CID)
			return cm.RestoreSubcontainer(args, nil)
		}
		return fmt.Errorf("sandbox is not in started state, cannot start subcontainer: state=%s", state)
	}
	expectedFDs := 1 // At least one FD for the root filesystem.
	expectedFDs += args.NumGoferFilestoreFDs
	if args.IsDevIoFilePresent {
		expectedFDs++
	}
	if !args.Spec.Process.Terminal {
		expectedFDs += 3
	}
	if args.IsRootfsUpperTarFilePresent {
		if cm.l.fsRestore != nil {
			return fmt.Errorf("rootfs upper tar file is mutually exclusive with filesystem checkpoint restore")
		}
		expectedFDs++
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

	var rootfsUpperTarFD *fd.FD
	if args.IsRootfsUpperTarFilePresent {
		var err error
		rootfsUpperTarFD, err = fd.NewFromFile(goferFiles[0])
		if err != nil {
			return fmt.Errorf("error dup'ing rootfs upper tar file: %w", err)
		}
		goferFiles = goferFiles[1:]
		defer rootfsUpperTarFD.Close()
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

	if err := cm.l.startSubcontainer(args.Spec, args.Conf, args.CID, stdios, goferFDs, goferFilestoreFDs, devGoferFD, args.GoferMountConfs, rootfsUpperTarFD); err != nil {
		log.Debugf("containerManager.StartSubcontainer failed, cid: %s, args: %+v, err: %v", args.CID, args, err)
		return err
	}
	log.Debugf("Container started, cid: %s", args.CID)
	cm.l.releaseStartupHeapWhenIdle()
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
func (cm *containerManager) Checkpoint(o *controlapi.SaveOpts, _ *struct{}) error {
	log.Debugf("containerManager.Checkpoint")
	o.RunscVersion = version.Version()
	cm.l.lifecycleCPUs.hold()
	defer cm.l.lifecycleCPUs.release()
	return cm.l.save(o)
}

// PortForward initiates a port forward to the container.
func (cm *containerManager) PortForward(opts *sentryapi.PortForwardOpts, _ *struct{}) error {
	log.Debugf("containerManager.PortForward, cid: %s, port: %d", opts.ContainerID, opts.Port)
	if err := cm.l.portForward(opts); err != nil {
		log.Debugf("containerManager.PortForward failed, opts: %+v, err: %v", opts, err)
		return err
	}
	return nil
}

// Restore loads a container from a statefile.
// The container's current kernel is destroyed, a restore environment is
// created, and the kernel is recreated with the restore state file. The
// container then sends the signal to start.
func (cm *containerManager) Restore(o *sentryapi.RestoreOpts, reply *sentryapi.RestoreReply) (retErr error) {
	timer := starttime.Timer("Restore")
	timer.Reached("cm.Restore RPC")
	log.Debugf("containerManager.Restore")

	cm.l.mu.Lock()
	cu := cleanup.Make(cm.l.mu.Unlock)
	defer cu.Clean()

	if cm.l.state != created {
		return fmt.Errorf("cannot restore a container in state=%s", cm.l.state)
	}
	defer func() {
		if retErr != nil {
			cu.Clean() // Release `cm.l.mu` as onRestoreFailed will acquire it.
			cm.onRestoreFailed(fmt.Errorf("Restore failed: %w", retErr))
		}
	}()
	cm.l.lifecycleCPUs.holdForRestore()

	// If filesystem restore files were donated to the loader during sandbox
	// creation, we must perform a split filesystem restore. Restoring a split
	// checkpoint without split-fsrestore enabled is not supported.
	if (cm.l.fsRestore != nil) != o.SplitFSRestore {
		if o.SplitFSRestore {
			return fmt.Errorf("split filesystem restore requested, but sandbox was created without filesystem restore files")
		}
		return fmt.Errorf("filesystem restore files were donated during sandbox creation, but split filesystem restore was not requested")
	}

	if len(o.Files) == 0 {
		return fmt.Errorf("at least one file must be passed to Restore")
	}

	readerCPUs := cm.l.lifecycleCPUs.num
	if o.Background {
		// Most page reads run after the application starts, under its CPU
		// limit.
		readerCPUs = cm.l.root.applicationCores
	}
	stateFile, pagesMetadata, pagesFile, err := getRestoreReaders(o, readerCPUs)
	if err != nil {
		return err
	}
	defer func() {
		if stateFile != nil {
			stateFile.Close()
		}
		if pagesMetadata != nil {
			pagesMetadata.Close()
		}
		if pagesFile != nil {
			pagesFile.Close()
		}
	}()
	timer.Reached("got restore readers")

	cm.restorer = &restorer{
		cm:         cm,
		background: o.Background,
		timer:      timer,
	}

	// Create the main MemoryFile.
	cm.restorer.mainMF, err = createMemoryFile(cm.l.root.conf.AppHugePages, cm.l.hostTHP)
	if err != nil {
		return fmt.Errorf("creating memory file: %v", err)
	}
	timer.Reached("created MemoryFile")

	if o.HavePagesFile {
		// This immediately starts loading the main MemoryFile asynchronously.
		// For background restore, throttle page loading until the kernel is
		// restored, so that restore does not wait behind page reads.
		cm.restorer.asyncMFLoader = kernel.NewAsyncMFLoader(pagesMetadata, pagesFile, cm.restorer.mainMF, timer.Fork("PagesFileLoader"), pgalloc.AsyncPagesFileLoadOpts{Throttled: o.Background}) // transfers ownership
		pagesMetadata = nil
		pagesFile = nil
		timer.Reached("created async MF loader")
	}

	cm.restorer.stateFile, cm.restorer.metadata, err = state.NewStatefileReader(stateFile /* transfers ownership on success */, nil)
	if err != nil {
		return fmt.Errorf("creating statefile reader: %w", err)
	}
	stateFile = nil
	timer.Reached("created statefile reader")

	cm.l.state = restoringUnstarted

	// Release `cm.l.mu`.
	cu.Clean()

	if o.HaveDeviceFile {
		cm.restorer.deviceFile, err = o.ReleaseFD(len(o.Files) - 1)
		if err != nil {
			return err
		}
	}

	// Pause the kernel while we build a new one.
	cm.l.k.Pause()

	countStr, ok := cm.restorer.metadata[ContainerCountKey]
	if !ok {
		return errors.New("container count not present in state file")
	}
	count, err := strconv.Atoi(countStr)
	if err != nil {
		return fmt.Errorf("invalid container count: %w", err)
	}
	if count < 1 {
		return fmt.Errorf("invalid container count value: %v", count)
	}
	cm.restorer.totalContainers = count
	log.Infof("Restoring a total of %d containers", cm.restorer.totalContainers)

	containerSpecs, ok := cm.restorer.metadata[ContainerSpecsKey]
	if !ok {
		return fmt.Errorf("container specs not found in metadata during restore")
	}
	specs, err := specutils.GetSpecsFromString(containerSpecs)
	if err != nil {
		return err
	}
	cm.restorer.checkpointedSpecs = specs

	checkpointVersion := cm.restorer.metadata[VersionKey]
	currentVersion := version.Version()
	if checkpointVersion != currentVersion {
		return fmt.Errorf("runsc version does not match across checkpoint restore, checkpoint: %v current: %v", checkpointVersion, currentVersion)
	}
	if saved := cm.restorer.metadata[noRootContainerKey] == "true"; saved != cm.l.noRootContainer.enabled {
		return fmt.Errorf("checkpoint taken with no-root-container=%t cannot be restored with no-root-container=%t", saved, cm.l.noRootContainer.enabled)
	}
	timer.Reached("restorer initialized")
	reply.KernelStarted, err = cm.restorer.restoreContainerInfo(cm.l, &cm.l.root)
	return err
}

// getRestoreReaders returns readers for the checkpoint files
// (appropriate for `cpus` CPUs).
func getRestoreReaders(o *sentryapi.RestoreOpts, cpus int) (io.ReadCloser, io.ReadCloser, stateio.AsyncReader, error) {
	if o.UseCheckpointGofer {
		return getRestoreReadersForCheckpointGofer(o)
	}
	return getRestoreReadersForLocalCheckpointFiles(o, cpus)
}

func getRestoreReadersForLocalCheckpointFiles(o *sentryapi.RestoreOpts, cpus int) (io.ReadCloser, io.ReadCloser, stateio.AsyncReader, error) {
	stateFile, err := o.ReleaseFD(0)
	if err != nil {
		return nil, nil, nil, err
	}
	cu := cleanup.Make(func() { stateFile.Close() })
	defer cu.Clean()
	var stat unix.Stat_t
	if err := unix.Fstat(stateFile.FD(), &stat); err != nil {
		return nil, nil, nil, err
	}
	if stat.Size == 0 {
		return nil, nil, nil, fmt.Errorf("statefile cannot be empty")
	}

	if !o.HavePagesFile {
		cu.Release()
		return stateFile, nil, nil, nil
	}
	pagesMetadataFile, err := o.ReleaseFD(1)
	if err != nil {
		return nil, nil, nil, err
	}
	cu.Add(func() { pagesMetadataFile.Close() })
	pagesFile, err := o.ReleaseFD(2)
	if err != nil {
		return nil, nil, nil, err
	}
	cu.Release()
	// //pkg/state/wire reads one byte at a time; buffer reads from
	// pagesMetadataFile to avoid making one syscall per read. For the state
	// file, this buffering is handled by statefile.NewReader() =>
	// compressio.Reader or compressio.NewSimpleReader().
	return stateFile,
		stateio.NewBufioReadCloser(pagesMetadataFile),
		stateio.NewPagesFileFDReaderDefault(int32(pagesFile.Release()), cpus),
		nil
}

func getRestoreReadersForCheckpointGofer(o *sentryapi.RestoreOpts) (io.ReadCloser, io.ReadCloser, stateio.AsyncReader, error) {
	clientFD, err := unix.Dup(int(o.Files[0].Fd()))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to dup checkpoint gofer client FD: %w", err)
	}
	clientSock, err := unet.NewSocket(clientFD)
	if err != nil {
		unix.Close(clientFD)
		return nil, nil, nil, fmt.Errorf("failed to create unet.Socket for checkpoint gofer client FD: %w", err)
	}
	afc, err := stateipc.NewAsyncFileClient(urpc.NewClient(clientSock) /* transfers ownership */)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to create stateipc client: %w", err)
	}
	defer afc.DecRef()

	stateFileAsync, err := afc.OpenRead(checkpointfiles.StateFileName)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to open state file: %w", err)
	}
	stateFile, err := stateio.NewBufReader(stateFileAsync /* transfers ownership */, 8<<20 /* size = 8 MiB */)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to buffer state file: %w", err)
	}

	pagesMetadataAsync, err := afc.OpenRead(checkpointfiles.PagesMetadataFileName)
	if err != nil {
		// This might be fs.ErrNotExist or unix.ENOENT, but this detail is lost
		// by URPC (which only preserves the error string), so log and continue
		// under the assumption that it is.
		log.Infof("Failed to open pages metadata file: %v", err)
		o.HavePagesFile = false
		return stateFile, nil, nil, nil
	}
	pagesMetadata, err := stateio.NewBufReader(pagesMetadataAsync /* transfers ownership */, 8<<20 /* size = 8 MiB */)
	if err != nil {
		stateFile.Close()
		return nil, nil, nil, fmt.Errorf("failed to buffer pages metadata file: %w", err)
	}
	pagesFile, err := afc.OpenRead(checkpointfiles.PagesFileName)
	if err != nil {
		pagesMetadata.Close()
		stateFile.Close()
		return nil, nil, nil, fmt.Errorf("failed to open pages file: %w", err)
	}
	o.HavePagesFile = true
	return stateFile, pagesMetadata, pagesFile, nil
}

func (cm *containerManager) onRestoreFailed(err error) {
	cm.l.lifecycleCPUs.releaseForRestore()
	cm.l.mu.Lock()
	cm.l.state = restoreFailed
	cm.l.restoreErr = err
	cm.l.mu.Unlock()
	cm.l.restoreDone.Broadcast()
	cm.restorer = nil
}

func (cm *containerManager) onRestoreDone(s sentryapi.Savings) {
	cm.l.mu.Lock()
	cm.l.state = restored
	cm.l.savings = s
	cm.l.mu.Unlock()
	cm.l.restoreDone.Broadcast()
	cm.restorer = nil
	cm.l.releaseStartupHeapWhenIdle()
}

func (cm *containerManager) RestoreSubcontainer(args *sentryapi.StartArgs, reply *sentryapi.RestoreReply) (retErr error) {
	log.Debugf("containerManager.RestoreSubcontainer, cid: %s, args: %+v", args.CID, args)
	cm.l.mu.Lock()
	state := cm.l.state
	cm.l.mu.Unlock()
	if state != restoringUnstarted {
		return fmt.Errorf("sandbox is not being restored, cannot restore subcontainer: state=%s", state)
	}
	defer func() {
		if retErr != nil {
			cm.onRestoreFailed(fmt.Errorf("RestoreSubcontainer failed: %w", retErr))
		}
	}()

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
	if args.IsDevIoFilePresent {
		expectedFDs++
	}
	if !args.Spec.Process.Terminal {
		expectedFDs += 3
	}
	if args.IsRootfsUpperTarFilePresent {
		return errors.New("rootfs upper tar file is not supported during restore")
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

	reply.KernelStarted, err = cm.restorer.restoreSubcontainer(args.Spec, args.Conf, cm.l, args.CID, stdios, goferFDs, goferFilestoreFDs, devGoferFD, args.GoferMountConfs)
	if err != nil {
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
	return control.PostResume(cm.l.k, nil)
}

// Wait waits for the init process in the given container.
func (cm *containerManager) Wait(cid *string, waitStatus *uint32) error {
	log.Debugf("containerManager.Wait, cid: %s", *cid)
	err := cm.l.waitContainer(*cid, waitStatus)
	log.Debugf("containerManager.Wait returned, cid: %s, waitStatus: %#x, err: %v", *cid, *waitStatus, err)
	return err
}

// WaitPID waits for the process with PID 'pid' in the sandbox.
func (cm *containerManager) WaitPID(args *sentryapi.WaitPIDArgs, waitStatus *uint32) error {
	log.Debugf("containerManager.Wait, cid: %s, pid: %d", args.CID, args.PID)
	err := cm.l.waitPID(kernel.ThreadID(args.PID), args.CID, waitStatus)
	log.Debugf("containerManager.Wait, cid: %s, pid: %d, waitStatus: %#x, err: %v", args.CID, args.PID, *waitStatus, err)
	return err
}

// WaitCheckpoint waits for the Kernel to have been successfully checkpointed.
func (cm *containerManager) WaitCheckpoint(*struct{}, *struct{}) error {
	log.Debugf("containerManager.WaitCheckpoint")
	err := cm.l.k.WaitForCheckpoint()
	log.Debugf("containerManager.WaitCheckpoint done, err = %v", err)
	return err
}

func (cm *containerManager) WaitRestore(*struct{}, *struct{}) error {
	log.Debugf("containerManager.WaitRestore")
	err := cm.l.waitRestore()
	log.Debugf("containerManager.WaitRestore done, err = %v", err)
	return err
}

// +checklocksexclude:cm.l.k.fsSaveMu
func (cm *containerManager) WaitFSCheckpoint(*struct{}, *struct{}) error {
	log.Debugf("containerManager.WaitFSCheckpoint")
	err := cm.l.k.WaitForFSSave()
	log.Debugf("containerManager.WaitFSCheckpoint done, err = %v", err)
	return err
}

func (cm *containerManager) WaitFSRestore(args *sentryapi.WaitFSRestoreArgs, _ *struct{}) error {
	log.Debugf("containerManager.WaitFSRestore")
	err := cm.l.fsRestore.wait(args.CID)
	log.Debugf("containerManager.WaitFSRestore done, err = %v", err)
	return err
}

// Signal sends a signal to one or more processes in a container. If args.PID
// is 0, then the container init process is used. Depending on the
// args.SignalDeliveryMode option, the signal may be sent directly to the
// indicated process, to all processes in the container, or to the foreground
// process group.
func (cm *containerManager) Signal(args *sentryapi.SignalArgs, _ *struct{}) error {
	log.Debugf("containerManager.Signal: cid: %s, PID: %d, signal: %d, mode: %v", args.CID, args.PID, args.Signo, args.Mode)
	return cm.l.signal(args.CID, args.PID, args.Signo, args.Mode)
}

// CreateTraceSession creates a new trace session.
func (cm *containerManager) CreateTraceSession(args *sentryapi.CreateTraceSessionArgs, _ *struct{}) error {
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
//
// Callers must not hold any thread-group leader's Task.mu in the sandbox.
// checklocks cannot name the leader mutexes in the slice returned by
// PIDNamespace.ThreadGroups.
func (cm *containerManager) ProcfsDump(_ *struct{}, out *[]procfs.ProcessProcfsDump) error {
	log.Debugf("containerManager.ProcfsDump")
	ts := cm.l.k.TaskSet()
	pidns := ts.Root
	tgs := pidns.ThreadGroups()
	*out = make([]procfs.ProcessProcfsDump, 0, len(tgs))
	for _, tg := range tgs {
		pid := pidns.IDOfThreadGroup(tg)
		procDump, err := dumpProcfs(tg.Leader(), pid, pidns)
		if err != nil {
			log.Warningf("skipping procfs dump for PID %s: %v", pid, err)
			continue
		}
		*out = append(*out, procDump)
	}
	return nil
}

const initTID kernel.ThreadID = 1

// Mount mounts a filesystem in a container.
func (cm *containerManager) Mount(args *sentryapi.MountArgs, _ *struct{}) error {
	log.Debugf("containerManager.Mount, cid: %s, args: %+v", args.ContainerID, args)

	var cu cleanup.Cleanup
	defer cu.Clean()

	cm.l.mu.Lock()
	defer cm.l.mu.Unlock()
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

	ctx := t.Kernel().SupervisorContext()
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
func (cm *containerManager) ContainerRuntimeState(cid *string, state *sentryapi.ContainerRuntimeState) error {
	log.Debugf("containerManager.ContainerRuntimeState: cid: %s", *cid)
	*state = cm.l.containerRuntimeState(*cid)
	return nil
}

// FSSave collects a filesystem checkpoint.
//
// +checklocksexclude:cm.l.k.fsSaveMu
func (cm *containerManager) FSSave(args *sentryapi.FSSaveArgs, _ *struct{}) error {
	log.Debugf("containerManager.FSSave")
	kopts, err := convertToKernelFSSaveOpts(args)
	if err != nil {
		cm.l.k.SignalAllFSSaveWaiters(err)
		return err
	}
	defer cm.l.stopIfKilled()
	return cm.l.k.FSSave(cm.l.k.SupervisorContext(), &kopts)
}

// GetSavings returns the savings for restored sandboxes.
func (cm *containerManager) GetSavings(_ *struct{}, s *sentryapi.Savings) error {
	log.Debugf("containerManager.GetSavings")
	cm.l.mu.Lock()
	*s = cm.l.savings
	cm.l.mu.Unlock()
	return nil
}

// SetNetworkArgs sets the network arguments. It configures host sockets
// (packet fanout groups) before seccomp is installed, but does not create
// the netstack links and routes.
func (cm *containerManager) SetNetworkArgs(args *sentryapi.CreateLinksAndRoutesArgs, _ *struct{}) error {
	log.Debugf("containerManager.SetNetworkArgs")
	if args == nil {
		return fmt.Errorf("cannot set nil networkArgs")
	}

	cm.l.mu.Lock()
	state := cm.l.state
	cm.l.mu.Unlock()
	if state == started || state == restored || state == restoringStarted {
		log.Warningf("SetNetworkArgs called after sandbox started (state=%s), ignoring", state)
		return nil
	}

	// Create a new CreateLinksAndRoutesArgs variable to store in the loader
	// as the FDs associated with the original argument passed to this urpc
	// will be closed when it returns.
	networkArgs := *args
	dupedFDs, err := fd.NewFromFiles(args.FilePayload.Files)
	if err != nil {
		return fmt.Errorf("failed to dup network FDs: %w", err)
	}
	c := cleanup.Make(func() {
		for _, f := range dupedFDs {
			_ = f.Close()
		}
	})
	defer c.Clean()

	// Configure FDs before seccomp is installed.
	fdIdx := 0
	for i := range networkArgs.FDBasedLinks {
		link := &networkArgs.FDBasedLinks[i]
		link.IsPacket = make([]bool, link.NumChannels)

		fid := int32(-1)
		for ch := 0; ch < link.NumChannels; ch++ {
			if fdIdx >= len(dupedFDs) {
				return fmt.Errorf("insufficient FDs provided for link %q", link.Name)
			}
			f := dupedFDs[fdIdx]
			fdIdx++
			cm.l.pinRing.Add(f.FD())

			isSocket, err := fdbased.IsSocketFD(f.FD())
			if err != nil {
				return err
			}

			isPacket, err := fdbased.IsPacketSocket(f.FD(), isSocket)
			if err != nil {
				return err
			}
			link.IsPacket[ch] = isPacket

			if isPacket {
				if fid < 0 {
					fid, err = fdbased.CreatePacketFanoutGroup(f.FD())
				} else {
					err = fdbased.JoinPacketFanoutGroup(f.FD(), fid)
				}
				if err != nil {
					return fmt.Errorf("pre-configuring PACKET_FANOUT failed for link %q: %w", link.Name, err)
				}
			}
		}
		if networkArgs.PCAP {
			// Skip PCAP fd.
			fdIdx++
		}
		link.PreConfigured = true
	}

	// Release the duplicated FDs back to os.File objects and store them in the copy.
	networkArgs.FilePayload.Files = fd.ReleaseToFiles(dupedFDs, "network-fd")
	c.Release()

	cm.l.mu.Lock()
	cm.l.networkArgs = &networkArgs
	cm.l.mu.Unlock()
	return nil
}

// GetNetworkConfig returns the network interfaces and routes.
func (cm *containerManager) GetNetworkConfig(_ *struct{}, networkArgs *sentryapi.CreateLinksAndRoutesArgs) error {
	log.Debugf("containerManager.GetNetworkConfig")
	cm.l.mu.Lock()
	if cm.l.networkArgs != nil {
		*networkArgs = *cm.l.networkArgs
	}
	cm.l.mu.Unlock()

	if networkArgs == nil {
		log.Debugf("networks args is nil")
	}
	return nil
}

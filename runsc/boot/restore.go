// Copyright 2023 The gVisor Authors.
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
	"strconv"
	time2 "time"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/cleanup"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/devutil"
	"gvisor.dev/gvisor/pkg/fd"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/control"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/host"
	"gvisor.dev/gvisor/pkg/sentry/inet"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/pgalloc"
	"gvisor.dev/gvisor/pkg/sentry/socket/hostinet"
	"gvisor.dev/gvisor/pkg/sentry/socket/netstack"
	"gvisor.dev/gvisor/pkg/sentry/state"
	"gvisor.dev/gvisor/pkg/sentry/time"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/sentry/watchdog"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/timing"
	"gvisor.dev/gvisor/runsc/boot/pprof"
	"gvisor.dev/gvisor/runsc/config"
	"gvisor.dev/gvisor/runsc/specutils"
	"gvisor.dev/gvisor/runsc/version"
)

const (
	// CheckpointStateFileName is the file within the given image-path's
	// directory which contains the container's saved state.
	CheckpointStateFileName = "checkpoint.img"
	// CheckpointPagesMetadataFileName is the file within the given image-path's
	// directory containing the container's MemoryFile metadata.
	CheckpointPagesMetadataFileName = "pages_meta.img"
	// CheckpointPagesFileName is the file within the given image-path's
	// directory containing the container's MemoryFile pages.
	CheckpointPagesFileName = "pages.img"
	// VersionKey is the key used to save runsc version in the save metadata and compare
	// it across checkpoint restore.
	VersionKey = "runsc_version"
	// ContainerCountKey is the key used to save number of containers in the save metadata.
	ContainerCountKey = "container_count"
)

// restorer manages a restore session for a sandbox. It stores information about
// all containers and triggers the full sandbox restore after the last
// container is restored.
type restorer struct {
	mu sync.Mutex

	// totalContainers is the number of containers expected to be restored in
	// the sandbox. Sandbox restore can only happen, after all containers have
	// been restored.
	totalContainers int

	// containers is the list of containers restored so far.
	containers []*containerInfo

	// Files used by restore to rehydrate the state.
	stateFile     *fd.FD
	pagesMetadata *fd.FD
	pagesFile     *fd.FD

	// timer is the timer for the restore process.
	// The `restorer` owns the timer and will end it when restore is complete.
	timer *timing.Timer

	// If background is true, pagesFile may continue to be read after
	// restorer.restore() returns.
	background bool

	// mainMF is the main MemoryFile of the sandbox.
	// It is created as soon as possible, and may be restored to as soon as
	// the first container is restored, which is earlier than when the sandbox's
	// kernel object is created.
	mainMF *pgalloc.MemoryFile

	// pagesFileLoader is used to load the MemoryFile pages. It handles the
	// possibly-asynchronous loading of the memory pages.
	pagesFileLoader kernel.PagesFileLoader

	// deviceFile is the required to start the platform.
	deviceFile *fd.FD

	// restoreDone is a callback triggered when restore is successful.
	restoreDone func() error
}

// restoreSubcontainer restores a subcontainer.
// `subcontainerTimeline` must either be nil or an orphaned timeline.
// It takes ownership of subcontainerTimeline and will end it.
func (r *restorer) restoreSubcontainer(spec *specs.Spec, conf *config.Config, l *Loader, cid string, stdioFDs, goferFDs, goferFilestoreFDs []*fd.FD, devGoferFD *fd.FD, goferMountConfs []GoferMountConf, subcontainerTimeline *timing.Timeline) error {
	containerName := l.registerContainer(spec, cid)
	info := &containerInfo{
		cid:               cid,
		containerName:     containerName,
		conf:              conf,
		spec:              spec,
		stdioFDs:          stdioFDs,
		goferFDs:          goferFDs,
		devGoferFD:        devGoferFD,
		goferFilestoreFDs: goferFilestoreFDs,
		goferMountConfs:   goferMountConfs,
	}
	r.timer.Adopt(subcontainerTimeline)
	return r.restoreContainerInfo(l, info, subcontainerTimeline)
}

// restoreContainerInfo restores a container.
// It takes ownership of containerTimeline and will end it.
func (r *restorer) restoreContainerInfo(l *Loader, info *containerInfo, containerTimeline *timing.Timeline) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	containerTiming := containerTimeline.Lease()
	defer containerTiming.End()
	containerTiming.Reached("restorer locked")

	for _, container := range r.containers {
		if container.containerName == info.containerName {
			return fmt.Errorf("container %q already restored", info.containerName)
		}
		if container.cid == info.cid {
			return fmt.Errorf("container CID %q already belongs to container %q", info.cid, container.containerName)
		}
	}

	r.containers = append(r.containers, info)

	if log.IsLogging(log.Debug) {
		for i, fd := range info.stdioFDs {
			log.Debugf("Restore app FD: %d host FD: %d", i, fd.FD())
		}
	}
	containerTiming.End()
	log.Infof("Restored container %d of %d", len(r.containers), r.totalContainers)

	// Non-container-specific restore work:

	if err := r.maybeKickoffMainMemoryFileLoad(l); err != nil {
		return fmt.Errorf("main memory file: %w", err)
	}

	if len(r.containers) == r.totalContainers {
		// Trigger the restore if this is the last container.
		return r.restore(l)
	}
	return nil
}

// maybeKickoffMainMemoryFileLoad kicks off loading of the main MemoryFile
// asynchronously, if possible and if it hasn't been done yet.
func (r *restorer) maybeKickoffMainMemoryFileLoad(l *Loader) error {
	if r.mainMF == nil {
		// Create the main MemoryFile.
		mf, err := createMemoryFile(l.root.conf.AppHugePages, l.hostTHP)
		if err != nil {
			return fmt.Errorf("creating memory file: %v", err)
		}
		r.mainMF = mf
	}
	if r.pagesFileLoader != nil {
		return nil // Already kicked off.
	}
	if r.pagesFile == nil || r.pagesMetadata == nil {
		return nil // Asynchronous loading not possible.
	}
	pfl := kernel.NewMultiStateFilePagesFileLoader(r.pagesMetadata, r.pagesFile, r.timer.Fork("PagesFileLoader"))
	if err := pfl.KickoffMain(context.Background(), r.mainMF); err != nil {
		return fmt.Errorf("failed to load main memory file: %w", err)
	}
	r.pagesFileLoader = pfl

	// Ownership transferred to the pages file loader.
	r.pagesFile = nil
	r.pagesMetadata = nil

	return nil
}

func createNetworkStackForRestore(l *Loader) (*stack.Stack, inet.Stack) {
	// Save the current network stack to slap on top of the one that was restored.
	curNetwork := l.k.RootNetworkNamespace().Stack()
	if eps, ok := curNetwork.(*netstack.Stack); ok {
		return eps.Stack, curNetwork
	}
	return nil, hostinet.NewStack()
}

func (r *restorer) restore(l *Loader) error {
	log.Infof("Starting to restore %d containers", len(r.containers))

	// Create a new root network namespace with the network stack of the
	// old kernel to preserve the existing network configuration.
	oldStack, oldInetStack := createNetworkStackForRestore(l)
	r.timer.Reached("netstack created")

	// Reset the network stack in the network namespace to nil before
	// replacing the kernel. This will not free the network stack when this
	// old kernel is released.
	l.k.RootNetworkNamespace().ResetStack()
	r.timer.Reached("netstack reset")

	p, err := createPlatform(l.root.conf, r.deviceFile)
	if err != nil {
		return fmt.Errorf("creating platform: %v", err)
	}
	r.timer.Reached("platform created")

	// Start the old watchdog before replacing it with a new one below.
	l.watchdog.Start()
	r.timer.Reached("watchdog started")

	// Release the kernel and replace it with a new one that will be restored into.
	if l.k != nil {
		l.k.Release()
	}
	l.k = &kernel.Kernel{
		Platform: p,
	}
	l.k.SetMemoryFile(r.mainMF)

	if l.root.conf.ProfileEnable {
		// pprof.Initialize opens /proc/self/maps, so has to be called before
		// installing seccomp filters.
		pprof.Initialize()
	}

	// Seccomp filters have to be applied before vfs restore and before parsing
	// the state file.
	if err := l.installSeccompFilters(); err != nil {
		return err
	}

	// Set up the restore environment.
	ctx := l.k.SupervisorContext()
	if oldStack != nil {
		ctx = context.WithValue(ctx, stack.CtxRestoreStack, oldStack)
	}

	l.mu.Lock()
	cu := cleanup.Make(func() {
		l.mu.Unlock()
	})
	defer cu.Clean()

	fdmap := make(map[vfs.RestoreID]int)
	mfmap := make(map[string]*pgalloc.MemoryFile)
	for _, cont := range r.containers {
		// TODO(b/298078576): Need to process hints here probably
		mntr := newContainerMounter(cont, l.k, l.mountHints, l.sharedMounts, l.productName, cont.cid)
		if err = mntr.configureRestore(fdmap, mfmap); err != nil {
			return fmt.Errorf("configuring filesystem restore: %v", err)
		}

		for i, fd := range cont.stdioFDs {
			key := host.MakeRestoreID(cont.containerName, i)
			fdmap[key] = fd.Release()
		}
		for _, customFD := range cont.passFDs {
			key := host.MakeRestoreID(cont.containerName, customFD.guest)
			fdmap[key] = customFD.host.FD()
		}
	}
	r.timer.Reached("container mounts config'd")

	log.Debugf("Restore using fdmap: %v", fdmap)
	ctx = context.WithValue(ctx, vfs.CtxRestoreFilesystemFDMap, fdmap)
	log.Debugf("Restore using mfmap: %v", mfmap)
	ctx = context.WithValue(ctx, pgalloc.CtxMemoryFileMap, mfmap)
	ctx = context.WithValue(ctx, devutil.CtxDevGoferClientProvider, l.k)

	// Load the state.
	loadOpts := state.LoadOpts{
		Source:          r.stateFile,
		PagesFileLoader: r.pagesFileLoader,
		Background:      r.background,
	}
	err = loadOpts.Load(ctx, l.k, nil, oldInetStack, time.NewCalibratedClocks(), &vfs.CompleteRestoreOptions{}, l.saveRestoreNet)
	if err != nil {
		return fmt.Errorf("failed to load kernel: %w", err)
	}
	r.timer.Reached("kernel loaded")

	oldSpecs, err := popContainerSpecsFromCheckpoint(l.k)
	if err != nil {
		return fmt.Errorf("failed to pop container specs from checkpoint: %w", err)
	}
	if err := specutils.RestoreValidateSpec(oldSpecs, l.containerSpecs, l.root.conf); err != nil {
		return fmt.Errorf("failed to handle restore spec validation: %w", err)
	}
	r.timer.Reached("spec validated")

	// Since we have a new kernel we also must make a new watchdog.
	dogOpts := watchdog.DefaultOpts
	dogOpts.TaskTimeoutAction = l.root.conf.WatchdogAction
	dogOpts.StartupTimeout = 3 * time2.Minute // Give extra time for all containers to restore.
	dog := watchdog.New(l.k, dogOpts)

	// Change the loader fields to reflect the changes made when restoring.
	l.watchdog.Stop()
	l.watchdog = dog
	l.root.procArgs = kernel.CreateProcessArgs{}
	l.restore = true
	l.sandboxID = l.root.cid

	// Update all tasks in the system with their respective new container IDs.
	for _, task := range l.k.TaskSet().Root.Tasks() {
		oldCid := task.ContainerID()
		name := l.k.ContainerName(oldCid)
		newCid, ok := l.containerIDs[name]
		if !ok {
			return fmt.Errorf("unable to remap task with CID %q (name: %q). Available names: %v", task.ContainerID(), name, l.containerIDs)
		}
		task.RestoreContainerID(newCid)
	}
	r.timer.Reached("container tasks updated")

	// Rebuild `processes` map with containers' root process from the restored kernel.
	for _, tg := range l.k.RootPIDNamespace().ThreadGroups() {
		// Find all processes with no parent (root of execution), that were not started
		// via a call to `exec`.
		if tg.Leader().Parent() == nil && tg.Leader().Origin != kernel.OriginExec {
			cid := tg.Leader().ContainerID()
			proc := l.processes[execID{cid: cid}]
			if proc == nil {
				return fmt.Errorf("unable to find container root process with CID %q, processes: %v", cid, l.processes)
			}
			proc.tg = tg
		}
	}
	r.timer.Reached("processes rebuilt")

	// Kill all processes that have been exec'd since they cannot be properly
	// restored -- the caller is no longer connected.
	log.Debugf("Killing any exec session that existed previously")
	for _, tg := range l.k.RootPIDNamespace().ThreadGroups() {
		if tg.Leader().Origin == kernel.OriginExec {
			log.Infof("Killing exec'd process, PID: %d", tg.ID())
			if err := l.k.SendExternalSignalThreadGroup(tg, &linux.SignalInfo{Signo: int32(linux.SIGKILL)}); err != nil {
				log.Warningf("Failed to kill exec process after restore: %v", err)
			}
		}
	}

	l.k.RestoreContainerMapping(l.containerIDs)

	l.kernelInitExtra()
	r.timer.Reached("extra init done")

	// Refresh the control server with the newly created kernel.
	l.ctrl.refreshHandlers()

	// Release `l.mu` before calling into callbacks.
	cu.Clean()
	r.timer.Reached("post-restore cleanups")

	// r.restoreDone() signals and waits for the sandbox to start.
	if err := r.restoreDone(); err != nil {
		return fmt.Errorf("restorer.restoreDone callback failed: %w", err)
	}

	r.stateFile.Close()

	postRestoreThread := r.timer.Fork("postRestore")
	go func() {
		defer postRestoreThread.End()
		postRestoreThread.Reached("scheduled")
		if err := postRestoreImpl(l, postRestoreThread); err != nil {
			log.Warningf("Killing the sandbox after post restore work failed: %v", err)
			l.k.Kill(linux.WaitStatusTerminationSignal(linux.SIGKILL))
			return
		}
		postRestoreThread.Reached("post restore done")

		// Restore was successful, so increment the checkpoint count manually. The
		// count was saved while the previous kernel was being saved and checkpoint
		// success was unknown at that time. Now we know the checkpoint succeeded.
		l.k.OnRestoreDone()
		postRestoreThread.Reached("kernel notified")

		log.Infof("Restore successful")
	}()

	// Transfer ownership of the `timer` to a new goroutine.
	// This is because `timer.Log` blocks until all timed tasks are finished,
	// but some restore tasks may still run in the background, and we don't
	// want to block this function until they finish.
	timer := r.timer
	r.timer = nil
	go timer.Log()

	return nil
}

func (l *Loader) save(o *control.SaveOpts) (err error) {
	defer func() {
		// This closure is required to capture the final value of err.
		l.k.OnCheckpointAttempt(err)
	}()

	// TODO(gvisor.dev/issues/6243): save/restore not supported w/ hostinet
	if l.root.conf.Network == config.NetworkHost {
		return errors.New("checkpoint not supported when using hostinet")
	}

	if o.Metadata == nil {
		o.Metadata = make(map[string]string)
	}
	o.Metadata[ContainerCountKey] = strconv.Itoa(l.containerCount())

	// Save runsc version.
	o.Metadata[VersionKey] = version.Version()

	// Save container specs.
	l.addContainerSpecsToCheckpoint()

	if err := preSaveImpl(l, o); err != nil {
		return err
	}

	state := control.State{
		Kernel:   l.k,
		Watchdog: l.watchdog,
	}
	if err := state.Save(o, nil); err != nil {
		return err
	}

	if o.Resume {
		if err := postResumeImpl(l, nil); err != nil {
			return err
		}
	}
	return nil
}

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
	"io"
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
	"gvisor.dev/gvisor/pkg/sentry/time"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/sentry/watchdog"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
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
	// ContainerSpecsKey is the key used to add and pop the container specs to the
	// metadata during save/restore.
	ContainerSpecsKey = "container_specs"
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

	// stateFile is a reader for the statefile.
	stateFile io.ReadCloser

	// If background is true, pagesFile may continue to be read after
	// restorer.restore() returns.
	background bool

	// mainMF is the main MemoryFile of the sandbox.
	// It is created as soon as possible, and may be restored to as soon as
	// the first container is restored, which is earlier than when the sandbox's
	// kernel object is created.
	mainMF *pgalloc.MemoryFile

	// asyncMFLoader is used to load the MemoryFile pages. It handles the
	// asynchronous loading of the memory pages.
	asyncMFLoader *kernel.AsyncMFLoader

	// deviceFile is the required to start the platform.
	deviceFile *fd.FD

	// readyToStart is a callback triggered when the sandbox is ready to start.
	readyToStart func() error

	// onRestoreDone is a callback triggered when the restore is done.
	onRestoreDone func()

	// checkpointedSpecs contains the map of container specs used during
	// checkpoint.
	checkpointedSpecs map[string]*specs.Spec
}

func (r *restorer) restoreSubcontainer(spec *specs.Spec, conf *config.Config, l *Loader, cid string, stdioFDs, goferFDs, goferFilestoreFDs []*fd.FD, devGoferFD *fd.FD, goferMountConfs []GoferMountConf) error {
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
	return r.restoreContainerInfo(l, info)
}

func (r *restorer) restoreContainerInfo(l *Loader, info *containerInfo) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	for _, container := range r.containers {
		if container.containerName == info.containerName {
			return fmt.Errorf("container %q already restored", info.containerName)
		}
		if container.cid == info.cid {
			return fmt.Errorf("container CID %q already belongs to container %q", info.cid, container.containerName)
		}
	}

	r.containers = append(r.containers, info)

	log.Infof("Restored container %d of %d", len(r.containers), r.totalContainers)
	if log.IsLogging(log.Debug) {
		for i, fd := range info.stdioFDs {
			log.Debugf("Restore app FD: %d host FD: %d", i, fd.FD())
		}
	}

	if len(r.containers) == r.totalContainers {
		if err := specutils.RestoreValidateSpec(r.checkpointedSpecs, l.GetContainerSpecs(), l.root.conf); err != nil {
			return fmt.Errorf("failed to handle restore spec validation: %w", err)
		}

		// Trigger the restore if this is the last container.
		return r.restore(l)
	}
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

	// Reset the network stack in the network namespace to nil before
	// replacing the kernel. This will not free the network stack when this
	// old kernel is released.
	l.k.RootNetworkNamespace().ResetStack()

	p, err := createPlatform(l.root.conf, r.deviceFile)
	if err != nil {
		return fmt.Errorf("creating platform: %v", err)
	}

	// Start the old watchdog before replacing it with a new one below.
	l.watchdog.Start()

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

	log.Debugf("Restore using fdmap: %v", fdmap)
	ctx = context.WithValue(ctx, vfs.CtxRestoreFilesystemFDMap, fdmap)
	log.Debugf("Restore using mfmap: %v", mfmap)
	ctx = context.WithValue(ctx, pgalloc.CtxMemoryFileMap, mfmap)
	ctx = context.WithValue(ctx, devutil.CtxDevGoferClientProvider, l.k)

	if r.asyncMFLoader != nil {
		// Now that private memory files are known, kick off their loading in the
		// background goroutine.
		r.asyncMFLoader.KickoffPrivate(mfmap)
	}

	// Load the state.
	if err := l.k.LoadFrom(ctx, r.stateFile, r.asyncMFLoader == nil, nil, oldInetStack, time.NewCalibratedClocks(), &vfs.CompleteRestoreOptions{}, l.saveRestoreNet); err != nil {
		return fmt.Errorf("failed to load kernel: %w", err)
	}
	// The kernel should already have been started at this point, so we can
	// immediately wait for the save/restore binary to be ready.
	if _, err := l.k.ExecSaveRestoreBin(kernel.SaveRestoreBinRestore); err != nil {
		return fmt.Errorf("failed to wait for save/restore binary: %w", err)
	}

	if r.asyncMFLoader != nil {
		if r.background {
			if err := r.asyncMFLoader.WaitMetadata(); err != nil {
				return err
			}
		} else {
			if err := r.asyncMFLoader.Wait(); err != nil {
				return err
			}
		}
	}

	// Since we have a new kernel we also must make a new watchdog.
	dogOpts := watchdog.DefaultOpts
	dogOpts.TaskTimeoutAction = l.root.conf.WatchdogAction
	dogOpts.StartupTimeout = 3 * time2.Minute // Give extra time for all containers to restore.
	dog := watchdog.New(l.k, dogOpts)

	// Change the loader fields to reflect the changes made when restoring.
	l.watchdog.Stop()
	l.watchdog = dog
	l.root.procArgs = kernel.CreateProcessArgs{}
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

	// Refresh the control server with the newly created kernel.
	l.ctrl.refreshHandlers()

	// Release `l.mu` before calling into callbacks.
	cu.Clean()

	if err := r.readyToStart(); err != nil {
		return fmt.Errorf("restorer.readyToStart callback failed: %w", err)
	}

	r.stateFile.Close()

	go func() {
		if err := postRestoreImpl(l); err != nil {
			log.Warningf("Killing the sandbox after post restore work failed: %v", err)
			l.k.Kill(linux.WaitStatusTerminationSignal(linux.SIGKILL))
			return
		}

		// Now that post restore work succeeded, increment the checkpoint gen
		// manually. The count was saved while the previous kernel was being saved
		// and checkpoint success was unknown at that time. Now we know the had
		// checkpoint succeeded. Allow the application to proceed while pages may
		// keep loading in the background.
		l.k.IncCheckpointGenOnRestore()

		// Wait for page loading to complete if happening in the background.
		if r.asyncMFLoader != nil {
			if err := r.asyncMFLoader.Wait(); err != nil {
				log.Warningf("Killing the sandbox after MemoryFile page loading failed: %v", err)
				l.k.Kill(linux.WaitStatusTerminationSignal(linux.SIGKILL))
				return
			}
		}

		r.onRestoreDone()

		log.Infof("Restore successful")
	}()
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
	specsStr, err := specutils.ConvertSpecsToString(l.GetContainerSpecs())
	if err != nil {
		return err
	}
	o.Metadata[ContainerSpecsKey] = specsStr

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
		if err := postResumeImpl(l); err != nil {
			return err
		}
	}
	return nil
}

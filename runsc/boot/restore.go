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
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	time2 "time"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/cleanup"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/devutil"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/fd"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/checkpoint"
	"gvisor.dev/gvisor/pkg/sentry/control"
	"gvisor.dev/gvisor/pkg/sentry/devices/nvproxy/nvconf"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/host"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/proc"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/pgalloc"
	"gvisor.dev/gvisor/pkg/sentry/state"
	"gvisor.dev/gvisor/pkg/sentry/time"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/sentry/watchdog"
	"gvisor.dev/gvisor/pkg/state/statefile"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/timing"
	"gvisor.dev/gvisor/pkg/urpc"
	"gvisor.dev/gvisor/runsc/boot/pprof"
	"gvisor.dev/gvisor/runsc/config"
	"gvisor.dev/gvisor/runsc/specutils"
	"gvisor.dev/gvisor/runsc/starttime"
	"gvisor.dev/gvisor/runsc/version"
)

const (
	// VersionKey is the key used to save runsc version in the save metadata and compare
	// it across checkpoint restore.
	VersionKey = "runsc_version"
	// ContainerCountKey is the key used to save number of containers in the save metadata.
	ContainerCountKey = "container_count"
	// ContainerSpecsKey is the key used to add and pop the container specs to the
	// metadata during save/restore.
	ContainerSpecsKey = "container_specs"

	annotationCheckpointPrefix = "dev.gvisor.internal.checkpoint."

	// annotationCheckpointPath is the path to the directory where the checkpoint files will be
	// created. When present, it allows for the workload running inside to trigger a checkpoint
	// without having to use the runsc CLI.
	annotationCheckpointPath = annotationCheckpointPrefix + "path"

	// annotationCheckpointResume indicates whether the sandbox should continue running after the
	// checkpoint. Optional, defaults to false.
	annotationCheckpointResume = annotationCheckpointPrefix + "resume"

	// annotationCheckpointCompression is the compression to use for the checkpoint file. Optional,
	// defaults to best speed compression.
	annotationCheckpointCompression = annotationCheckpointPrefix + "compression"

	// annotationCheckpointDirect indicates whether the checkpoint IOs should use O_DIRECT. Optional,
	// defaults to false.
	annotationCheckpointDirect = annotationCheckpointPrefix + "direct"

	// annotationCheckpointExcludeCommittedZeroPages indicates whether the checkpoint should exclude
	// committed zero pages. Optional, defaults to false.
	annotationCheckpointExcludeCommittedZeroPages = annotationCheckpointPrefix + "exclude-committed-zero-pages"

	// annotationCheckpointCudaCheckpointPath is the path to the cuda-checkpoint binary. It's required
	// if the workload has CUDA processes.
	annotationCheckpointCudaCheckpointPath = annotationCheckpointPrefix + "cuda-checkpoint-path"

	// annotationCheckpointCudaCheckpointSequential indicates whether cuda-checkpoint should be run
	// sequentially. Optional, defaults to false.
	annotationCheckpointCudaCheckpointSequential = annotationCheckpointPrefix + "cuda-checkpoint-sequential"

	// annotationCheckpointEnable indicates whether files under /proc/gvisor should be present in
	// the container to allow the workload to trigger a checkpoint.
	annotationCheckpointEnable = annotationCheckpointPrefix + "enable"

	// annotationSaveRestoreExecArgv is the argv to use for the save/restore exec
	// binary.
	annotationSaveRestoreExecArgv = annotationCheckpointPrefix + "save-restore-exec-argv"

	// annotationSaveRestoreExecTimeout is the timeout to use for the save/restore
	// exec binary.
	annotationSaveRestoreExecTimeout = annotationCheckpointPrefix + "save-restore-exec-timeout"

	networkKey = "network"
)

// GetAnnotationCheckpointPath returns the checkpoint path specified in the
// container annotation. Return empty string if no annotation is specified.
func GetAnnotationCheckpointPath(conf *config.Config, spec *specs.Spec) (string, error) {
	path := spec.Annotations[annotationCheckpointPath]
	if len(path) != 0 {
		if len(conf.TestOnlyAutosaveImagePath) != 0 {
			return "", fmt.Errorf("autosave is not supported with %q annotation", annotationCheckpointPath)
		}
	}
	return path, nil
}

// GetAnnotationCheckpointCompression returns the checkpoint compression level
// specified in the container annotation.
func GetAnnotationCheckpointCompression(spec *specs.Spec) (statefile.CompressionLevel, error) {
	return statefile.CompressionLevelFromString(spec.Annotations[annotationCheckpointCompression])
}

// GetAnnotationCheckpointDirect returns true if the checkpoint is direct.
func GetAnnotationCheckpointDirect(spec *specs.Spec) bool {
	return specutils.AnnotationToBool(spec, annotationCheckpointDirect)
}

// SaveAsync starts a goroutine to save the kernel. Implements kernel.Saver.
func (l *Loader) SaveAsync() (err error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	cu := cleanup.Make(func() {
		// Save failed, unblock the callers as the workload will resume.
		l.k.OnCheckpointAttempt(err)
	})
	defer cu.Clean()

	// Save either not configured or already done.
	if len(l.saveFDs) == 0 {
		return linuxerr.ENXIO
	}

	o, err := saveOptsFromSpec(l.root.spec, l.saveFDs, l.saveCheckpointGofer)
	if err != nil {
		return err
	}
	// Close all FDs and set saveFDs to nil to mark that save has already
	// been triggered. So further attempts to save won't reuse and corrupt the files.
	for _, fd := range l.saveFDs {
		_ = fd.Close()
	}
	l.saveFDs = nil

	go func() {
		_ = l.save(o)
	}()
	// Loader.save() takes over the responsibility of calling OnCheckpointAttempt() when
	// it completes.
	cu.Release()

	return nil
}

// saveOptsFromSpec returns the saveOpts based on annotations from the spec. `fds` are
// no longer needed and can be closed after this is called.
func saveOptsFromSpec(spec *specs.Spec, fds []*fd.FD, useCheckpointGofer bool) (*control.SaveOpts, error) {
	// Convert the FDs to files which is required by the saveOpts.
	files := make([]*os.File, len(fds))
	for i, fd := range fds {
		var err error
		files[i], err = fd.File()
		if err != nil {
			return nil, err
		}
	}

	comp, err := GetAnnotationCheckpointCompression(spec)
	if err != nil {
		return nil, err
	}

	saveOpts := &control.SaveOpts{
		AppMFExcludeCommittedZeroPages: specutils.AnnotationToBool(spec, annotationCheckpointExcludeCommittedZeroPages),
		FilePayload: urpc.FilePayload{
			Files: files,
		},
		Metadata:                 comp.ToMetadata(),
		HavePagesFile:            len(files) > 1,
		Resume:                   specutils.AnnotationToBool(spec, annotationCheckpointResume),
		CudaCheckpointSequential: specutils.AnnotationToBool(spec, annotationCheckpointCudaCheckpointSequential),
	}
	if cudaPath, ok := spec.Annotations[annotationCheckpointCudaCheckpointPath]; ok {
		saveOpts.CudaCheckpointPath = cudaPath
	}
	if useCheckpointGofer {
		saveOpts.UseCheckpointGofer = true
		if comp == statefile.CompressionLevelNone {
			saveOpts.HavePagesFile = true
		}
	}

	if spec.Annotations[annotationSaveRestoreExecArgv] != "" {
		saveRestoreExecTimeout := control.DefaultSaveRestoreExecTimeout
		if spec.Annotations[annotationSaveRestoreExecTimeout] != "" {
			saveRestoreExecTimeout, err = time2.ParseDuration(spec.Annotations[annotationSaveRestoreExecTimeout])
			if err != nil {
				return nil, fmt.Errorf("failed to parse save-restore-exec-timeout: %w", err)
			}
		}
		saveOpts.ExecOpts = control.SaveRestoreExecOpts{
			Argv:    spec.Annotations[annotationSaveRestoreExecArgv],
			Timeout: saveRestoreExecTimeout,
		}
	}
	return saveOpts, nil
}

// The root container has the annotationCheckpointPath annotation set if
// application-driven checkpoint is enabled. Since the root container is
// always the first container, we can use it to initialize this global variable
// and it will inform the future sub-containers.
var appDrivenCheckpointEnabled = false

func newProcInternalData(conf *config.Config, spec *specs.Spec) *proc.InternalData {
	if len(spec.Annotations[annotationCheckpointPath]) != 0 {
		appDrivenCheckpointEnabled = true
	}
	return &proc.InternalData{
		GVisorMarkerFile:           conf.GVisorMarkerFile,
		OverrideProcs:              procFiles(conf),
		AppDrivenCheckpointEnabled: appDrivenCheckpointEnabled,
		SaveTriggerEnabled:         specutils.AnnotationToBool(spec, annotationCheckpointEnable),
		FSCheckpointEnabled:        specutils.AnnotationToBool(spec, annotationFSCheckpointEnable),
	}
}

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

	// metadata is the metadata contained in the statefile.
	metadata map[string]string

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

	// asyncMFLoader is used to load the MemoryFile pages. It handles the
	// asynchronous loading of the memory pages.
	asyncMFLoader *kernel.AsyncMFLoader

	// deviceFile is the required to start the platform.
	deviceFile *fd.FD

	// cm is the container manager that is used to restore the sandbox.
	cm *containerManager

	// checkpointedSpecs contains the map of container specs used during
	// checkpoint.
	checkpointedSpecs map[string]*specs.Spec

	// extractRootFsMode is true if we only want to extract the upper layer of
	// a rootfs overlay.
	extractRootFsMode bool

	// rootFsOutputTar is the file to write the rootfs upper layer tar archive to.
	rootFsOutputTar *os.File
}

// restoreSubcontainer restores a subcontainer.
func (r *restorer) restoreSubcontainer(spec *specs.Spec, conf *config.Config, l *Loader, cid string, stdioFDs, goferFDs, goferFilestoreFDs []*fd.FD, devGoferFD *fd.FD, goferMountConfs []specutils.GoferMountConf) error {
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

// restoreContainerInfo restores a container.
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

	if log.IsLogging(log.Debug) {
		for i, fd := range info.stdioFDs {
			log.Debugf("Restore app FD: %d host FD: %d", i, fd.FD())
		}
	}
	log.Infof("Restored container %d of %d", len(r.containers), r.totalContainers)
	r.timer.Reached(fmt.Sprintf("restore cont %d/%d", len(r.containers), r.totalContainers))

	// Non-container-specific restore work:

	if len(r.containers) == r.totalContainers {
		// Trigger the restore if this is the last container.
		if err := r.restore(l); err != nil {
			return err
		}
	}
	return nil
}

func (r *restorer) restore(l *Loader) error {
	log.Infof("Starting to restore %d containers", len(r.containers))

	// Validate the container specs to ensure they did not meaningfully change
	// between checkpoint and restore.
	if err := specutils.RestoreValidateSpec(r.checkpointedSpecs, l.GetContainerSpecs(), l.root.conf); err != nil {
		return fmt.Errorf("failed to handle restore spec validation: %w", err)
	}
	if l.root.conf.Network != config.NetworkSandbox && l.root.conf.Network != config.NetworkNone && l.root.conf.Network != config.NetworkHost {
		return fmt.Errorf("checkpoint not supported when using %s networking", l.root.conf.Network)
	}
	// Checkpoints without the network key predate hostinet support.
	savedNetwork, ok := r.metadata[networkKey]
	if !ok {
		savedNetwork = config.NetworkSandbox.String()
	}
	savedHost := savedNetwork == config.NetworkHost.String()
	if restoreHost := l.root.conf.Network == config.NetworkHost; savedHost != restoreHost {
		return fmt.Errorf("checkpoint created with %s networking cannot be restored with %s networking", savedNetwork, l.root.conf.Network)
	}
	r.timer.Reached("specs validated")

	p, err := createPlatform(l.root.conf, l.root.applicationCores, r.deviceFile, l.sandboxID)
	if err != nil {
		return fmt.Errorf("creating platform: %v", err)
	}

	// Start the old watchdog before replacing it with a new one below.
	l.watchdog.Start()

	// Release the kernel and replace it with a new one that will be restored into.
	var oldNvidiaDriverVersion nvconf.DriverVersion
	if l.k != nil {
		oldNvidiaDriverVersion = l.k.NvidiaDriverVersion
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

	if l.root.conf.Network == config.NetworkHost {
		devFile, err := os.Open("/proc/net/dev")
		if err != nil {
			log.Warningf("Failed to open /proc/net/dev during restore: %v", err)
		} else {
			l.hostinetNetDevFile = devFile
		}
		snmpFile, err := os.Open("/proc/net/snmp")
		if err != nil {
			log.Warningf("Failed to open /proc/net/snmp during restore: %v", err)
		} else {
			l.hostinetNetSNMPFile = snmpFile
		}
		defer func() {
			if l.hostinetNetDevFile != nil {
				l.hostinetNetDevFile.Close()
				l.hostinetNetDevFile = nil
			}
			if l.hostinetNetSNMPFile != nil {
				l.hostinetNetSNMPFile.Close()
				l.hostinetNetSNMPFile = nil
			}
		}()
	}

	// Seccomp filters have to be applied before vfs restore and before parsing
	// the state file.
	if err := l.installSeccompFilters(); err != nil {
		return err
	}

	l.mu.Lock()
	cu := cleanup.Make(func() {
		l.mu.Unlock()
	})
	defer cu.Clean()

	fdmap := make(map[checkpoint.ResourceID]int)
	mfmap := make(map[checkpoint.ResourceID]*pgalloc.MemoryFile)
	for _, cont := range r.containers {
		// TODO(b/298078576): Need to process hints here probably
		mntr := l.newContainerMounter(cont)
		if err = mntr.configureRestore(fdmap, mfmap); err != nil {
			return fmt.Errorf("configuring filesystem restore: %v", err)
		}

		for i, fd := range cont.stdioFDs {
			key := host.MakeResourceID(cont.containerName, i)
			fdmap[key] = fd.Release()
		}
		for _, customFD := range cont.passFDs {
			key := host.MakeResourceID(cont.containerName, customFD.guest)
			fdmap[key] = customFD.host.FD()
		}
	}

	log.Debugf("Restore using fdmap: %#v", fdmap)
	ctx := l.k.SupervisorContext()
	log.Debugf("Restore using mfmap: %v", mfmap)
	ctx = context.WithValues(ctx, map[any]any{
		vfs.CtxRestoreFilesystemFDMap:     fdmap,
		pgalloc.CtxMemoryFileMap:          mfmap,
		devutil.CtxDevGoferClientProvider: l.k,
	})

	if r.asyncMFLoader != nil {
		// Now that private memory files are known, kick off their loading in the
		// background goroutine.
		r.asyncMFLoader.KickoffPrivate(mfmap)
	}

	ctx, err = r.prepareNvproxyRestoreContextLocked(ctx, l)
	if err != nil {
		return err
	}
	ctx, err = r.prepareTPURestoreContextLocked(ctx, l)
	if err != nil {
		return err
	}

	// Load the state.
	r.timer.Reached("loading kernel")
	if r.extractRootFsMode {
		if err := l.k.ExtractRootfsUpperLayer(ctx, r.stateFile, r.asyncMFLoader, nil, time.NewCalibratedClocks(), r.rootFsOutputTar); err != nil {
			return fmt.Errorf("failed to extract rootfs upper layer: %w", err)
		}
		r.timer.Reached("rootfs upper layer extracted")
		return nil
	}
	if err := l.k.LoadFrom(ctx, r.stateFile, r.asyncMFLoader, nil, l, time.NewCalibratedClocks(), &vfs.CompleteRestoreOptions{}, r.timer.Fork("kernel load")); err != nil {
		return fmt.Errorf("failed to load kernel: %w", err)
	}
	r.timer.Reached("kernel loaded")
	if oldNvidiaDriverVersion.Major() > 0 && !l.k.NvidiaDriverVersion.Equals(oldNvidiaDriverVersion) {
		return fmt.Errorf("nvidia driver version changed during restore: was %v, now %v", oldNvidiaDriverVersion, l.k.NvidiaDriverVersion)
	}

	if r.asyncMFLoader != nil {
		if r.background {
			if err := r.asyncMFLoader.WaitMetadata(); err != nil {
				return err
			}
			r.timer.Reached("MF metadata loaded")
		} else {
			if err := r.asyncMFLoader.Wait(); err != nil {
				return err
			}
			r.timer.Reached("MFs loaded")
		}
	}

	// Since we have a new kernel we also must make a new watchdog.
	dogOpts := watchdog.DefaultOpts
	if err := dogOpts.TaskTimeoutAction.Set(l.root.conf.WatchdogAction); err != nil {
		return fmt.Errorf("setting watchdog action: %w", err)
	}
	dogOpts.StartupTimeout = 3 * time2.Minute // Give extra time for all containers to restore.
	dog := watchdog.New(l.k, dogOpts)

	// Change the loader fields to reflect the changes made when restoring.
	l.watchdog.Stop()
	l.watchdog = dog
	l.root.procArgs = kernel.CreateProcessArgs{}
	l.sandboxID = l.root.cid

	// Update all tasks in the system with:
	// 1. their respective new container IDs.
	// 2. the new hostname and domainname.
	visitedUTS := make(map[*kernel.UTSNamespace]struct{})
	for _, task := range l.k.TaskSet().Root.Tasks() {
		oldCid := task.ContainerID()
		name := l.k.ContainerName(oldCid)
		newCid, ok := l.containerIDs[name]
		if !ok {
			return fmt.Errorf("unable to remap task with CID %q (name: %q). Available names: %v", task.ContainerID(), name, l.containerIDs)
		}
		task.RestoreContainerID(newCid)

		if utsns := task.UTSNamespace(); utsns != nil {
			if _, ok := visitedUTS[utsns]; !ok {
				visitedUTS[utsns] = struct{}{}
				utsns.RestoreSpecValues(l.root.spec.Hostname, l.root.spec.Domainname)
			}
		}
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
	l.k.SetSaver(l)
	l.createRemappedNvproxyDeviceFiles(ctx)

	// Refresh the control server with the newly created kernel.
	l.ctrl.refreshHandlers()

	// Release `l.mu` before calling into callbacks.
	cu.Clean()

	r.timer.Reached("Starting sandbox")
	if err := r.cm.onStart(); err != nil {
		return fmt.Errorf("restorer.readyToStart callback failed: %w", err)
	}

	r.stateFile.Close()

	// Transfer ownership of the `timer` to a new goroutine.
	// This is because `timer.Log` blocks until all timed tasks are finished,
	// but some restore tasks may still run in the background, and we don't
	// want to block this function until they finish.
	postRestoreTimeline := r.timer.Fork("postRestore")
	go r.postRestore(l.k, postRestoreTimeline, r.timer)
	r.timer = nil

	return nil
}

func (r *restorer) postRestore(k *kernel.Kernel, timeline *timing.Timeline, timer *timing.Timer) {
	defer timer.Log()
	defer timeline.End()

	timeline.Reached("scheduled")
	if err := control.PostRestore(k, timeline); err != nil {
		r.cm.onRestoreFailed(fmt.Errorf("post restore work failed: %w", err))
		log.Warningf("Killing the sandbox after post restore work failed: %v", err)
		k.Kill(linux.WaitStatusTerminationSignal(linux.SIGKILL))
		return
	}
	timeline.Reached("post restore done")

	// Now that post restore work succeeded, increment the checkpoint gen
	// manually. The count was saved while the previous kernel was being saved
	// and checkpoint success was unknown at that time. Now we know the had
	// checkpoint succeeded. Allow the application to proceed while pages may
	// keep loading in the background.
	k.IncCheckpointGenOnRestore()

	// Wait for page loading to complete if happening in the background.
	if r.asyncMFLoader != nil {
		if err := r.asyncMFLoader.Wait(); err != nil {
			r.cm.onRestoreFailed(fmt.Errorf("async MemoryFile loading failed: %w", err))
			log.Warningf("Killing the sandbox after MemoryFile page loading failed: %v", err)
			k.Kill(linux.WaitStatusTerminationSignal(linux.SIGKILL))
			return
		}
	}

	var s Savings
	if err := r.calculateCPUSavings(&s); err != nil {
		log.Warningf("Failed to calculate CPU savings: %v", err)
	}
	if err := r.calculateWallTimeSavings(&s); err != nil {
		log.Warningf("Failed to calculate walltime savings: %v", err)
	}

	r.cm.onRestoreDone(s)
	timeline.Reached("kernel notified")
	log.Infof("Restore successful")
}

// Calculate the CPU time saved for restore.
func (r *restorer) calculateCPUSavings(s *Savings) error {
	t, err := state.CPUTime()
	if err != nil {
		return fmt.Errorf("failed to get CPU time usage for restore, err: %w", err)
	}
	savedTimeStr, ok := r.metadata[state.GvisorCPUUsageKey]
	if !ok {
		return fmt.Errorf("failed to retrieve CPU time usage from the metadata")
	}
	savedTime, err := time2.ParseDuration(savedTimeStr)
	if err != nil {
		return fmt.Errorf("cpu time usage in metadata %v is invalid, err: %w", savedTimeStr, err)
	}

	s.CPUTimeSaved = savedTime - t
	log.Infof("CPU time saved with restore: %v ms, restore CPU time: %v ms", s.CPUTimeSaved.Milliseconds(), t.Milliseconds())
	return nil
}

// Calculate the walltime saved for restore.
func (r *restorer) calculateWallTimeSavings(s *Savings) error {
	savedWtStr, ok := r.metadata[state.GvisorWallTimeKey]
	if !ok {
		return fmt.Errorf("failed to retrieve walltime from the metadata")
	}
	savedWt, err := time2.ParseDuration(savedWtStr)
	if err != nil {
		return fmt.Errorf("walltime in metadata %v is invalid, err: %w", savedWtStr, err)
	}

	wt := time2.Since(starttime.Get())
	s.WallTimeSaved = savedWt - wt
	log.Infof("Walltime saved with restore: %v ms, restore walltime: %v ms", s.WallTimeSaved.Milliseconds(), wt.Milliseconds())
	return nil
}

func (l *Loader) save(o *control.SaveOpts) (err error) {
	saveOpts, err := control.ConvertToStateSaveOpts(o)
	if err != nil {
		return err
	}
	defer saveOpts.Close()

	return l.saveWithOpts(saveOpts, &o.ExecOpts)
}

// saveWithOpts saves the kernel with the given options.
func (l *Loader) saveWithOpts(saveOpts *state.SaveOpts, execOpts *control.SaveRestoreExecOpts) (err error) {
	defer func() {
		// This closure is required to capture the final value of err.
		l.k.OnCheckpointAttempt(err)
	}()

	if saveOpts.Metadata == nil {
		saveOpts.Metadata = make(map[string]string)
	}
	saveOpts.Metadata[ContainerCountKey] = strconv.Itoa(l.containerCount())

	// Save runsc version.
	saveOpts.Metadata[VersionKey] = version.Version()

	saveOpts.Metadata[networkKey] = l.root.conf.Network.String()

	// Save container specs.
	specsStr, err := specutils.ConvertSpecsToString(l.GetContainerSpecs())
	if err != nil {
		return err
	}
	saveOpts.Metadata[ContainerSpecsKey] = specsStr

	// Save start time of the runsc process.
	saveOpts.StartTime = starttime.Get()

	if err := l.setNvproxyDeviceRemapMetadata(saveOpts); err != nil {
		return err
	}
	if err := l.setTPUDeviceRemapMetadata(saveOpts); err != nil {
		return err
	}

	state := control.State{
		Kernel:   l.k,
		Watchdog: l.watchdog,
	}
	return state.SaveWithOpts(saveOpts, execOpts)
}

func procFiles(conf *config.Config) []string {
	if conf.OverrideProcs == "" {
		return nil
	}
	return strings.Split(conf.OverrideProcs, ",")
}

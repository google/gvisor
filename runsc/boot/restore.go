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
	"reflect"
	"sort"
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
	"gvisor.dev/gvisor/runsc/boot/pprof"
	"gvisor.dev/gvisor/runsc/config"
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
	stateFile     io.ReadCloser
	pagesMetadata *fd.FD
	pagesFile     *fd.FD

	// If background is true, pagesFile may continue to be read after
	// restorer.restore() returns.
	background bool

	// deviceFile is the required to start the platform.
	deviceFile *fd.FD

	// restoreDone is a callback triggered when restore is successful.
	restoreDone func() error
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

func validateErrorWithMsg(field, cName string, oldV, newV any, msg string) error {
	return fmt.Errorf("%v does not match across checkpoint restore for container: %v, checkpoint %v restore %v, got error %v", field, cName, oldV, newV, msg)
}

func validateError(field, cName string, oldV, newV any) error {
	return fmt.Errorf("%v does not match across checkpoint restore for container: %v, checkpoint %v restore %v", field, cName, oldV, newV)
}

type mntNoSrc struct {
	destination string
	mntType     string
}

func validateMounts(cName string, o, n []specs.Mount) error {
	field := "Mount"
	if len(o) != len(n) {
		return validateErrorWithMsg(field, cName, o, n, "length mismatch")
	}
	if len(o) == 0 {
		return nil
	}

	// Create a new []Mount array without source as source path can vary
	// across checkpoint restore.
	oldMnts := make(map[mntNoSrc][]string)
	newMnts := make(map[mntNoSrc][]string)
	for _, m := range o {
		mnt := mntNoSrc{
			destination: m.Destination,
			mntType:     m.Type,
		}
		if _, ok := oldMnts[mnt]; ok {
			return validateError(field, cName, o, n)
		}
		opts := []string{}
		copy(opts, m.Options)
		sort.Strings(opts)
		oldMnts[mnt] = opts
	}
	for _, m := range n {
		mnt := mntNoSrc{
			destination: m.Destination,
			mntType:     m.Type,
		}
		if _, ok := newMnts[mnt]; ok {
			return validateError(field, cName, o, n)
		}
		opts := []string{}
		copy(opts, m.Options)
		sort.Strings(opts)
		newMnts[mnt] = opts
	}
	if !reflect.DeepEqual(oldMnts, newMnts) {
		return validateError(field, cName, o, n)
	}
	return nil
}

func validateDevices(cName string, o, n []specs.LinuxDevice) error {
	field := "Device"
	if len(o) != len(n) {
		return validateErrorWithMsg(field, cName, o, n, "length mismatch")
	}
	if len(o) == 0 {
		return nil
	}

	// Create with only Path and Type fields as other fields can vary during restore.
	oldDevs := make(map[specs.LinuxDevice]int)
	newDevs := make(map[specs.LinuxDevice]int)
	for _, d := range o {
		dev := specs.LinuxDevice{
			Path: d.Path,
			Type: d.Type,
		}
		if _, ok := oldDevs[dev]; !ok {
			oldDevs[dev] = 1
		}
		oldDevs[dev]++
	}
	for _, d := range n {
		dev := specs.LinuxDevice{
			Path: d.Path,
			Type: d.Type,
		}
		if _, ok := newDevs[dev]; !ok {
			newDevs[dev] = 1
		}
		newDevs[dev]++
	}
	if !reflect.DeepEqual(oldDevs, newDevs) {
		return validateError(field, cName, o, n)
	}
	return nil
}

func validateArray[T any](cName string, oldArr, newArr []T) error {
	var t T
	switch v := any(t).(type) {
	case string:
		if len(oldArr) != len(newArr) {
			return validateErrorWithMsg("Args", cName, oldArr, newArr, "length mismatch")
		}
		if len(oldArr) == 0 {
			return nil
		}
		oArr := (any(oldArr)).([]string)
		nArr := (any(newArr)).([]string)
		sort.Strings(oArr)
		sort.Strings(nArr)
		for i, val := range oArr {
			if val != nArr[i] {
				return validateError("Args", cName, oldArr, newArr)
			}
		}
		return nil
	case specs.LinuxDevice:
		return validateDevices(cName, (any(oldArr)).([]specs.LinuxDevice), (any(newArr)).([]specs.LinuxDevice))
	case specs.Mount:
		return validateMounts(cName, (any(oldArr)).([]specs.Mount), (any(newArr)).([]specs.Mount))
	default:
		if len(oldArr) != len(newArr) {
			return validateErrorWithMsg(reflect.TypeOf(v).String(), cName, oldArr, newArr, "length mismatch")
		}
		if len(oldArr) == 0 {
			return nil
		}
		oldMap := make(map[any]int)
		newMap := make(map[any]int)
		for i := 0; i < len(oldArr); i++ {
			key := oldArr[i]
			if _, ok := oldMap[key]; !ok {
				oldMap[key] = 1
			} else {
				oldMap[key]++
			}
			key = newArr[i]
			if _, ok := newMap[key]; !ok {
				newMap[key] = 1
			} else {
				newMap[key]++
			}
		}
		if !reflect.DeepEqual(oldMap, newMap) {
			return validateError(reflect.TypeOf(v).String(), cName, oldArr, newArr)
		}
	}

	return nil
}

func validateStruct(field, cName string, oldS, newS any) error {
	if !reflect.DeepEqual(oldS, newS) {
		return validateError(field, cName, oldS, newS)
	}
	return nil
}

func validateSpecForContainer(oldSpec, newSpec *specs.Spec, cName string) error {
	if (oldSpec.Root == nil && newSpec.Root != nil) || (oldSpec.Root != nil && newSpec.Root == nil) {
		return validateError("Root", cName, oldSpec.Root, newSpec.Root)
	}
	if (oldSpec.Process == nil && newSpec.Process != nil) || (oldSpec.Process != nil && newSpec.Process == nil) {
		return validateError("Process", cName, oldSpec.Process, newSpec.Process)
	}
	if (oldSpec.Linux == nil && newSpec.Linux != nil) || (oldSpec.Linux != nil && newSpec.Linux == nil) {
		return validateError("Linux", cName, oldSpec.Linux, newSpec.Linux)
	}

	if oldSpec.Version != newSpec.Version {
		return validateError("OCI Version", cName, oldSpec.Version, newSpec.Version)
	}
	validateStructMap := make(map[string][]any)
	if oldSpec.Root != nil && newSpec.Root != nil {
		validateStructMap["Root"] = []any{oldSpec.Root, newSpec.Root}
	}
	if err := validateArray(cName, oldSpec.Mounts, newSpec.Mounts); err != nil {
		return err
	}
	if oldSpec.Process != nil && newSpec.Process != nil {
		if oldSpec.Process.Terminal != newSpec.Process.Terminal {
			return validateError("Terminal", cName, oldSpec.Process.Terminal, newSpec.Process.Terminal)
		}
		if oldSpec.Process.Cwd != newSpec.Process.Cwd {
			return validateError("Cwd", cName, oldSpec.Process.Cwd, newSpec.Process.Cwd)
		}
		validateStructMap["User"] = []any{oldSpec.Process.User, newSpec.Process.User}
		validateStructMap["Rlimits"] = []any{oldSpec.Process.Rlimits, newSpec.Process.Rlimits}
		if err := validateArray(cName, oldSpec.Process.Args, newSpec.Process.Args); err != nil {
			return err
		}
	}
	if oldSpec.Linux != nil && newSpec.Linux != nil {
		if oldSpec.Linux.CgroupsPath != newSpec.Linux.CgroupsPath {
			return validateError("CgroupsPath", cName, oldSpec.Linux.CgroupsPath, newSpec.Linux.CgroupsPath)
		}
		validateStructMap["Sysctl"] = []any{oldSpec.Linux.Sysctl, newSpec.Linux.Sysctl}
		validateStructMap["Seccomp"] = []any{oldSpec.Linux.Seccomp, newSpec.Linux.Seccomp}
		if err := validateArray(cName, oldSpec.Linux.Devices, newSpec.Linux.Devices); err != nil {
			return err
		}
		if err := validateArray(cName, oldSpec.Linux.UIDMappings, newSpec.Linux.UIDMappings); err != nil {
			return err
		}
		if err := validateArray(cName, oldSpec.Linux.GIDMappings, newSpec.Linux.GIDMappings); err != nil {
			return err
		}
		if err := validateArray(cName, oldSpec.Linux.Namespaces, newSpec.Linux.Namespaces); err != nil {
			return err
		}
	}
	for key, val := range validateStructMap {
		if err := validateStruct(key, cName, val[0], val[1]); err != nil {
			return err
		}
	}

	// TODO(b/359591006): Validate runsc version, Linux.Resources, Process.Capabilities and Annotations.
	// TODO(b/359591006): Check other remaining fields for equality.
	return nil
}

// Validate OCI specs before restoring the containers.
func validateSpecs(oldSpecs, newSpecs map[string]*specs.Spec) error {
	for cName, newSpec := range newSpecs {
		oldSpec, ok := oldSpecs[cName]
		if !ok {
			return fmt.Errorf("checkpoint image does not contain spec for container: %q", cName)
		}
		return validateSpecForContainer(oldSpec, newSpec, cName)
	}

	return nil
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

	mf, err := createMemoryFile(l.root.conf.AppHugePages, l.hostShmemHuge)
	if err != nil {
		return fmt.Errorf("creating memory file: %v", err)
	}
	l.k.SetMemoryFile(mf)

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

	// Load the state.
	loadOpts := state.LoadOpts{
		Source:        r.stateFile,
		PagesMetadata: r.pagesMetadata,
		PagesFile:     r.pagesFile,
		Background:    r.background,
	}
	err = loadOpts.Load(ctx, l.k, nil, oldInetStack, time.NewCalibratedClocks(), &vfs.CompleteRestoreOptions{}, l.saveRestoreNet)
	r.pagesFile = nil // transferred to loadOpts.Load()
	if err != nil {
		return err
	}

	oldSpecs, err := popContainerSpecsFromCheckpoint(l.k)
	if err != nil {
		return err
	}
	if err := validateSpecs(oldSpecs, l.containerSpecs); err != nil {
		return err
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
	for _, tg := range l.k.RootPIDNamespace().ThreadGroups() {
		if tg.Leader().Origin == kernel.OriginExec {
			if err := l.k.SendExternalSignalThreadGroup(tg, &linux.SignalInfo{Signo: int32(linux.SIGKILL)}); err != nil {
				log.Warningf("Failed to kill exec process after restore: %v", err)
			}
		}
	}

	l.k.RestoreContainerMapping(l.containerIDs)

	if err := l.kernelInitExtra(); err != nil {
		return err
	}

	// Refresh the control server with the newly created kernel.
	l.ctrl.refreshHandlers()

	// Release `l.mu` before calling into callbacks.
	cu.Clean()

	// r.restoreDone() signals and waits for the sandbox to start.
	if err := r.restoreDone(); err != nil {
		return err
	}

	r.stateFile.Close()
	if r.pagesFile != nil {
		r.pagesFile.Close()
	}
	if r.pagesMetadata != nil {
		r.pagesMetadata.Close()
	}

	go func() {
		if err := postRestoreImpl(l); err != nil {
			log.Warningf("Killing the sandbox after post restore work failed: %w", err)
			l.k.Kill(linux.WaitStatusTerminationSignal(linux.SIGKILL))
			return
		}

		// Restore was successful, so increment the checkpoint count manually. The
		// count was saved while the previous kernel was being saved and checkpoint
		// success was unknown at that time. Now we know the checkpoint succeeded.
		l.k.IncCheckpointCount()
		log.Infof("Restore successful")
	}()
	return nil
}

func (l *Loader) save(o *control.SaveOpts) (err error) {
	defer func() {
		// This closure is required to capture the final value of err.
		l.k.OnCheckpointAttempt(err)
	}()
	l.k.ResetCheckpointStatus()

	// TODO(gvisor.dev/issues/6243): save/restore not supported w/ hostinet
	if l.root.conf.Network == config.NetworkHost {
		return errors.New("checkpoint not supported when using hostinet")
	}

	if o.Metadata == nil {
		o.Metadata = make(map[string]string)
	}
	o.Metadata["container_count"] = strconv.Itoa(l.containerCount())

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
		if err := postResumeImpl(l); err != nil {
			return err
		}
	}
	return nil
}

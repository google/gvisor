// Copyright 2024 The gVisor Authors.
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
	"cmp"
	"encoding/json"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strconv"

	specs "github.com/opencontainers/runtime-spec/specs-go"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/abi/nvgpu"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/devutil"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/devices/nvproxy"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/dev"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/state"
	"gvisor.dev/gvisor/runsc/config"
	"gvisor.dev/gvisor/runsc/specutils"
)

const (
	// nvproxyDeviceRemapIDsKey is the metadata key for the marshaled
	// nvproxy.DeviceRemapIDs slice.
	nvproxyDeviceRemapIDsKey = "nvproxy-device-remap-ids"
)

// setNvproxyDeviceRemapMetadata records the set of accessible GPUs for
// remapping after restore. This will constrain restore to needing the same
// number of GPUs or more, so only do this if at least one GPU device file is
// open, which is indicative of GPU usage.
func (l *Loader) setNvproxyDeviceRemapMetadata(saveOpts *state.SaveOpts) error {
	if !nvproxy.AnyFrontendDevicesOpen(l.k.VFS()) {
		return nil
	}
	ctx := l.k.SupervisorContext()
	ids, err := getNvproxyDeviceRemapIDs(ctx, l.k, l.GetContainerSpecs(), l.root.conf)
	if err != nil {
		return fmt.Errorf("failed to get nvproxy device IDs: %w", err)
	}
	if err := nvproxy.CheckDevicesRemappable(ids); err != nil {
		return fmt.Errorf("nvproxy device is not remappable: %w", err)
	}
	idsJSON, err := json.Marshal(ids)
	if err != nil {
		return fmt.Errorf("failed to marshal nvproxy device IDs: %w", err)
	}
	saveOpts.Metadata[nvproxyDeviceRemapIDsKey] = string(idsJSON)
	if log.IsLogging(log.Debug) {
		log.Debugf("Saving %d nvproxy devices:", len(ids))
		for _, id := range ids {
			log.Debugf("%v", &id)
		}
	}
	return nil
}

// +checklocks:l.mu
func (r *restorer) prepareNvproxyRestoreContextLocked(ctx context.Context, l *Loader) (context.Context, error) {
	if idsJSON, ok := r.metadata[nvproxyDeviceRemapIDsKey]; ok {
		var oldIDs []nvproxy.DeviceRemapID
		if err := json.Unmarshal([]byte(idsJSON), &oldIDs); err != nil {
			return ctx, fmt.Errorf("failed to unmarshal checkpointed nvproxy device IDs: %w", err)
		}
		newIDs, err := getNvproxyDeviceRemapIDs(ctx, l.k, l.containerSpecs, l.root.conf)
		if err != nil {
			return ctx, fmt.Errorf("failed to get nvproxy device IDs: %w", err)
		}
		dr, err := nvproxy.MakeDeviceRemapping(oldIDs, newIDs)
		if err != nil {
			return ctx, fmt.Errorf("failed to remap nvproxy devices: %w", err)
		}
		ctx = context.WithValue(ctx, nvproxy.CtxDeviceRemapping, dr)
		if log.IsLogging(log.Debug) {
			log.Debugf("Remapping %d nvproxy devices:", len(dr.NewDeviceByOld))
			for _, oldMinor := range slices.Sorted(maps.Keys(dr.OldDeviceByMinor)) {
				oldID := dr.OldDeviceByMinor[oldMinor]
				log.Debugf("%v => %v", oldID, dr.NewDeviceByOld[oldID])
			}
		}
	}
	return ctx, nil
}

func getNvproxyDeviceRemapIDs(ctx context.Context, k *kernel.Kernel, specs map[string]*specs.Spec, conf *config.Config) ([]nvproxy.DeviceRemapID, error) {
	minorsMap := make(map[uint32]*devutil.GoferClient)
	var anyDevClient *devutil.GoferClient
	for contName, spec := range specs {
		devClient := k.GetDevGoferClient(contName)
		if gotAny, err := collectContainerNvidiaRegularDevices(ctx, spec, conf, devClient, minorsMap); err != nil {
			return nil, err
		} else if gotAny {
			anyDevClient = devClient
		}
	}
	ids := make([]nvproxy.DeviceRemapID, 0, len(minorsMap))
	for minor, devClient := range minorsMap {
		ids = append(ids, nvproxy.DeviceRemapID{
			Minor:          minor,
			DevGoferClient: devClient,
		})
	}
	// Sort devices by minor number:
	//
	// - Since Go map iteration order is randomized, some kind of sorting is
	// needed to make device order reproducible. This ensures that the
	// remapping for a given checkpoint to a given set of restored GPUs is
	// consistent, and that a checkpoint restored with the same set of GPUs
	// with which it was saved gets a no-op remapping, both of which are
	// intuitively desirable.
	//
	// - When device hardware is identical and
	// CUDA_VISIBLE_DEVICES/CUDA_DEVICE_ORDER are unspecified, CUDA appears to
	// order devices by device minor number, GPU ID, or something else that
	// correlates with these (possibly PCI info; not device instance and not
	// UUID), so sorting device sets by minor number during both save and
	// restore is believed to be most likely to produce the same remapping as
	// cuda-checkpoint without the --device-map flag.
	slices.SortFunc(ids, func(a, b nvproxy.DeviceRemapID) int {
		return cmp.Compare(a.Minor, b.Minor)
	})
	if err := nvproxy.FillDeviceRemapIDsFromMinor(ctx, anyDevClient, ids); err != nil {
		return nil, err
	}
	return ids, nil
}

func collectContainerNvidiaRegularDevices(ctx context.Context, spec *specs.Spec, conf *config.Config, devClient *devutil.GoferClient, minors map[uint32]*devutil.GoferClient) (bool, error) {
	// This is based on vfs.go:createDeviceFiles().
	gotAny := false
	if spec.Linux != nil {
		for _, dev := range spec.Linux.Devices {
			if dev.Type == "c" && dev.Major == nvgpu.NV_MAJOR_DEVICE_NUMBER && dev.Minor <= nvgpu.NV_MINOR_DEVICE_NUMBER_REGULAR_MAX {
				minors[uint32(dev.Minor)] = devClient
				gotAny = true
			}
		}
	}
	if specutils.GPUFunctionalityRequestedViaHook(spec, conf) {
		goferMinors, err := nvidiaRegularDeviceMinorsFromGofer(ctx, devClient)
		if err != nil {
			return gotAny, err
		}
		for _, minor := range goferMinors {
			minors[minor] = devClient
			gotAny = true
		}
	}
	return gotAny, nil
}

// nvidiaRegularDeviceMinorsFromGofer returns the minor device numbers of the
// nvidia regular devices (i.e. /dev/nvidia#) visible in devClient's directory.
func nvidiaRegularDeviceMinorsFromGofer(ctx context.Context, devClient *devutil.GoferClient) ([]uint32, error) {
	if devClient == nil {
		return nil, fmt.Errorf("dev gofer client not found")
	}
	names, err := devClient.DirentNames(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get names of dirents from dev gofer: %w", err)
	}
	nvidiaDeviceRegex := regexp.MustCompile(`^nvidia(\d+)$`)
	var minors []uint32
	for _, name := range names {
		ms := nvidiaDeviceRegex.FindStringSubmatch(name)
		if ms == nil {
			continue
		}
		minor, err := strconv.ParseUint(ms[1], 10, 32)
		if err != nil {
			return nil, fmt.Errorf("invalid nvidia device name %q: %w", name, err)
		}
		if minor > nvgpu.NV_MINOR_DEVICE_NUMBER_REGULAR_MAX {
			return nil, fmt.Errorf("invalid nvidia regular minor device number %d", minor)
		}
		minors = append(minors, uint32(minor))
	}
	return minors, nil
}

// createNvproxyDeviceFilesAfterRestore creates device files for GPUs available
// after restore. The set of GPUs may differ from the set with which the
// sandbox was saved, in which case restored /dev filesystems lack device files
// for GPUs that did not exist during save.
//
// +checklocks:l.mu
func (l *Loader) createNvproxyDeviceFilesAfterRestore(ctx context.Context) {
	for contName, spec := range l.containerSpecs {
		minorsMap := make(map[uint32]*devutil.GoferClient)
		devClient := l.k.GetDevGoferClient(contName)
		if _, err := collectContainerNvidiaRegularDevices(ctx, spec, l.root.conf, devClient, minorsMap); err != nil {
			log.Warningf("Failed to collect nvidia devices available to container %q after restore: %v", contName, err)
			continue
		}
		if len(minorsMap) == 0 {
			continue
		}
		ep, ok := l.processes[execID{cid: l.containerIDs[contName]}]
		if !ok || ep.tg == nil {
			log.Warningf("Failed to find root process of container %q; not creating its nvidia device files", contName)
			continue
		}
		l.createNvproxyDeviceFilesAfterRestoreFor(ctx, contName, ep.tg.Leader(), minorsMap)
	}
}

func (l *Loader) createNvproxyDeviceFilesAfterRestoreFor(ctx context.Context, contName string, leader *kernel.Task, minors map[uint32]*devutil.GoferClient) {
	mntns := leader.GetMountNamespace()
	if mntns == nil {
		// The container's root process has already exited.
		return
	}
	defer mntns.DecRef(ctx)
	rootVD := mntns.Root(ctx)
	if !rootVD.Ok() {
		return
	}
	defer rootVD.DecRef(ctx)
	vfsObj := l.k.VFS()
	creds := auth.CredentialsFromContext(ctx)
	for minor := range minors {
		pathname := fmt.Sprintf("/dev/nvidia%d", minor)
		if err := dev.CreateDeviceFile(ctx, vfsObj, creds, rootVD, pathname, nvgpu.NV_MAJOR_DEVICE_NUMBER, minor, linux.FileMode(linux.S_IFCHR|0o666), nil /* uid */, nil /* gid */); err != nil {
			log.Warningf("Failed to create device file %s in container %q: %v", pathname, contName, err)
		}
	}
}

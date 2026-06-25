// Copyright 2026 The gVisor Authors.
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
	"slices"
	"strconv"
	"strings"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/devices/tpuproxy/vfio"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/state"
)

const (
	tpuDeviceRemapIDsKey = "tpu-device-remap-ids"
	googleVendorID       = "0x1ae0"
)

// setTPUDeviceRemapMetadata records the set of accessible TPUs for remapping
// after restore.
func (l *Loader) setTPUDeviceRemapMetadata(saveOpts *state.SaveOpts) error {
	if !vfio.AnyDevicesOpen(l.k.VFS()) {
		return nil
	}
	ctx := l.k.SupervisorContext()
	ids, err := getTPUDeviceRemapIDs(ctx, l.k, l.GetContainerSpecs())
	if err != nil {
		return fmt.Errorf("failed to get TPU device IDs: %w", err)
	}
	idsJSON, err := json.Marshal(ids)
	if err != nil {
		return fmt.Errorf("failed to marshal TPU device IDs: %w", err)
	}
	saveOpts.Metadata[tpuDeviceRemapIDsKey] = string(idsJSON)
	if log.IsLogging(log.Debug) {
		log.Debugf("Saving %d TPU devices:", len(ids))
		for _, id := range ids {
			log.Debugf("%+v", id)
		}
	}
	return nil
}

// +checklocks:l.mu
func (r *restorer) prepareTPURestoreContextLocked(ctx context.Context, l *Loader) (context.Context, error) {
	if idsJSON, ok := r.metadata[tpuDeviceRemapIDsKey]; ok {
		var oldIDs []vfio.TPUDeviceRemapID
		if err := json.Unmarshal([]byte(idsJSON), &oldIDs); err != nil {
			return ctx, fmt.Errorf("failed to unmarshal checkpointed TPU device IDs: %w", err)
		}
		newIDs, err := getTPUDeviceRemapIDs(ctx, l.k, l.containerSpecs)
		if err != nil {
			return ctx, fmt.Errorf("failed to get TPU device IDs: %w", err)
		}
		dr, err := makeTPUDeviceRemapping(oldIDs, newIDs)
		if err != nil {
			return ctx, fmt.Errorf("failed to remap TPU devices: %w", err)
		}
		ctx = context.WithValue(ctx, vfio.CtxTPUDeviceRemapping, dr)
		if log.IsLogging(log.Debug) {
			log.Debugf("Remapping %d TPU devices:", len(dr.NewBDFByOldBDF))
			for oldBDF, newBDF := range dr.NewBDFByOldBDF {
				log.Debugf("%s => %s", oldBDF, newBDF)
			}
		}
	}
	return ctx, nil
}

func getTPUDeviceRemapIDs(ctx context.Context, k *kernel.Kernel, specs map[string]*specs.Spec) ([]vfio.TPUDeviceRemapID, error) {
	groups := make(map[uint32]struct{})
	for _, spec := range specs {
		if spec.Linux != nil {
			for _, dev := range spec.Linux.Devices {
				if strings.HasPrefix(dev.Path, "/dev/vfio/") {
					groupStr := strings.TrimPrefix(dev.Path, "/dev/vfio/")
					if groupNum, err := strconv.ParseUint(groupStr, 10, 32); err == nil {
						groups[uint32(groupNum)] = struct{}{}
					}
				}
			}
		}
	}

	var ids []vfio.TPUDeviceRemapID
	for groupNum := range groups {
		bdfs, err := getTPUBDFsInGroup(groupNum)
		if err != nil {
			return nil, err
		}
		for _, bdf := range bdfs {
			ids = append(ids, vfio.TPUDeviceRemapID{
				BDF:      bdf,
				GroupNum: groupNum,
			})
		}
	}

	slices.SortFunc(ids, func(a, b vfio.TPUDeviceRemapID) int {
		return cmp.Compare(a.BDF, b.BDF)
	})

	return ids, nil
}

func getTPUBDFsInGroup(groupNum uint32) ([]string, error) {
	groupDir := fmt.Sprintf("/sys/kernel/iommu_groups/%d/devices", groupNum)
	entries, err := safeReadDir(groupDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read IOMMU group directory %s: %w", groupDir, err)
	}

	var bdfs []string
	for _, entry := range entries {
		bdf := entry
		vendorPath := fmt.Sprintf("/sys/bus/pci/devices/%s/vendor", bdf)
		vendorBytes, err := safeReadFile(vendorPath)
		if err != nil {
			continue
		}
		vendor := strings.TrimSpace(string(vendorBytes))
		if vendor == googleVendorID {
			bdfs = append(bdfs, bdf)
		}
	}
	return bdfs, nil
}

func safeReadDir(path string) ([]string, error) {
	fd, err := unix.Openat(-1, path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to open directory %s: %w", path, err)
	}
	defer unix.Close(fd)

	var names []string
	buf := make([]byte, 4096)
	for {
		n, err := unix.Getdents(fd, buf)
		if err != nil {
			return nil, fmt.Errorf("failed to get dents for %s: %w", path, err)
		}
		if n == 0 {
			break
		}
		var count int
		_, count, names = unix.ParseDirent(buf[:n], -1, names)
		if count == 0 {
			break
		}
	}
	var filtered []string
	for _, name := range names {
		if name != "." && name != ".." {
			filtered = append(filtered, name)
		}
	}
	return filtered, nil
}

func safeReadFile(path string) ([]byte, error) {
	fd, err := unix.Openat(-1, path, unix.O_RDONLY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to open file %s: %w", path, err)
	}
	defer unix.Close(fd)

	var buf [256]byte
	n, err := unix.Read(fd, buf[:])
	if err != nil {
		return nil, fmt.Errorf("failed to read file %s: %w", path, err)
	}
	return buf[:n], nil
}

func makeTPUDeviceRemapping(oldIDs, newIDs []vfio.TPUDeviceRemapID) (*vfio.TPUDeviceRemapping, error) {
	if len(oldIDs) > len(newIDs) {
		return nil, fmt.Errorf("can't remap %d saved TPU devices to %d restored TPU devices", len(oldIDs), len(newIDs))
	}
	dr := &vfio.TPUDeviceRemapping{
		NewBDFByOldBDF:     make(map[string]string),
		NewGroupByOldGroup: make(map[uint32]uint32),
		NewGroupByNewBDF:   make(map[string]uint32),
	}
	for i := range oldIDs {
		oldID := oldIDs[i]
		newID := newIDs[i]
		dr.NewBDFByOldBDF[oldID.BDF] = newID.BDF
		dr.NewGroupByOldGroup[oldID.GroupNum] = newID.GroupNum
		dr.NewGroupByNewBDF[newID.BDF] = newID.GroupNum
	}
	return dr, nil
}

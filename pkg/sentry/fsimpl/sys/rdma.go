// Copyright 2026 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package sys

import (
	"fmt"
	"path"
	regex "regexp"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/kernfs"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
)

var (
	// uverbsDeviceRegex matches uverbs device directories (e.g. uverbs0).
	uverbsDeviceRegex = regex.MustCompile(`^uverbs\d+$`)

	// ibDeviceRegex matches InfiniBand device directories (e.g. mlx5_0).
	ibDeviceRegex = regex.MustCompile(`^mlx5_\d+$`)

	// Allowlisted files under /sys/class/infiniband_verbs/uverbsN/.
	uverbsSysfsFiles = map[string]bool{
		"ibdev":       true,
		"abi_version": true,
		"dev":         true,
	}

	// Allowlisted files under /sys/class/infiniband/<device>/.
	ibDeviceSysfsFiles = map[string]bool{
		"node_type":      true,
		"node_guid":      true,
		"node_desc":      true,
		"sys_image_guid": true,
		"fw_ver":         true,
		"hca_type":       true,
		"hw_rev":         true,
		"board_id":       true,
	}

	// Allowlisted files under /sys/class/infiniband/<device>/ports/<N>/.
	ibPortSysfsFiles = map[string]bool{
		"state":          true,
		"phys_state":     true,
		"link_layer":     true,
		"rate":           true,
		"lid":            true,
		"sm_lid":         true,
		"sm_sl":          true,
		"cap_mask":       true,
		"lid_mask_count": true,
		"has_smi":        true,
	}
)

const (
	hostInfinibandVerbsPath = "/sys/class/infiniband_verbs"
	hostInfinibandPath      = "/sys/class/infiniband"
)

// newInfinibandVerbsDir creates the /sys/class/infiniband_verbs/ directory
// by reading the host sysfs and mirroring allowlisted entries.
func (fs *filesystem) newInfinibandVerbsDir(ctx context.Context, creds *auth.Credentials, sysfsPrefix string) (map[string]kernfs.Inode, error) {
	hostPath := path.Join(sysfsPrefix, hostInfinibandVerbsPath)
	dents, err := hostDirEntries(hostPath)
	if err != nil {
		log.Debugf("rdma sysfs: %s not accessible: %v, skipping", hostPath, err)
		return nil, nil
	}

	result := map[string]kernfs.Inode{}
	for _, dent := range dents {
		if !uverbsDeviceRegex.MatchString(dent) {
			continue
		}
		deviceDir, err := fs.newUverbsDeviceDir(ctx, creds, path.Join(hostPath, dent))
		if err != nil {
			return nil, err
		}
		result[dent] = fs.newDir(ctx, creds, defaultSysDirMode, deviceDir)
	}
	return result, nil
}

// newUverbsDeviceDir creates entries for a single uverbs device directory,
// e.g. /sys/class/infiniband_verbs/uverbs0/.
func (fs *filesystem) newUverbsDeviceDir(ctx context.Context, creds *auth.Credentials, hostDir string) (map[string]kernfs.Inode, error) {
	dents, err := hostDirEntries(hostDir)
	if err != nil {
		return nil, fmt.Errorf("rdma sysfs: reading %s: %w", hostDir, err)
	}
	result := map[string]kernfs.Inode{}
	for _, dent := range dents {
		if !uverbsSysfsFiles[dent] {
			continue
		}
		result[dent] = fs.newHostFile(ctx, creds, defaultSysMode, path.Join(hostDir, dent))
	}
	return result, nil
}

// newInfinibandDir creates the /sys/class/infiniband/ directory by reading
// the host sysfs and mirroring allowlisted entries for each IB device.
func (fs *filesystem) newInfinibandDir(ctx context.Context, creds *auth.Credentials, sysfsPrefix string) (map[string]kernfs.Inode, error) {
	hostPath := path.Join(sysfsPrefix, hostInfinibandPath)
	dents, err := hostDirEntries(hostPath)
	if err != nil {
		log.Debugf("rdma sysfs: %s not accessible: %v, skipping", hostPath, err)
		return nil, nil
	}

	result := map[string]kernfs.Inode{}
	for _, dent := range dents {
		if !ibDeviceRegex.MatchString(dent) {
			continue
		}
		deviceDir, err := fs.newIBDeviceDir(ctx, creds, path.Join(hostPath, dent))
		if err != nil {
			return nil, err
		}
		result[dent] = fs.newDir(ctx, creds, defaultSysDirMode, deviceDir)
	}
	return result, nil
}

// newIBDeviceDir creates entries for a single InfiniBand device directory,
// e.g. /sys/class/infiniband/mlx5_0/.
func (fs *filesystem) newIBDeviceDir(ctx context.Context, creds *auth.Credentials, hostDir string) (map[string]kernfs.Inode, error) {
	dents, err := hostDirEntries(hostDir)
	if err != nil {
		return nil, fmt.Errorf("rdma sysfs: reading %s: %w", hostDir, err)
	}
	result := map[string]kernfs.Inode{}
	for _, dent := range dents {
		dentPath := path.Join(hostDir, dent)
		if ibDeviceSysfsFiles[dent] {
			result[dent] = fs.newHostFile(ctx, creds, defaultSysMode, dentPath)
			continue
		}
		if dent == "ports" {
			portsDir, err := fs.newIBPortsDir(ctx, creds, dentPath)
			if err != nil {
				return nil, err
			}
			if portsDir != nil {
				result["ports"] = fs.newDir(ctx, creds, defaultSysDirMode, portsDir)
			}
		}
	}
	return result, nil
}

// newIBPortsDir creates the ports/ subdirectory for an IB device.
func (fs *filesystem) newIBPortsDir(ctx context.Context, creds *auth.Credentials, hostDir string) (map[string]kernfs.Inode, error) {
	dents, err := hostDirEntries(hostDir)
	if err != nil {
		return nil, fmt.Errorf("rdma sysfs: reading %s: %w", hostDir, err)
	}
	result := map[string]kernfs.Inode{}
	for _, dent := range dents {
		portDir, err := fs.newIBPortDir(ctx, creds, path.Join(hostDir, dent))
		if err != nil {
			return nil, err
		}
		result[dent] = fs.newDir(ctx, creds, defaultSysDirMode, portDir)
	}
	return result, nil
}

// newIBPortDir creates entries for a single port directory,
// e.g. /sys/class/infiniband/mlx5_0/ports/1/.
func (fs *filesystem) newIBPortDir(ctx context.Context, creds *auth.Credentials, hostDir string) (map[string]kernfs.Inode, error) {
	dents, err := hostDirEntries(hostDir)
	if err != nil {
		return nil, fmt.Errorf("rdma sysfs: reading %s: %w", hostDir, err)
	}
	result := map[string]kernfs.Inode{}
	for _, dent := range dents {
		dentPath := path.Join(hostDir, dent)
		if ibPortSysfsFiles[dent] {
			result[dent] = fs.newHostFile(ctx, creds, defaultSysMode, dentPath)
			continue
		}
		// Mirror subdirectories like gids/, pkeys/, gid_attrs/,
		// counters/, hw_counters/ as directories with host-backed files.
		switch dent {
		case "gids", "pkeys", "gid_attrs", "counters", "hw_counters":
			subDir, err := fs.mirrorFlatHostDir(ctx, creds, dentPath)
			if err != nil {
				log.Debugf("rdma sysfs: skipping %s: %v", dentPath, err)
				continue
			}
			result[dent] = fs.newDir(ctx, creds, defaultSysDirMode, subDir)
		}
	}
	return result, nil
}

// mirrorFlatHostDir mirrors a host directory as a flat collection of
// host-backed read-only files. Only regular files are included.
func (fs *filesystem) mirrorFlatHostDir(ctx context.Context, creds *auth.Credentials, hostDir string) (map[string]kernfs.Inode, error) {
	dents, err := hostDirEntries(hostDir)
	if err != nil {
		return nil, err
	}
	result := map[string]kernfs.Inode{}
	for _, dent := range dents {
		dentPath := path.Join(hostDir, dent)
		mode, err := hostFileMode(dentPath)
		if err != nil {
			continue
		}
		switch mode {
		case unix.S_IFREG:
			result[dent] = fs.newHostFile(ctx, creds, defaultSysMode, dentPath)
		case unix.S_IFDIR:
			subDir, err := fs.mirrorFlatHostDir(ctx, creds, dentPath)
			if err != nil {
				continue
			}
			result[dent] = fs.newDir(ctx, creds, defaultSysDirMode, subDir)
		default:
			// Skip symlinks and other special files.
		}
	}
	return result, nil
}

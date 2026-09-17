// Copyright 2026 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package utils

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/containerd/log"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/runsc/specutils"
)

var (
	// fuseConnectionsDir is the default sysfs directory where FUSE connection control
	// directories reside on the host. It is a variable so tests can override it.
	fuseConnectionsDir = "/sys/fs/fuse/connections"

	// mountinfoPath is the path to the mountinfo file. Variable for testing.
	mountinfoPath = "/proc/self/mountinfo"
)

// parseFuseMinorsFromMountinfo parses mountinfo formatted content and returns unique FUSE minor device IDs
// for mounts matching the predicate matchFn. It does not perform any stat() or VFS calls, preventing deadlocks
// when a FUSE daemon is wedged.
func parseFuseMinorsFromMountinfo(mountinfoContent string, matchFn func(mountPoint string) bool) []uint32 {
	var minors []uint32
	seen := make(map[uint32]bool)
	scanner := bufio.NewScanner(strings.NewReader(mountinfoContent))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		// In /proc/[pid]/mountinfo (see proc(5)), each line starts with 6 fixed prefix
		// fields (indices 0..5: mount ID, parent ID, major:minor, root, mount point,
		// mount options), followed by zero or more optional fields, a "-" separator,
		// filesystem type, mount source, and super options. A line with fewer than 7
		// fields cannot even reach the separator (earliest index 6) or filesystem type,
		// and checking this guarantees safe indexing of fields[2] and fields[4].
		if len(fields) < 7 {
			continue
		}
		// Find the "-" separator which separates optional fields from fs type.
		sepIdx := -1
		for i, field := range fields {
			if field == "-" {
				sepIdx = i
				break
			}
		}
		if sepIdx == -1 || sepIdx+1 >= len(fields) {
			continue
		}
		fsType := fields[sepIdx+1]
		if fsType != "fuse" && !strings.HasPrefix(fsType, "fuse.") {
			continue
		}

		dev := fields[2] // "major:minor"
		parts := strings.Split(dev, ":")
		if len(parts) != 2 {
			continue
		}
		minor64, err := strconv.ParseUint(parts[1], 10, 32)
		if err != nil {
			continue
		}
		minor := uint32(minor64)

		mountPoint := fields[4]
		if matchFn != nil && !matchFn(mountPoint) {
			continue
		}

		if !seen[minor] {
			seen[minor] = true
			minors = append(minors, minor)
		}
	}
	return minors
}

// isMountOrSubpath returns whether source is the mountPoint itself or a subdirectory within it.
func isMountOrSubpath(source, mountPoint string) bool {
	cleanSource := filepath.Clean(source)
	cleanMountPoint := filepath.Clean(mountPoint)
	if cleanSource == cleanMountPoint {
		return true
	}
	if cleanMountPoint == string(filepath.Separator) {
		return strings.HasPrefix(cleanSource, cleanMountPoint)
	}
	return strings.HasPrefix(cleanSource, cleanMountPoint+string(filepath.Separator))
}

// FindFuseMountMinors inspects the given mounts, identifies any FUSE filesystems
// by parsing /proc/self/mountinfo, and returns their unique minor device numbers.
// It avoids calling stat() or statfs() on mounts to prevent deadlocking when FUSE is wedged.
func FindFuseMountMinors(mounts []specs.Mount) []uint32 {
	var cleanSources []string
	for _, m := range mounts {
		if m.Source != "" {
			cleanSources = append(cleanSources, filepath.Clean(m.Source))
		}
	}
	if len(cleanSources) == 0 {
		return nil
	}
	content, err := os.ReadFile(mountinfoPath)
	if err != nil {
		log.L.Warnf("Failed to read %s: %v", mountinfoPath, err)
		return nil
	}
	return parseFuseMinorsFromMountinfo(string(content), func(mountPoint string) bool {
		for _, src := range cleanSources {
			if isMountOrSubpath(src, mountPoint) {
				return true
			}
		}
		return false
	})
}

// FindPodCSIFuseMinors searches /proc/self/mountinfo for any CSI FUSE mounts
// belonging to the pod UID and returns their unique minor device numbers.
// It avoids calling stat() or statfs() on mounts to prevent deadlocking when FUSE is wedged.
func FindPodCSIFuseMinors(podUID string) []uint32 {
	if podUID == "" {
		return nil
	}
	content, err := os.ReadFile(mountinfoPath)
	if err != nil {
		log.L.Warnf("Failed to read %s: %v", mountinfoPath, err)
		return nil
	}
	podSubpath := string(filepath.Separator) + filepath.Join("pods", podUID) + string(filepath.Separator)
	return parseFuseMinorsFromMountinfo(string(content), func(mountPoint string) bool {
		return strings.Contains(mountPoint, podSubpath) &&
			(strings.Contains(mountPoint, "kubernetes.io~csi") || strings.Contains(mountPoint, "volume-subpaths"))
	})
}

// AbortFuseMinors writes "1" to the abort control file for each given FUSE minor device ID.
func AbortFuseMinors(minors []uint32) error {
	var errs []error
	for _, minor := range minors {
		if err := abortFuseConnection(minor); err != nil {
			log.L.Warnf("Failed to abort FUSE connection %d: %v", minor, err)
			errs = append(errs, fmt.Errorf("failed to abort FUSE connection %d: %w", minor, err))
		} else {
			log.L.Infof("Aborted FUSE connection %d", minor)
		}
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}

// AbortMountFuseConnections inspects the given mounts, identifies any FUSE filesystems,
// and writes "1" to their corresponding /sys/fs/fuse/connections/<minor>/abort control file.
func AbortMountFuseConnections(mounts []specs.Mount) error {
	return AbortFuseMinors(FindFuseMountMinors(mounts))
}

// AbortPodFuseConnections searches for any CSI FUSE mounts under the pod's volumes
// directory and aborts them.
func AbortPodFuseConnections(podUID string) error {
	return AbortFuseMinors(FindPodCSIFuseMinors(podUID))
}

func abortFuseConnection(minor uint32) error {
	if _, err := os.Stat(fuseConnectionsDir); err != nil {
		if os.IsNotExist(err) {
			log.L.Warnf("sysfs fusectl directory %q is not mounted on host", fuseConnectionsDir)
			return fmt.Errorf("sysfs fusectl directory %q is not mounted on host", fuseConnectionsDir)
		}
		return fmt.Errorf("failed to stat sysfs fusectl directory %q: %w", fuseConnectionsDir, err)
	}
	abortPath := filepath.Join(fuseConnectionsDir, fmt.Sprintf("%d", minor), "abort")
	f, err := os.OpenFile(abortPath, os.O_WRONLY, 0)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer f.Close()
	if _, err := f.WriteString("1"); err != nil {
		return fmt.Errorf("failed to write to fuse abort file %q: %w", abortPath, err)
	}
	return nil
}

// AbortContainerFuse aborts FUSE connections for the container, first attempting
// via podUID, then falling back to reading the bundle's OCI spec mounts if podUID is empty.
func AbortContainerFuse(podUID, bundleDir, containerID string) error {
	log.L.Debugf("AbortContainerFuse called: containerID=%q, podUID=%q, bundleDir=%q", containerID, podUID, bundleDir)
	if podUID != "" {
		if err := AbortPodFuseConnections(podUID); err != nil {
			log.L.Warningf("Failed to abort pod FUSE connections for container %q (pod %q): %v", containerID, podUID, err)
			return err
		}
		log.L.Infof("AbortPodFuseConnections succeeded for container %q (pod %q)", containerID, podUID)
		return nil
	}
	if bundleDir != "" {
		s, err := ReadSpec(bundleDir)
		if err != nil {
			log.L.Warningf("ReadSpec failed for container %q bundle %q: %v", containerID, bundleDir, err)
			return err
		}
		if err := AbortMountFuseConnections(s.Mounts); err != nil {
			log.L.Warningf("Failed to abort mount FUSE connections for container %q: %v", containerID, err)
			return err
		}
		log.L.Infof("AbortMountFuseConnections succeeded for container %q", containerID)
		return nil
	}
	log.L.Warningf("AbortContainerFuse: neither podUID nor bundleDir provided for container %q", containerID)
	return fmt.Errorf("neither podUID nor bundleDir provided for container %q", containerID)
}

type containerStateJSON struct {
	GoferPid int `json:"goferPid"`
}

func readGoferPIDFromStateFile(path string) int {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	var s containerStateJSON
	if err := json.Unmarshal(data, &s); err != nil {
		log.L.Debugf("FindGoferPID: failed to unmarshal JSON from %s: %v", path, err)
		return 0
	}
	if s.GoferPid > 0 {
		log.L.Debugf("FindGoferPID: found goferPid=%d in %s", s.GoferPid, path)
		return s.GoferPid
	}
	return 0
}

// FindGoferPID locates the container state file in rootDir and returns the gofer PID.
// It checks set paths (OCI bundle spec annotation and root container ID) without globbing.
// Returns 0 if not found or on error.
func FindGoferPID(rootDir, bundleDir, containerID string) int {
	if rootDir == "" || containerID == "" {
		return 0
	}

	// 1. For a subcontainer, resolve the sandbox ID from the OCI spec in the bundle.
	if bundleDir != "" {
		if s, err := ReadSpec(bundleDir); err == nil {
			if sbID, ok := specutils.SandboxID(s); ok && sbID != "" && sbID != containerID {
				path := filepath.Join(rootDir, fmt.Sprintf("%s_sandbox:%s.state", containerID, sbID))
				if pid := readGoferPIDFromStateFile(path); pid > 0 {
					return pid
				}
			}
		}
	}

	// 2. For a root/sandbox container, the sandbox ID matches the container ID.
	path := filepath.Join(rootDir, fmt.Sprintf("%s_sandbox:%s.state", containerID, containerID))
	return readGoferPIDFromStateFile(path)
}

// IsProcessDeadOrZombie checks /proc/<pid>/status to determine if a process is in zombie or dead state.
// Returns true if the process is dead, zombie, or cannot be read.
func IsProcessDeadOrZombie(pid int) bool {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return true
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "State:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				state := fields[1]
				return state == "Z" || state == "X"
			}
			break
		}
	}
	return false
}

// ErrProcessWaitStopped is returned by WaitForProcessExit if stopCh is signaled first.
var ErrProcessWaitStopped = errors.New("process wait stopped by caller")

// WaitForProcessExit blocks until the process with the given pid exits, becomes a zombie,
// or stopCh is closed/receives a value.
func WaitForProcessExit(pid int, stopCh <-chan struct{}) error {
	if IsProcessDeadOrZombie(pid) {
		return nil
	}

	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-stopCh:
			return ErrProcessWaitStopped
		case <-ticker.C:
			if IsProcessDeadOrZombie(pid) {
				return nil
			}
			if err := unix.Kill(pid, 0); errors.Is(err, unix.ESRCH) {
				return nil
			}
		}
	}
}

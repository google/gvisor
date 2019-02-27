// Copyright 2019 The gVisor Authors.
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

package hostmm

import (
	"bufio"
	"fmt"
	"os"
	"path"
	"strings"
)

// currentCgroupDirectory returns the directory for the cgroup for the given
// controller in which the calling process resides.
func currentCgroupDirectory(ctrl string) (string, error) {
	root, err := cgroupRootDirectory(ctrl)
	if err != nil {
		return "", err
	}
	cg, err := currentCgroup(ctrl)
	if err != nil {
		return "", err
	}
	return path.Join(root, cg), nil
}

// cgroupRootDirectory returns the root directory for the cgroup hierarchy in
// which the given cgroup controller is mounted in the calling process' mount
// namespace.
func cgroupRootDirectory(ctrl string) (string, error) {
	const path = "/proc/self/mounts"
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()

	// Per proc(5) -> fstab(5):
	// Each line of /proc/self/mounts describes a mount.
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		// Each line consists of 6 space-separated fields. Find the line for
		// which the third field (fs_vfstype) is cgroup, and the fourth field
		// (fs_mntops, a comma-separated list of mount options) contains
		// ctrl.
		var spec, file, vfstype, mntopts, freq, passno string
		const nrfields = 6
		line := scanner.Text()
		n, err := fmt.Sscan(line, &spec, &file, &vfstype, &mntopts, &freq, &passno)
		if err != nil {
			return "", fmt.Errorf("failed to parse %s: %v", path, err)
		}
		if n != nrfields {
			return "", fmt.Errorf("failed to parse %s: line %q: got %d fields, wanted %d", path, line, n, nrfields)
		}
		if vfstype != "cgroup" {
			continue
		}
		for _, mntopt := range strings.Split(mntopts, ",") {
			if mntopt == ctrl {
				return file, nil
			}
		}
	}
	return "", fmt.Errorf("no cgroup hierarchy mounted for controller %s", ctrl)
}

// currentCgroup returns the cgroup for the given controller in which the
// calling process resides. The returned string is a path that should be
// interpreted as relative to cgroupRootDirectory(ctrl).
func currentCgroup(ctrl string) (string, error) {
	const path = "/proc/self/cgroup"
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()

	// Per proc(5) -> cgroups(7):
	// Each line of /proc/self/cgroups describes a cgroup hierarchy.
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		// Each line consists of 3 colon-separated fields. Find the line for
		// which the second field (controller-list, a comma-separated list of
		// cgroup controllers) contains ctrl.
		line := scanner.Text()
		const nrfields = 3
		fields := strings.Split(line, ":")
		if len(fields) != nrfields {
			return "", fmt.Errorf("failed to parse %s: line %q: got %d fields, wanted %d", path, line, len(fields), nrfields)
		}
		for _, controller := range strings.Split(fields[1], ",") {
			if controller == ctrl {
				return fields[2], nil
			}
		}
	}
	return "", fmt.Errorf("not a member of a cgroup hierarchy for controller %s", ctrl)
}

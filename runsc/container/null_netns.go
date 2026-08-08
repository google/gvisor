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

package container

import (
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"

	"gvisor.dev/gvisor/runsc/config"
	"gvisor.dev/gvisor/runsc/specutils"
)

// nullNetNSPath returns the path of the bind mount pinning the shared "null"
// network namespace.
func nullNetNSPath(conf *config.Config) string {
	return filepath.Join(conf.SharedRoot(), specutils.NullNetNSFilename)
}

// openNullNetNS opens the network namespace bind-mounted at `path`.
func openNullNetNS(path string) (*os.File, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	var st unix.Statfs_t
	if err := unix.Fstatfs(int(f.Fd()), &st); err != nil {
		f.Close()
		return nil, fmt.Errorf("statfs %q: %w", path, err)
	}
	if st.Type != unix.NSFS_MAGIC {
		f.Close()
		return nil, fmt.Errorf("%q is not a namespace mount", path)
	}
	if nsType, err := unix.IoctlRetInt(int(f.Fd()), unix.NS_GET_NSTYPE); err != nil {
		f.Close()
		return nil, fmt.Errorf("getting namespace type of %q: %w", path, err)
	} else if nsType != unix.CLONE_NEWNET {
		f.Close()
		return nil, fmt.Errorf("%q is not a network namespace", path)
	}
	return f, nil
}

// pinNullNetNS pins the network namespace of the process `pid` by
// bind-mounting its `nsfs` file at the null network namespace path, so that
// future gofers can join it. The process must have been started in a new,
// empty network namespace, and must not have exited yet.
//
// Pinning is not serialized across invocations, so concurrent invocations
// may stack bind mounts on top of each other.
// This is OK: all of them pin valid empty network namespaces, and future
// invocations join whichever one is mounted on top.
// (Expected to happen very infrequently in practice, as it requires multiple
// concurrent cold starts using the same shared root directory.)
func pinNullNetNS(conf *config.Config, pid int) error {
	path := nullNetNSPath(conf)
	f, err := os.OpenFile(path, os.O_RDONLY|os.O_CREATE, 0444)
	if err != nil {
		return fmt.Errorf("creating mount point: %w", err)
	}
	_ = f.Close()
	if err := unix.Mount(fmt.Sprintf("/proc/%d/ns/net", pid), path, "", unix.MS_BIND, ""); err != nil {
		_ = os.Remove(path) // Best effort.
		return fmt.Errorf("bind-mounting namespace of PID %d: %w", pid, err)
	}
	return nil
}

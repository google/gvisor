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

package container

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/runsc/config"
	"gvisor.dev/gvisor/runsc/specutils"
)

// filestoreAdopter selects artifacts by mount identity and donates private
// writable clones in the current filestore FD order.
type filestoreAdopter struct {
	dir   string
	names []string
	next  int
}

func (c *Container) newFilestoreAdopter(conf *config.Config) (*filestoreAdopter, error) {
	if !filepath.IsAbs(conf.FilestoreAdoptDir) {
		return nil, fmt.Errorf("filestore snapshot directory must be absolute")
	}
	names, err := c.filestoreSnapshotNames()
	if err != nil {
		return nil, err
	}
	return &filestoreAdopter{dir: conf.FilestoreAdoptDir, names: names}, nil
}

func (a *filestoreAdopter) clone(goferRootfs, filestoreDir string) (*os.File, error) {
	if a.next >= len(a.names) {
		return nil, fmt.Errorf("no snapshot for filestore FD %d", a.next)
	}
	name := filepath.Join(a.dir, a.names[a.next])
	src, err := os.OpenFile(name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer src.Close()
	st, err := src.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("filestore snapshot %q is not a regular file", name)
	}
	// Use the configured medium in the gofer mount namespace (issue/9834).
	// O_TMPFILE leaves no persistent working clone if this process crashes.
	fd, err := unix.Open(filepath.Join(goferRootfs, filestoreDir), unix.O_TMPFILE|unix.O_RDWR|unix.O_CLOEXEC, 0600)
	if err != nil {
		return nil, fmt.Errorf("creating private filestore clone: %w", err)
	}
	dst := os.NewFile(uintptr(fd), "filestore-clone")
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, dst.Fd(), unix.FICLONE, src.Fd()); errno != 0 {
		dst.Close()
		return nil, fmt.Errorf("cloning filestore %q: %w", name, errno)
	}
	a.next++
	return dst, nil
}

// prepareFilestoreSnapshot validates the mount layout and prepares empty clone
// destinations. No sandbox pause or destructive save has started on failure.
func (c *Container) prepareFilestoreSnapshot(snapDir string) (files []*os.File, err error) {
	if !filepath.IsAbs(snapDir) {
		return nil, fmt.Errorf("filestore snapshot directory must be absolute")
	}
	names, err := c.filestoreSnapshotNames()
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(snapDir, 0700); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(snapDir)
	if err != nil {
		return nil, err
	}
	if len(entries) != 0 {
		return nil, fmt.Errorf("filestore snapshot directory %q must be empty", snapDir)
	}
	defer func() {
		if err != nil {
			for _, f := range files {
				f.Close()
				os.Remove(f.Name())
			}
			files = nil
		}
	}()
	for _, name := range names {
		f, e := os.OpenFile(filepath.Join(snapDir, name), os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
		if e != nil {
			return files, e
		}
		files = append(files, f)
	}
	// Probe reflink support without reading or writing live sandbox data.
	probeFD, err := unix.Open(snapDir, unix.O_TMPFILE|unix.O_RDWR|unix.O_CLOEXEC, 0600)
	if err != nil {
		return files, fmt.Errorf("snapshot filesystem requires O_TMPFILE: %w", err)
	}
	defer unix.Close(probeFD)
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, files[0].Fd(), unix.FICLONE, uintptr(probeFD)); errno != 0 {
		return files, fmt.Errorf("snapshot filesystem does not support reflink: %w", errno)
	}

	return files, nil
}

// filestoreSnapshotNames returns artifact names in donated FD order. Names use
// the original OCI destination, not its position in the spec or the host source
// path: restore accepts reordered mounts and relocated sources. The hash encodes
// the destination as a bounded filename; it is not a content integrity check.
// Both capture and restore derive these names in runsc, before the gofer resolves
// symlinks and the sentry sorts mounts.
func (c *Container) filestoreSnapshotNames() ([]string, error) {
	if c.Spec == nil || len(c.GoferMountConfs) == 0 {
		return nil, fmt.Errorf("missing filestore mount layout")
	}
	names := make([]string, 0, len(c.GoferMountConfs))
	seen := make(map[string]bool, len(c.GoferMountConfs))
	add := func(conf specutils.GoferMountConf, name string) error {
		if !conf.IsFilestorePresent() {
			return nil
		}
		if conf.IsSelfBacked() {
			return fmt.Errorf("filestore snapshots require anonymous disk-backed mounts")
		}
		if seen[name] {
			return fmt.Errorf("duplicate filestore snapshot identity %q", name)
		}
		seen[name] = true
		names = append(names, name)
		return nil
	}
	if err := add(c.GoferMountConfs[0], "filestore-root"); err != nil {
		return nil, err
	}
	mountIdx := 1
	for _, m := range c.Spec.Mounts {
		if !specutils.HasMountConfig(m) {
			continue
		}
		if mountIdx >= len(c.GoferMountConfs) {
			return nil, fmt.Errorf("missing configuration for mount %q", m.Destination)
		}
		conf := c.GoferMountConfs[mountIdx]
		mountIdx++
		if !conf.IsFilestorePresent() {
			continue
		}
		if !filepath.IsAbs(m.Destination) {
			return nil, fmt.Errorf("filestore mount destination %q must be absolute", m.Destination)
		}
		name := fmt.Sprintf("filestore-mount-%x", sha256.Sum256([]byte(m.Destination)))
		if err := add(conf, name); err != nil {
			return nil, err
		}
	}
	if mountIdx != len(c.GoferMountConfs) {
		return nil, fmt.Errorf("unused filestore mount configurations")
	}
	if len(names) == 0 {
		return nil, fmt.Errorf("no disk-backed filestores to snapshot")
	}
	return names, nil
}

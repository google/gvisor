// Copyright 2018 The gVisor Authors.
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

package sandboxsetup

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/runsc/config"
)

// PivotRoot changes the root filesystem to the given directory using
// pivot_root(2). The old root is unmounted after the pivot.
func PivotRoot(root string) error {
	if err := os.Chdir(root); err != nil {
		return fmt.Errorf("error changing working directory: %v", err)
	}
	// pivot_root(new_root, put_old) moves the root filesystem (old_root)
	// of the calling process to the directory put_old and makes new_root
	// the new root filesystem of the calling process.
	//
	// pivot_root(".", ".") makes a mount of the working directory the new
	// root filesystem, so it will be moved in "/" and then the old_root
	// will be moved to "/" too. The parent mount of the old_root will be
	// new_root, so after umounting the old_root, we will see only
	// the new_root in "/".
	if err := unix.PivotRoot(".", "."); err != nil {
		return fmt.Errorf("pivot_root failed, make sure that the root mount has a parent: %v", err)
	}

	if err := unix.Unmount(".", unix.MNT_DETACH); err != nil {
		return fmt.Errorf("error umounting the old root file system: %v", err)
	}
	return nil
}

// CopyFile copies a file from src to dst.
func CopyFile(dst, src string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = out.ReadFrom(in)
	return err
}

// ResolveSymlinks walks 'rel' having 'root' as the root directory. If there
// are symlinks, they are evaluated relative to 'root' to ensure the end
// result is the same as if the process was running inside the container.
func ResolveSymlinks(root, rel string) (string, error) {
	return resolveSymlinksImpl(root, root, rel, 255)
}

func resolveSymlinksImpl(root, base, rel string, followCount uint) (string, error) {
	if followCount == 0 {
		return "", fmt.Errorf("too many symlinks to follow, path: %q", filepath.Join(base, rel))
	}

	rel = filepath.Clean(rel)
	for _, name := range strings.Split(rel, string(filepath.Separator)) {
		if name == "" {
			continue
		}
		// Note that Join() resolves things like ".." and returns a
		// clean path.
		path := filepath.Join(base, name)
		if !strings.HasPrefix(path, root) {
			// One cannot '..' their way out of root.
			base = root
			continue
		}
		fi, err := os.Lstat(path)
		if err != nil {
			if !os.IsNotExist(err) {
				return "", err
			}
			// Not found means there is no symlink to check. Just
			// keep walking dirs.
			base = path
			continue
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			link, err := os.Readlink(path)
			if err != nil {
				return "", err
			}
			if filepath.IsAbs(link) {
				base = root
			}
			base, err = resolveSymlinksImpl(root, base, link, followCount-1)
			if err != nil {
				return "", err
			}
			continue
		}
		base = path
	}
	return base, nil
}

// AdjustMountOptions adds filesystem-specific gofer mount options.
func AdjustMountOptions(conf *config.Config, path string, opts []string) ([]string, error) {
	rv := make([]string, len(opts))
	copy(rv, opts)

	statfs := unix.Statfs_t{}
	if err := unix.Statfs(path, &statfs); err != nil {
		return nil, err
	}
	switch statfs.Type {
	case unix.OVERLAYFS_SUPER_MAGIC:
		rv = append(rv, "overlayfs_stale_read")
	case unix.NFS_SUPER_MAGIC, unix.FUSE_SUPER_MAGIC:
		// The gofer client implements remote file handle sharing for
		// performance. However, remote filesystems like NFS and FUSE
		// rely on close(2) syscall for flushing file data to the
		// server. Such handle sharing prevents the application's
		// close(2) syscall from being propagated to the host. Hence
		// disable file handle sharing, so remote files are flushed
		// correctly.
		rv = append(rv, "disable_file_handle_sharing")
	}
	return rv, nil
}

// WaitForFD waits for the other end of a given FD to be closed.
// The FD is closed unconditionally after that.
// This should only be called for actual FDs (i.e. fd >= 0).
func WaitForFD(fd int, fdName string) error {
	log.Debugf("Waiting on %s %d...", fdName, fd)
	f := os.NewFile(uintptr(fd), fdName)
	defer f.Close()
	var b [1]byte
	if n, err := f.Read(b[:]); n != 0 || err != io.EOF {
		return fmt.Errorf("failed to sync on %s: %v: %v", fdName, n, err)
	}
	log.Debugf("Synced on %s %d.", fdName, fd)
	return nil
}

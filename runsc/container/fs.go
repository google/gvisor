// Copyright 2018 Google Inc.
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
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"gvisor.googlesource.com/gvisor/pkg/log"
	"gvisor.googlesource.com/gvisor/runsc/boot"
	"gvisor.googlesource.com/gvisor/runsc/specutils"
)

type mapping struct {
	set bool
	val uint32
}

var optionsMap = map[string]mapping{
	"acl":           {set: true, val: syscall.MS_POSIXACL},
	"async":         {set: false, val: syscall.MS_SYNCHRONOUS},
	"atime":         {set: false, val: syscall.MS_NOATIME},
	"bind":          {set: true, val: syscall.MS_BIND},
	"defaults":      {set: true, val: 0},
	"dev":           {set: false, val: syscall.MS_NODEV},
	"diratime":      {set: false, val: syscall.MS_NODIRATIME},
	"dirsync":       {set: true, val: syscall.MS_DIRSYNC},
	"exec":          {set: false, val: syscall.MS_NOEXEC},
	"iversion":      {set: true, val: syscall.MS_I_VERSION},
	"loud":          {set: false, val: syscall.MS_SILENT},
	"mand":          {set: true, val: syscall.MS_MANDLOCK},
	"noacl":         {set: false, val: syscall.MS_POSIXACL},
	"noatime":       {set: true, val: syscall.MS_NOATIME},
	"nodev":         {set: true, val: syscall.MS_NODEV},
	"nodiratime":    {set: true, val: syscall.MS_NODIRATIME},
	"noexec":        {set: true, val: syscall.MS_NOEXEC},
	"noiversion":    {set: false, val: syscall.MS_I_VERSION},
	"nomand":        {set: false, val: syscall.MS_MANDLOCK},
	"norelatime":    {set: false, val: syscall.MS_RELATIME},
	"nostrictatime": {set: false, val: syscall.MS_STRICTATIME},
	"nosuid":        {set: true, val: syscall.MS_NOSUID},
	"private":       {set: true, val: syscall.MS_PRIVATE},
	"rbind":         {set: true, val: syscall.MS_BIND | syscall.MS_REC},
	"relatime":      {set: true, val: syscall.MS_RELATIME},
	"remount":       {set: true, val: syscall.MS_REMOUNT},
	"ro":            {set: true, val: syscall.MS_RDONLY},
	"rprivate":      {set: true, val: syscall.MS_PRIVATE | syscall.MS_REC},
	"rw":            {set: false, val: syscall.MS_RDONLY},
	"silent":        {set: true, val: syscall.MS_SILENT},
	"strictatime":   {set: true, val: syscall.MS_STRICTATIME},
	"suid":          {set: false, val: syscall.MS_NOSUID},
	"sync":          {set: true, val: syscall.MS_SYNCHRONOUS},
}

// setupFS creates the container directory structure under 'spec.Root.Path'.
// This allows the gofer serving the containers to be chroot under this
// directory to create an extra layer to security in case the gofer gets
// compromised.
func setupFS(spec *specs.Spec, conf *boot.Config, bundleDir string) error {
	for _, m := range spec.Mounts {
		if m.Type != "bind" || !specutils.IsSupportedDevMount(m) {
			continue
		}

		// It's possible that 'm.Destination' follows symlinks inside the
		// container.
		dst, err := resolveSymlinks(spec.Root.Path, m.Destination)
		if err != nil {
			return fmt.Errorf("failed to resolve symlinks: %v", err)
		}

		flags := optionsToFlags(m.Options)
		flags |= syscall.MS_BIND
		log.Infof("Mounting src: %q, dst: %q, flags: %#x", m.Source, dst, flags)
		if err := specutils.Mount(m.Source, dst, m.Type, flags); err != nil {
			return fmt.Errorf("failed to mount %v: %v", m, err)
		}

		// Make the mount a slave, so that for recursive bind mount, umount won't
		// propagate to the source.
		flags = syscall.MS_SLAVE | syscall.MS_REC
		if err := syscall.Mount("", dst, "", uintptr(flags), ""); err != nil {
			return fmt.Errorf("failed to rslave mount dst: %q, flags: %#x, err: %v", dst, flags, err)
		}
	}

	// If root is read only, check if it needs to be remounted as readonly.
	if spec.Root.Readonly {
		isMountPoint, readonly, err := mountInfo(spec.Root.Path)
		if err != nil {
			return err
		}
		if readonly {
			return nil
		}
		if !isMountPoint {
			// Readonly root is not a mount point nor read-only. Can't do much other
			// than just logging a warning. The gofer will prevent files to be open
			// in write mode.
			log.Warningf("Mount where root is located is not read-only and cannot be changed: %q", spec.Root.Path)
			return nil
		}

		// If root is a mount point but not read-only, we can change mount options
		// to make it read-only for extra safety.
		log.Infof("Remounting root as readonly: %q", spec.Root.Path)
		flags := uintptr(syscall.MS_BIND | syscall.MS_REMOUNT | syscall.MS_RDONLY | syscall.MS_REC)
		src := spec.Root.Path
		if err := syscall.Mount(src, src, "bind", flags, ""); err != nil {
			return fmt.Errorf("failed to remount root as read-only with source: %q, target: %q, flags: %#x, err: %v", spec.Root.Path, spec.Root.Path, flags, err)
		}
	}
	return nil
}

// mountInfo returns whether the path is a mount point and whether the mount
// that path belongs to is read-only.
func mountInfo(path string) (bool, bool, error) {
	// Mounts are listed by their real paths.
	realPath, err := filepath.EvalSymlinks(path)
	if err != nil {
		return false, false, err
	}
	f, err := os.Open("/proc/mounts")
	if err != nil {
		return false, false, err
	}
	scanner := bufio.NewScanner(f)

	var mountPoint string
	var readonly bool
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Split(line, " ")
		if len(parts) < 4 {
			return false, false, fmt.Errorf("invalid /proc/mounts line format %q", line)
		}
		mp := parts[1]
		opts := strings.Split(parts[3], ",")

		// Find the closest submount to the path.
		if strings.Contains(realPath, mp) && len(mp) > len(mountPoint) {
			mountPoint = mp
			readonly = specutils.ContainsStr(opts, "ro")
		}
	}
	if err := scanner.Err(); err != nil {
		return false, false, err
	}
	return mountPoint == realPath, readonly, nil
}

// destroyFS unmounts mounts done by runsc under `spec.Root.Path`. This
// recovers the container rootfs into the original state.
func destroyFS(spec *specs.Spec) error {
	for _, m := range spec.Mounts {
		if m.Type != "bind" || !specutils.IsSupportedDevMount(m) {
			continue
		}

		// It's possible that 'm.Destination' follows symlinks inside the
		// container.
		dst, err := resolveSymlinks(spec.Root.Path, m.Destination)
		if err != nil {
			return err
		}

		flags := syscall.MNT_DETACH
		log.Infof("Unmounting dst: %q, flags: %#x", dst, flags)
		// Do not return error if dst is not a mountpoint.
		// Based on http://man7.org/linux/man-pages/man2/umount.2.html
		// For kernel version 2.6+ and MNT_DETACH flag, EINVAL means
		// the dst is not a mount point.
		if err := syscall.Unmount(dst, flags); err != nil &&
			!os.IsNotExist(err) && err != syscall.EINVAL {
			return err
		}
	}
	return nil
}

// resolveSymlinks walks 'rel' having 'root' as the root directory. If there are
// symlinks, they are evaluated relative to 'root' to ensure the end result is
// the same as if the process was running inside the container.
func resolveSymlinks(root, rel string) (string, error) {
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
		// Note that Join() resolves things like ".." and returns a clean path.
		path := filepath.Join(base, name)
		if !strings.HasPrefix(path, root) {
			// One cannot '..' their way out of root.
			path = root
			continue
		}
		fi, err := os.Lstat(path)
		if err != nil {
			if !os.IsNotExist(err) {
				return "", err
			}
			// Not found means there is no symlink to check. Just keep walking dirs.
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

func optionsToFlags(opts []string) uint32 {
	var rv uint32
	for _, opt := range opts {
		if m, ok := optionsMap[opt]; ok {
			if m.set {
				rv |= m.val
			} else {
				rv ^= m.val
			}
		} else {
			log.Warningf("Ignoring mount option %q", opt)
		}
	}
	return rv
}

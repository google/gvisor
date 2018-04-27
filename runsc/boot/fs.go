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

package boot

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	// Include filesystem types that OCI spec might mount.
	_ "gvisor.googlesource.com/gvisor/pkg/sentry/fs/dev"
	_ "gvisor.googlesource.com/gvisor/pkg/sentry/fs/gofer"
	_ "gvisor.googlesource.com/gvisor/pkg/sentry/fs/host"
	_ "gvisor.googlesource.com/gvisor/pkg/sentry/fs/proc"
	_ "gvisor.googlesource.com/gvisor/pkg/sentry/fs/sys"
	_ "gvisor.googlesource.com/gvisor/pkg/sentry/fs/tmpfs"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"gvisor.googlesource.com/gvisor/pkg/abi/linux"
	"gvisor.googlesource.com/gvisor/pkg/log"
	"gvisor.googlesource.com/gvisor/pkg/sentry/context"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs/ramfs"
	"gvisor.googlesource.com/gvisor/pkg/syserror"
)

type fdDispenser struct {
	fds []int
}

func (f *fdDispenser) remove() int {
	rv := f.fds[0]
	f.fds = f.fds[1:]
	return rv
}

func (f *fdDispenser) empty() bool {
	return len(f.fds) == 0
}

// createMountNamespace creates a mount manager containing the root filesystem
// and all mounts.
func createMountNamespace(ctx context.Context, spec *specs.Spec, conf *Config, ioFDs []int) (*fs.MountNamespace, error) {
	fds := &fdDispenser{fds: ioFDs}

	// Create the MountNamespace from the root.
	rootInode, err := createRootMount(ctx, spec, conf, fds)
	if err != nil {
		return nil, fmt.Errorf("failed to create root overlay: %v", err)
	}
	mns, err := fs.NewMountNamespace(ctx, rootInode)
	if err != nil {
		return nil, fmt.Errorf("failed to construct MountNamespace: %v", err)
	}

	// Keep track of whether proc, sys, and tmp were mounted.
	var procMounted, sysMounted, tmpMounted bool

	// Mount all submounts from the spec.
	for _, m := range spec.Mounts {
		// OCI spec uses many different mounts for the things inside of '/dev'. We
		// have a single mount at '/dev' that is always mounted, regardless of
		// whether it was asked for, as the spec says we SHOULD.
		if strings.HasPrefix(m.Destination, "/dev") {
			log.Warningf("ignoring dev mount at %q", m.Destination)
			continue
		}
		switch m.Destination {
		case "/proc":
			procMounted = true
		case "/sys":
			sysMounted = true
		case "/tmp":
			tmpMounted = true
		}

		if err := mountSubmount(ctx, spec, conf, mns, fds, m); err != nil {
			return nil, err
		}
	}

	// Always mount /dev.
	if err := mountSubmount(ctx, spec, conf, mns, nil, specs.Mount{
		Type:        "devtmpfs",
		Destination: "/dev",
	}); err != nil {
		return nil, err
	}

	// Mount proc and sys even if the user did not ask for it, as the spec
	// says we SHOULD.
	if !procMounted {
		if err := mountSubmount(ctx, spec, conf, mns, nil, specs.Mount{
			Type:        "proc",
			Destination: "/proc",
		}); err != nil {
			return nil, err
		}
	}
	if !sysMounted {
		if err := mountSubmount(ctx, spec, conf, mns, nil, specs.Mount{
			Type:        "sysfs",
			Destination: "/sys",
		}); err != nil {
			return nil, err
		}
	}

	// Technically we don't have to mount tmpfs at /tmp, as we could just
	// rely on the host /tmp, but this is a nice optimization, and fixes
	// some apps that call mknod in /tmp.
	if !tmpMounted {
		if err := mountSubmount(ctx, spec, conf, mns, nil, specs.Mount{
			Type:        "tmpfs",
			Destination: "/tmp",
		}); err != nil {
			return nil, err
		}
	}

	if !fds.empty() {
		return nil, fmt.Errorf("not all mount points were consumed, remaining: %v", fds)
	}

	return mns, nil
}

// createRootMount creates the root filesystem.
func createRootMount(ctx context.Context, spec *specs.Spec, conf *Config, fds *fdDispenser) (*fs.Inode, error) {
	// First construct the filesystem from the spec.Root.
	mf := fs.MountSourceFlags{
		ReadOnly: spec.Root.Readonly,
		NoAtime:  true,
	}

	var (
		rootInode *fs.Inode
		err       error
	)
	switch conf.FileAccess {
	case FileAccessProxy:
		fd := fds.remove()
		log.Infof("Mounting root over 9P, ioFD: %d", fd)
		hostFS := mustFindFilesystem("9p")
		rootInode, err = hostFS.Mount(ctx, "root", mf, fmt.Sprintf("trans=fd,rfdno=%d,wfdno=%d,privateunixsocket=true", fd, fd))
		if err != nil {
			return nil, fmt.Errorf("failed to generate root mount point: %v", err)
		}

	case FileAccessDirect:
		hostFS := mustFindFilesystem("whitelistfs")
		rootInode, err = hostFS.Mount(ctx, "root", mf, "root="+spec.Root.Path+",dont_translate_ownership=true")
		if err != nil {
			return nil, fmt.Errorf("failed to generate root mount point: %v", err)
		}

	default:
		return nil, fmt.Errorf("invalid file access type: %v", conf.FileAccess)
	}

	// We need to overlay the root on top of a ramfs with stub directories
	// for submount paths.  "/dev" "/sys" "/proc" and "/tmp" are always
	// mounted even if they are not in the spec.
	submounts := append(subtargets("/", spec.Mounts), "/dev", "/sys", "/proc", "/tmp")
	rootInode, err = addSubmountOverlay(ctx, rootInode, submounts)
	if err != nil {
		return nil, fmt.Errorf("error adding submount overlay: %v", err)
	}

	if conf.Overlay {
		log.Debugf("Adding overlay on top of root mount")
		// Overlay a tmpfs filesystem on top of the root.
		rootInode, err = addOverlay(ctx, conf, rootInode, "root-overlay-upper", mf)
		if err != nil {
			return nil, err
		}
	}

	log.Infof("Mounted %q to \"/\" type root", spec.Root.Path)
	return rootInode, nil
}

func addOverlay(ctx context.Context, conf *Config, lower *fs.Inode, name string, lowerFlags fs.MountSourceFlags) (*fs.Inode, error) {
	// Upper layer uses the same flags as lower, but it must be read-write.
	lowerFlags.ReadOnly = false

	tmpFS := mustFindFilesystem("tmpfs")
	upper, err := tmpFS.Mount(ctx, name+"-upper", lowerFlags, "")
	if err != nil {
		return nil, fmt.Errorf("failed to create tmpfs overlay: %v", err)
	}
	return fs.NewOverlayRoot(ctx, upper, lower, lowerFlags)
}

func mountSubmount(ctx context.Context, spec *specs.Spec, conf *Config, mns *fs.MountNamespace, fds *fdDispenser, m specs.Mount) error {
	// Map mount type to filesystem name, and parse out the options that we are
	// capable of dealing with.
	var data []string
	var fsName string
	var useOverlay bool
	switch m.Type {
	case "proc", "sysfs", "devtmpfs":
		fsName = m.Type
	case "none":
		fsName = "sysfs"
	case "tmpfs":
		fsName = m.Type

		// tmpfs has some extra supported options that we must pass through.
		var err error
		data, err = parseAndFilterOptions(m.Options, "mode", "uid", "gid")
		if err != nil {
			return err
		}
	case "bind":
		switch conf.FileAccess {
		case FileAccessProxy:
			fd := fds.remove()
			fsName = "9p"
			data = []string{"trans=fd", fmt.Sprintf("rfdno=%d", fd), fmt.Sprintf("wfdno=%d", fd), "privateunixsocket=true"}
		case FileAccessDirect:
			fsName = "whitelistfs"
			data = []string{"root=" + m.Source, "dont_translate_ownership=true"}
		default:
			return fmt.Errorf("invalid file access type: %v", conf.FileAccess)
		}

		fi, err := os.Stat(m.Source)
		if err != nil {
			return err
		}
		// Add overlay to all writable mounts, except when mapping an individual file.
		useOverlay = conf.Overlay && !mountFlags(m.Options).ReadOnly && fi.Mode().IsDir()
	default:
		// TODO: Support all the mount types and make this a
		// fatal error.  Most applications will "just work" without
		// them, so this is a warning for now.
		// we do not support.
		log.Warningf("ignoring unknown filesystem type %q", m.Type)
		return nil
	}

	// All filesystem names should have been mapped to something we know.
	filesystem := mustFindFilesystem(fsName)

	mf := mountFlags(m.Options)
	if useOverlay {
		// All writes go to upper, be paranoid and make lower readonly.
		mf.ReadOnly = true
	}
	mf.NoAtime = true

	inode, err := filesystem.Mount(ctx, m.Type, mf, strings.Join(data, ","))
	if err != nil {
		return fmt.Errorf("failed to create mount with source %q: %v", m.Source, err)
	}

	// If there are submounts, we need to overlay the mount on top of a
	// ramfs with stub directories for submount paths.
	//
	// We do not do this for /dev, since there will usually be submounts in
	// the spec, but our devfs implementation contains all the necessary
	// directories and files (well, most of them anyways).
	if m.Destination != "/dev" {
		submounts := subtargets(m.Destination, spec.Mounts)
		if len(submounts) > 0 {
			log.Infof("Adding submount overlay over %q", m.Destination)
			inode, err = addSubmountOverlay(ctx, inode, submounts)
			if err != nil {
				return fmt.Errorf("error adding submount overlay: %v", err)
			}
		}
	}

	if useOverlay {
		log.Debugf("Adding overlay on top of mount %q", m.Destination)
		if inode, err = addOverlay(ctx, conf, inode, m.Type, mf); err != nil {
			return err
		}
	}

	root := mns.Root()
	defer root.DecRef()
	dirent, err := mns.FindInode(ctx, root, nil, m.Destination, linux.MaxSymlinkTraversals)
	if err != nil {
		return fmt.Errorf("failed to find mount destination %q: %v", m.Destination, err)
	}
	defer dirent.DecRef()
	if err := mns.Mount(ctx, dirent, inode); err != nil {
		return fmt.Errorf("failed to mount at destination %q: %v", m.Destination, err)
	}

	log.Infof("Mounted %q to %q type %s", m.Source, m.Destination, m.Type)
	return nil
}

func mkdirAll(ctx context.Context, mns *fs.MountNamespace, path string) error {
	root := mns.Root()
	defer root.DecRef()

	// Starting at the root, walk the path.
	parent := root
	ps := strings.Split(filepath.Clean(path), string(filepath.Separator))
	for i := 0; i < len(ps); i++ {
		if ps[i] == "" {
			// This will be case for the first and last element, if the path
			// begins or ends with '/'. Note that we always treat the path as
			// absolute, regardless of what the first character contains.
			continue
		}
		d, err := mns.FindInode(ctx, root, parent, ps[i], fs.DefaultTraversalLimit)
		if err == syserror.ENOENT {
			// If we encounter a path that does not exist, then
			// create it.
			if err := parent.CreateDirectory(ctx, root, ps[i], fs.FilePermsFromMode(0755)); err != nil {
				return fmt.Errorf("failed to create directory %q: %v", ps[i], err)
			}
			if d, err = parent.Walk(ctx, root, ps[i]); err != nil {
				return fmt.Errorf("walk to %q failed: %v", ps[i], err)
			}
		} else if err != nil {
			return fmt.Errorf("failed to find inode %q: %v", ps[i], err)
		}
		parent = d
	}
	return nil
}

// parseAndFilterOptions parses a MountOptions slice and filters by the allowed
// keys.
func parseAndFilterOptions(opts []string, allowedKeys ...string) ([]string, error) {
	var out []string
	for _, o := range opts {
		kv := strings.Split(o, "=")
		switch len(kv) {
		case 1:
			if contains(allowedKeys, o) {
				out = append(out, o)
				continue
			}
			log.Warningf("ignoring unsupported key %q", kv)
		case 2:
			if contains(allowedKeys, kv[0]) {
				out = append(out, o)
				continue
			}
			log.Warningf("ignoring unsupported key %q", kv[0])
		default:
			return nil, fmt.Errorf("invalid option %q", o)
		}
	}
	return out, nil
}

func destinations(mounts []specs.Mount, extra ...string) []string {
	var ds []string
	for _, m := range mounts {
		ds = append(ds, m.Destination)
	}
	return append(ds, extra...)
}

func mountFlags(opts []string) fs.MountSourceFlags {
	mf := fs.MountSourceFlags{}
	for _, o := range opts {
		switch o {
		case "ro":
			mf.ReadOnly = true
		case "noatime":
			mf.NoAtime = true
		default:
			log.Warningf("ignorning unknown mount option %q", o)
		}
	}
	return mf
}

func contains(strs []string, str string) bool {
	for _, s := range strs {
		if s == str {
			return true
		}
	}
	return false
}

func mustFindFilesystem(name string) fs.Filesystem {
	fs, ok := fs.FindFilesystem(name)
	if !ok {
		panic(fmt.Sprintf("could not find filesystem %q", name))
	}
	return fs
}

// addSubmountOverlay overlays the inode over a ramfs tree containing the given
// paths.
func addSubmountOverlay(ctx context.Context, inode *fs.Inode, submounts []string) (*fs.Inode, error) {
	// There is no real filesystem backing this ramfs tree, so we pass in
	// "nil" here.
	mountTree, err := ramfs.MakeDirectoryTree(ctx, fs.NewNonCachingMountSource(nil, fs.MountSourceFlags{}), submounts)
	if err != nil {
		return nil, fmt.Errorf("error creating mount tree: %v", err)
	}
	overlayInode, err := fs.NewOverlayRoot(ctx, inode, mountTree, fs.MountSourceFlags{})
	if err != nil {
		return nil, fmt.Errorf("failed to make mount overlay: %v", err)
	}
	return overlayInode, err
}

// subtargets takes a set of Mounts and returns only the targets that are
// children of the given root. The returned paths are relative to the root.
func subtargets(root string, mnts []specs.Mount) []string {
	r := filepath.Clean(root)
	var targets []string
	for _, mnt := range mnts {
		t := filepath.Clean(mnt.Destination)
		if strings.HasPrefix(t, r) {
			// Make the mnt path relative to the root path.  If the
			// result is empty, then mnt IS the root mount, not a
			// submount.  We don't want to include those.
			if t := strings.TrimPrefix(t, r); t != "" {
				targets = append(targets, t)
			}
		}
	}
	return targets
}

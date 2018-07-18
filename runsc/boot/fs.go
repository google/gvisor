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
	"path/filepath"
	"strings"

	// Include filesystem types that OCI spec might mount.
	_ "gvisor.googlesource.com/gvisor/pkg/sentry/fs/dev"
	_ "gvisor.googlesource.com/gvisor/pkg/sentry/fs/gofer"
	_ "gvisor.googlesource.com/gvisor/pkg/sentry/fs/host"
	_ "gvisor.googlesource.com/gvisor/pkg/sentry/fs/proc"
	_ "gvisor.googlesource.com/gvisor/pkg/sentry/fs/sys"
	_ "gvisor.googlesource.com/gvisor/pkg/sentry/fs/tmpfs"
	_ "gvisor.googlesource.com/gvisor/pkg/sentry/fs/tty"
	"gvisor.googlesource.com/gvisor/pkg/sentry/kernel"
	"gvisor.googlesource.com/gvisor/pkg/sentry/kernel/auth"
	"gvisor.googlesource.com/gvisor/pkg/sentry/limits"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"gvisor.googlesource.com/gvisor/pkg/abi/linux"
	"gvisor.googlesource.com/gvisor/pkg/log"
	"gvisor.googlesource.com/gvisor/pkg/sentry/context"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs/ramfs"
	"gvisor.googlesource.com/gvisor/pkg/syserror"
	"gvisor.googlesource.com/gvisor/runsc/specutils"
)

const (
	// Filesystem name for 9p gofer mounts.
	rootFsName = "9p"

	// Device name for root mount.
	rootDevice = "9pfs-/"
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

// createMountNamespace creates a mount namespace containing the root filesystem
// and all mounts. 'rootCtx' is used to walk directories to find mount points.
func createMountNamespace(userCtx context.Context, rootCtx context.Context, spec *specs.Spec, conf *Config, ioFDs []int) (*fs.MountNamespace, error) {
	fds := &fdDispenser{fds: ioFDs}
	rootInode, err := createRootMount(rootCtx, spec, conf, fds)
	if err != nil {
		return nil, fmt.Errorf("failed to create root mount: %v", err)
	}
	mns, err := fs.NewMountNamespace(userCtx, rootInode)
	if err != nil {
		return nil, fmt.Errorf("failed to create root mount namespace: %v", err)
	}
	mounts := compileMounts(spec)
	if err := setMounts(rootCtx, conf, mns, fds, mounts); err != nil {
		return nil, fmt.Errorf("failed to configure mounts: %v", err)
	}
	if !fds.empty() {
		return nil, fmt.Errorf("not all mount points were consumed, remaining: %v", fds)
	}
	return mns, nil
}

// compileMounts returns the supported mounts from the mount spec, adding any
// mandatory mounts that are required by the OCI specification.
func compileMounts(spec *specs.Spec) []specs.Mount {
	// Keep track of whether proc, sys, and tmp were mounted.
	var procMounted, sysMounted, tmpMounted bool
	var mounts []specs.Mount

	// Always mount /dev.
	mounts = append(mounts, specs.Mount{
		Type:        "devtmpfs",
		Destination: "/dev",
	})

	mounts = append(mounts, specs.Mount{
		Type:        "devpts",
		Destination: "/dev/pts",
	})

	// Mount all submounts from the spec.
	for _, m := range spec.Mounts {
		if !specutils.IsSupportedDevMount(m) {
			log.Warningf("ignoring dev mount at %q", m.Destination)
			continue
		}
		mounts = append(mounts, m)
		switch filepath.Clean(m.Destination) {
		case "/proc":
			procMounted = true
		case "/sys":
			sysMounted = true
		case "/tmp":
			tmpMounted = true
		}
	}

	// Mount proc and sys even if the user did not ask for it, as the spec
	// says we SHOULD.
	var mandatoryMounts []specs.Mount
	if !procMounted {
		mandatoryMounts = append(mandatoryMounts, specs.Mount{
			Type:        "proc",
			Destination: "/proc",
		})
	}
	if !sysMounted {
		mandatoryMounts = append(mandatoryMounts, specs.Mount{
			Type:        "sysfs",
			Destination: "/sys",
		})
	}

	// Technically we don't have to mount tmpfs at /tmp, as we could just
	// rely on the host /tmp, but this is a nice optimization, and fixes
	// some apps that call mknod in /tmp.
	if !tmpMounted {
		// TODO: If the host /tmp (or a mount at /tmp) has
		// files in it, we should overlay our tmpfs implementation over
		// that. Until then, the /tmp mount will always appear empty at
		// container creation.
		mandatoryMounts = append(mandatoryMounts, specs.Mount{
			Type:        "tmpfs",
			Destination: "/tmp",
		})
	}

	// The mandatory mounts should be ordered right after the root, in case
	// there are submounts of these mandatory mounts already in the spec.
	mounts = append(mounts[:0], append(mandatoryMounts, mounts[0:]...)...)

	return mounts
}

// setMounts iterates over mounts and mounts them in the specified
// mount namespace.
func setMounts(ctx context.Context, conf *Config, mns *fs.MountNamespace, fds *fdDispenser, mounts []specs.Mount) error {

	// Mount all submounts from mounts.
	for _, m := range mounts {
		if err := mountSubmount(ctx, conf, mns, fds, m, mounts); err != nil {
			return err
		}
	}
	return nil
}

// createRootMount creates the root filesystem.
func createRootMount(ctx context.Context, spec *specs.Spec, conf *Config, fds *fdDispenser) (*fs.Inode, error) {
	// First construct the filesystem from the spec.Root.
	mf := fs.MountSourceFlags{ReadOnly: spec.Root.Readonly}

	var (
		rootInode *fs.Inode
		err       error
	)

	switch conf.FileAccess {
	case FileAccessProxy:
		fd := fds.remove()
		log.Infof("Mounting root over 9P, ioFD: %d", fd)
		hostFS := mustFindFilesystem("9p")
		rootInode, err = hostFS.Mount(ctx, rootDevice, mf, fmt.Sprintf("trans=fd,rfdno=%d,wfdno=%d,privateunixsocket=true", fd, fd))
		if err != nil {
			return nil, fmt.Errorf("failed to generate root mount point: %v", err)
		}

	case FileAccessDirect:
		hostFS := mustFindFilesystem("whitelistfs")
		rootInode, err = hostFS.Mount(ctx, rootDevice, mf, "root="+spec.Root.Path+",dont_translate_ownership=true")
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

	if conf.Overlay && !spec.Root.Readonly {
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
	if !fs.IsDir(lower.StableAttr) {
		// Create overlay on top of mount file, e.g. /etc/hostname.
		msrc := fs.NewCachingMountSource(tmpFS, lowerFlags)
		return fs.NewOverlayRootFile(ctx, msrc, lower, lowerFlags)
	}

	// Create overlay on top of mount dir.
	upper, err := tmpFS.Mount(ctx, name+"-upper", lowerFlags, "")
	if err != nil {
		return nil, fmt.Errorf("failed to create tmpfs overlay: %v", err)
	}
	return fs.NewOverlayRoot(ctx, upper, lower, lowerFlags)
}

// getMountNameAndOptions retrieves the fsName, data, and useOverlay values
// used for mounts.
func getMountNameAndOptions(conf *Config, m specs.Mount, fds *fdDispenser) (string, []string, bool, error) {
	var fsName string
	var data []string
	var useOverlay bool
	var err error
	switch m.Type {
	case "devpts", "devtmpfs", "proc", "sysfs":
		fsName = m.Type
	case "none":
		fsName = "sysfs"
	case "tmpfs":
		fsName = m.Type

		// tmpfs has some extra supported options that we must pass through.
		data, err = parseAndFilterOptions(m.Options, "mode", "uid", "gid")

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
			err = fmt.Errorf("invalid file access type: %v", conf.FileAccess)
		}
		// If configured, add overlay to all writable mounts.
		useOverlay = conf.Overlay && !mountFlags(m.Options).ReadOnly

	default:
		// TODO: Support all the mount types and make this a
		// fatal error.  Most applications will "just work" without
		// them, so this is a warning for now.
		// we do not support.
		log.Warningf("ignoring unknown filesystem type %q", m.Type)
	}
	return fsName, data, useOverlay, err
}

func mountSubmount(ctx context.Context, conf *Config, mns *fs.MountNamespace, fds *fdDispenser, m specs.Mount, mounts []specs.Mount) error {
	// Map mount type to filesystem name, and parse out the options that we are
	// capable of dealing with.
	fsName, data, useOverlay, err := getMountNameAndOptions(conf, m, fds)

	// Return the error or nil that corresponds to the default case in getMountNameAndOptions.
	if err != nil {
		return err
	}
	if fsName == "" {
		return nil
	}

	// All filesystem names should have been mapped to something we know.
	filesystem := mustFindFilesystem(fsName)

	mf := mountFlags(m.Options)
	if useOverlay {
		// All writes go to upper, be paranoid and make lower readonly.
		mf.ReadOnly = true
	}

	inode, err := filesystem.Mount(ctx, mountDevice(m), mf, strings.Join(data, ","))
	if err != nil {
		return fmt.Errorf("failed to create mount with source %q: %v", m.Source, err)
	}

	// If there are submounts, we need to overlay the mount on top of a
	// ramfs with stub directories for submount paths.
	submounts := subtargets(m.Destination, mounts)
	if len(submounts) > 0 {
		log.Infof("Adding submount overlay over %q", m.Destination)
		inode, err = addSubmountOverlay(ctx, inode, submounts)
		if err != nil {
			return fmt.Errorf("error adding submount overlay: %v", err)
		}
	}

	if useOverlay {
		log.Debugf("Adding overlay on top of mount %q", m.Destination)
		inode, err = addOverlay(ctx, conf, inode, m.Type, mf)
		if err != nil {
			return err
		}
	}

	// Create destination in case it doesn't exist. This is required, in addition
	// to 'addSubmountOverlay', in case there are symlinks to create directories
	// in the right location, e.g.
	//   mount: /var/run/secrets, may be created in '/run/secrets' if
	//   '/var/run' => '/var'.
	if err := mkdirAll(ctx, mns, m.Destination); err != nil {
		return err
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

// mountDevice returns a device string based on the fs type and target
// of the mount.
func mountDevice(m specs.Mount) string {
	if m.Type == "bind" {
		// Make a device string that includes the target, which is consistent across
		// S/R and uniquely identifies the connection.
		return "9pfs-" + m.Destination
	}
	// All other fs types use device "none".
	return "none"
}

// addRestoreMount adds a mount to the MountSources map used for restoring a
// checkpointed container.
func addRestoreMount(conf *Config, renv *fs.RestoreEnvironment, m specs.Mount, fds *fdDispenser) error {
	fsName, data, _, err := getMountNameAndOptions(conf, m, fds)
	dataString := strings.Join(data, ",")

	// Return the error or nil that corresponds to the default case in getMountNameAndOptions.
	if err != nil {
		return err
	}
	// TODO: Fix this when we support all the mount types and
	// make this a fatal error.
	if fsName == "" {
		return nil
	}

	newMount := fs.MountArgs{
		Dev:   mountDevice(m),
		Flags: mountFlags(m.Options),
		Data:  dataString,
	}
	renv.MountSources[fsName] = append(renv.MountSources[fsName], newMount)
	log.Infof("Added mount at %q: %+v", fsName, newMount)
	return nil
}

// createRestoreEnvironment builds a fs.RestoreEnvironment called renv by adding the mounts
// to the environment.
func createRestoreEnvironment(spec *specs.Spec, conf *Config, fds *fdDispenser) (*fs.RestoreEnvironment, error) {
	if conf.FileAccess == FileAccessDirect {
		return nil, fmt.Errorf("host filesystem with whitelist not supported with S/R")
	}
	renv := &fs.RestoreEnvironment{
		MountSources: make(map[string][]fs.MountArgs),
	}

	mounts := compileMounts(spec)

	// Add root mount.
	fd := fds.remove()
	dataString := strings.Join([]string{"trans=fd", fmt.Sprintf("rfdno=%d", fd), fmt.Sprintf("wfdno=%d", fd), "privateunixsocket=true"}, ",")
	mf := fs.MountSourceFlags{}
	if spec.Root.Readonly {
		mf.ReadOnly = true
	}

	rootMount := fs.MountArgs{
		Dev:   rootDevice,
		Flags: mf,
		Data:  dataString,
	}
	renv.MountSources[rootFsName] = append(renv.MountSources[rootFsName], rootMount)

	// Add submounts
	for _, m := range mounts {
		if err := addRestoreMount(conf, renv, m, fds); err != nil {
			return nil, err
		}
	}
	return renv, nil
}

func mountFlags(opts []string) fs.MountSourceFlags {
	mf := fs.MountSourceFlags{}
	for _, o := range opts {
		switch o {
		case "rw":
			mf.ReadOnly = false
		case "ro":
			mf.ReadOnly = true
		case "noatime":
			mf.NoAtime = true
		default:
			log.Warningf("ignoring unknown mount option %q", o)
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
	if len(r) > 0 && r[len(r)-1] != '/' {
		r += "/"
	}
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

// setFileSystemForProcess is used to set up the file system and amend the procArgs accordingly.
// procArgs are passed by reference and the FDMap field is modified.
func setFileSystemForProcess(procArgs *kernel.CreateProcessArgs, spec *specs.Spec, conf *Config, ioFDs []int, console bool, creds *auth.Credentials, ls *limits.LimitSet, k *kernel.Kernel) error {
	ctx := procArgs.NewContext(k)

	// Create the FD map, which will set stdin, stdout, and stderr.  If
	// console is true, then ioctl calls will be passed through to the host
	// fd.
	fdm, err := createFDMap(ctx, k, ls, console)
	if err != nil {
		return fmt.Errorf("error importing fds: %v", err)
	}

	// CreateProcess takes a reference on FDMap if successful. We
	// won't need ours either way.
	procArgs.FDMap = fdm

	// If this is the root container, we also need to setup the root mount
	// namespace.
	if k.RootMountNamespace() == nil {
		// Use root user to configure mounts. The current user might not have
		// permission to do so.
		rootProcArgs := kernel.CreateProcessArgs{
			WorkingDirectory:     "/",
			Credentials:          auth.NewRootCredentials(creds.UserNamespace),
			Umask:                0022,
			MaxSymlinkTraversals: linux.MaxSymlinkTraversals,
		}
		rootCtx := rootProcArgs.NewContext(k)

		// Create the virtual filesystem.
		mns, err := createMountNamespace(ctx, rootCtx, spec, conf, ioFDs)
		if err != nil {
			return fmt.Errorf("error creating mounts: %v", err)
		}

		k.SetRootMountNamespace(mns)
	}

	return nil
}

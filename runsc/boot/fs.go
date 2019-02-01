// Copyright 2018 Google LLC
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
	"path"
	"path/filepath"
	"strconv"
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

	// ChildContainersDir is the directory where child container root
	// filesystems are mounted.
	ChildContainersDir = "/__runsc_containers__"

	// Filesystems that runsc supports.
	bind     = "bind"
	devpts   = "devpts"
	devtmpfs = "devtmpfs"
	proc     = "proc"
	sysfs    = "sysfs"
	tmpfs    = "tmpfs"
	nonefs   = "none"
)

type fdDispenser struct {
	fds []int
}

func (f *fdDispenser) remove() int {
	if f.empty() {
		panic("fdDispenser out of fds")
	}
	rv := f.fds[0]
	f.fds = f.fds[1:]
	return rv
}

func (f *fdDispenser) empty() bool {
	return len(f.fds) == 0
}

// setupRootContainerFS creates a mount namespace containing the root filesystem
// and all mounts. 'rootCtx' is used to walk directories to find mount points.
// 'setMountNS' is called after namespace is created. It must set the mount NS
// to 'rootCtx'.
func setupRootContainerFS(userCtx context.Context, rootCtx context.Context, spec *specs.Spec, conf *Config, goferFDs []int, setMountNS func(*fs.MountNamespace)) error {
	mounts := compileMounts(spec)

	// Create a tmpfs mount where we create and mount a root filesystem for
	// each child container.
	mounts = append(mounts, specs.Mount{
		Type:        tmpfs,
		Destination: ChildContainersDir,
	})

	fds := &fdDispenser{fds: goferFDs}
	rootInode, err := createRootMount(rootCtx, spec, conf, fds, mounts)
	if err != nil {
		return fmt.Errorf("creating root mount: %v", err)
	}
	mns, err := fs.NewMountNamespace(userCtx, rootInode)
	if err != nil {
		return fmt.Errorf("creating root mount namespace: %v", err)
	}
	setMountNS(mns)

	root := mns.Root()
	defer root.DecRef()
	return mountSubmounts(rootCtx, conf, mns, root, mounts, fds)
}

// compileMounts returns the supported mounts from the mount spec, adding any
// mandatory mounts that are required by the OCI specification.
func compileMounts(spec *specs.Spec) []specs.Mount {
	// Keep track of whether proc and sys were mounted.
	var procMounted, sysMounted bool
	var mounts []specs.Mount

	// Always mount /dev.
	mounts = append(mounts, specs.Mount{
		Type:        devtmpfs,
		Destination: "/dev",
	})

	mounts = append(mounts, specs.Mount{
		Type:        devpts,
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
		}
	}

	// Mount proc and sys even if the user did not ask for it, as the spec
	// says we SHOULD.
	var mandatoryMounts []specs.Mount
	if !procMounted {
		mandatoryMounts = append(mandatoryMounts, specs.Mount{
			Type:        proc,
			Destination: "/proc",
		})
	}
	if !sysMounted {
		mandatoryMounts = append(mandatoryMounts, specs.Mount{
			Type:        sysfs,
			Destination: "/sys",
		})
	}

	// The mandatory mounts should be ordered right after the root, in case
	// there are submounts of these mandatory mounts already in the spec.
	mounts = append(mounts[:0], append(mandatoryMounts, mounts[0:]...)...)

	return mounts
}

// createRootMount creates the root filesystem.
func createRootMount(ctx context.Context, spec *specs.Spec, conf *Config, fds *fdDispenser, mounts []specs.Mount) (*fs.Inode, error) {
	// First construct the filesystem from the spec.Root.
	mf := fs.MountSourceFlags{ReadOnly: spec.Root.Readonly}

	var (
		rootInode *fs.Inode
		err       error
	)

	fd := fds.remove()
	log.Infof("Mounting root over 9P, ioFD: %d", fd)
	p9FS := mustFindFilesystem("9p")
	opts := p9MountOptions(fd, conf.FileAccess)
	rootInode, err = p9FS.Mount(ctx, rootDevice, mf, strings.Join(opts, ","))
	if err != nil {
		return nil, fmt.Errorf("creating root mount point: %v", err)
	}

	// We need to overlay the root on top of a ramfs with stub directories
	// for submount paths.  "/dev" "/sys" "/proc" and "/tmp" are always
	// mounted even if they are not in the spec.
	submounts := append(subtargets("/", mounts), "/dev", "/sys", "/proc", "/tmp")
	rootInode, err = addSubmountOverlay(ctx, rootInode, submounts)
	if err != nil {
		return nil, fmt.Errorf("adding submount overlay: %v", err)
	}

	if conf.Overlay && !spec.Root.Readonly {
		log.Debugf("Adding overlay on top of root mount")
		// Overlay a tmpfs filesystem on top of the root.
		rootInode, err = addOverlay(ctx, conf, rootInode, "root-overlay-upper", mf)
		if err != nil {
			return nil, err
		}
	}

	log.Infof("Mounted %q to %q type root", spec.Root.Path, "/")
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
		return nil, fmt.Errorf("creating tmpfs overlay: %v", err)
	}
	return fs.NewOverlayRoot(ctx, upper, lower, lowerFlags)
}

// getMountNameAndOptions retrieves the fsName, opts, and useOverlay values
// used for mounts.
func getMountNameAndOptions(conf *Config, m specs.Mount, fds *fdDispenser) (string, []string, bool, error) {
	var (
		fsName     string
		opts       []string
		useOverlay bool
		err        error
	)

	switch m.Type {
	case devpts, devtmpfs, proc, sysfs:
		fsName = m.Type
	case nonefs:
		fsName = sysfs
	case tmpfs:
		fsName = m.Type

		// tmpfs has some extra supported options that we must pass through.
		opts, err = parseAndFilterOptions(m.Options, "mode", "uid", "gid")

	case bind:
		fd := fds.remove()
		fsName = "9p"
		// Non-root bind mounts are always shared.
		opts = p9MountOptions(fd, FileAccessShared)
		// If configured, add overlay to all writable mounts.
		useOverlay = conf.Overlay && !mountFlags(m.Options).ReadOnly

	default:
		// TODO: Support all the mount types and make this a
		// fatal error.  Most applications will "just work" without
		// them, so this is a warning for now.
		// we do not support.
		log.Warningf("ignoring unknown filesystem type %q", m.Type)
	}
	return fsName, opts, useOverlay, err
}

func mountSubmounts(ctx context.Context, conf *Config, mns *fs.MountNamespace, root *fs.Dirent, mounts []specs.Mount, fds *fdDispenser) error {
	for _, m := range mounts {
		if err := mountSubmount(ctx, conf, mns, root, fds, m, mounts); err != nil {
			return fmt.Errorf("mount submount %q: %v", m.Destination, err)
		}
	}

	if err := mountTmp(ctx, conf, mns, root, fds, mounts); err != nil {
		return fmt.Errorf("mount submount %q: %v", "tmp", err)
	}

	if !fds.empty() {
		return fmt.Errorf("not all mount points were consumed, remaining: %v", fds)
	}
	return nil
}

// mountSubmount mounts volumes inside the container's root. Because mounts may
// be readonly, a lower ramfs overlay is added to create the mount point dir.
// Another overlay is added with tmpfs on top if Config.Overlay is true.
// 'm.Destination' must be an absolute path with '..' and symlinks resolved.
func mountSubmount(ctx context.Context, conf *Config, mns *fs.MountNamespace, root *fs.Dirent, fds *fdDispenser, m specs.Mount, mounts []specs.Mount) error {
	// Map mount type to filesystem name, and parse out the options that we are
	// capable of dealing with.
	fsName, opts, useOverlay, err := getMountNameAndOptions(conf, m, fds)

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

	inode, err := filesystem.Mount(ctx, mountDevice(m), mf, strings.Join(opts, ","))
	if err != nil {
		return fmt.Errorf("creating mount with source %q: %v", m.Source, err)
	}

	// If there are submounts, we need to overlay the mount on top of a
	// ramfs with stub directories for submount paths.
	submounts := subtargets(m.Destination, mounts)
	if len(submounts) > 0 {
		log.Infof("Adding submount overlay over %q", m.Destination)
		inode, err = addSubmountOverlay(ctx, inode, submounts)
		if err != nil {
			return fmt.Errorf("adding submount overlay: %v", err)
		}
	}

	if useOverlay {
		log.Debugf("Adding overlay on top of mount %q", m.Destination)
		inode, err = addOverlay(ctx, conf, inode, m.Type, mf)
		if err != nil {
			return err
		}
	}

	maxTraversals := uint(0)
	dirent, err := mns.FindInode(ctx, root, root, m.Destination, &maxTraversals)
	if err != nil {
		return fmt.Errorf("can't find mount destination %q: %v", m.Destination, err)
	}
	defer dirent.DecRef()
	if err := mns.Mount(ctx, dirent, inode); err != nil {
		return fmt.Errorf("mount %q error: %v", m.Destination, err)
	}

	log.Infof("Mounted %q to %q type %s", m.Source, m.Destination, m.Type)
	return nil
}

// p9MountOptions creates a slice of options for a p9 mount.
func p9MountOptions(fd int, fa FileAccessType) []string {
	opts := []string{
		"trans=fd",
		"rfdno=" + strconv.Itoa(fd),
		"wfdno=" + strconv.Itoa(fd),
		"privateunixsocket=true",
	}
	if fa == FileAccessShared {
		opts = append(opts, "cache=remote_revalidating")
	}
	return opts
}

// parseAndFilterOptions parses a MountOptions slice and filters by the allowed
// keys.
func parseAndFilterOptions(opts []string, allowedKeys ...string) ([]string, error) {
	var out []string
	for _, o := range opts {
		kv := strings.Split(o, "=")
		switch len(kv) {
		case 1:
			if specutils.ContainsStr(allowedKeys, o) {
				out = append(out, o)
				continue
			}
			log.Warningf("ignoring unsupported key %q", kv)
		case 2:
			if specutils.ContainsStr(allowedKeys, kv[0]) {
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

// mountDevice returns a device string based on the fs type and target
// of the mount.
func mountDevice(m specs.Mount) string {
	if m.Type == bind {
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
	fsName, opts, _, err := getMountNameAndOptions(conf, m, fds)

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
		Data:  strings.Join(opts, ","),
	}
	renv.MountSources[fsName] = append(renv.MountSources[fsName], newMount)
	log.Infof("Added mount at %q: %+v", fsName, newMount)
	return nil
}

// createRestoreEnvironment builds a fs.RestoreEnvironment called renv by adding the mounts
// to the environment.
func createRestoreEnvironment(spec *specs.Spec, conf *Config, fds *fdDispenser) (*fs.RestoreEnvironment, error) {
	renv := &fs.RestoreEnvironment{
		MountSources: make(map[string][]fs.MountArgs),
	}

	// Add root mount.
	fd := fds.remove()
	opts := p9MountOptions(fd, conf.FileAccess)

	mf := fs.MountSourceFlags{}
	if spec.Root.Readonly {
		mf.ReadOnly = true
	}

	rootMount := fs.MountArgs{
		Dev:   rootDevice,
		Flags: mf,
		Data:  strings.Join(opts, ","),
	}
	renv.MountSources[rootFsName] = append(renv.MountSources[rootFsName], rootMount)

	// Add submounts.
	var tmpMounted bool
	for _, m := range compileMounts(spec) {
		if err := addRestoreMount(conf, renv, m, fds); err != nil {
			return nil, err
		}
		if filepath.Clean(m.Destination) == "/tmp" {
			tmpMounted = true
		}
	}

	// TODO: handle '/tmp' properly (see mountTmp()).
	if !tmpMounted {
		tmpMount := specs.Mount{
			Type:        tmpfs,
			Destination: "/tmp",
		}
		if err := addRestoreMount(conf, renv, tmpMount, fds); err != nil {
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
	msrc := fs.NewPseudoMountSource()
	mountTree, err := ramfs.MakeDirectoryTree(ctx, msrc, submounts)
	if err != nil {
		return nil, fmt.Errorf("creating mount tree: %v", err)
	}
	overlayInode, err := fs.NewOverlayRoot(ctx, inode, mountTree, fs.MountSourceFlags{})
	if err != nil {
		return nil, fmt.Errorf("adding mount overlay: %v", err)
	}
	return overlayInode, err
}

// subtargets takes a set of Mounts and returns only the targets that are
// children of the given root. The returned paths are relative to the root.
func subtargets(root string, mnts []specs.Mount) []string {
	var targets []string
	for _, mnt := range mnts {
		if relPath, isSubpath := fs.IsSubpath(mnt.Destination, root); isSubpath {
			targets = append(targets, relPath)
		}
	}
	return targets
}

// setupContainerFS is used to set up the file system and amend the procArgs accordingly.
// procArgs are passed by reference and the FDMap field is modified. It dups stdioFDs.
func setupContainerFS(procArgs *kernel.CreateProcessArgs, spec *specs.Spec, conf *Config, stdioFDs, goferFDs []int, console bool, creds *auth.Credentials, ls *limits.LimitSet, k *kernel.Kernel, cid string) error {
	ctx := procArgs.NewContext(k)

	// Create the FD map, which will set stdin, stdout, and stderr.  If
	// console is true, then ioctl calls will be passed through to the host
	// fd.
	fdm, err := createFDMap(ctx, k, ls, console, stdioFDs)
	if err != nil {
		return fmt.Errorf("importing fds: %v", err)
	}

	// CreateProcess takes a reference on FDMap if successful. We
	// won't need ours either way.
	procArgs.FDMap = fdm

	// Use root user to configure mounts. The current user might not have
	// permission to do so.
	rootProcArgs := kernel.CreateProcessArgs{
		WorkingDirectory:     "/",
		Credentials:          auth.NewRootCredentials(creds.UserNamespace),
		Umask:                0022,
		MaxSymlinkTraversals: linux.MaxSymlinkTraversals,
	}
	rootCtx := rootProcArgs.NewContext(k)

	// If this is the root container, we also need to setup the root mount
	// namespace.
	mns := k.RootMountNamespace()
	if mns == nil {
		// Setup the root container.
		return setupRootContainerFS(ctx, rootCtx, spec, conf, goferFDs, func(mns *fs.MountNamespace) {
			k.SetRootMountNamespace(mns)
		})
	}

	// Setup a child container.
	log.Infof("Creating new process in child container.")
	globalRoot := mns.Root()
	defer globalRoot.DecRef()

	// Create mount point for the container's rootfs.
	maxTraversals := uint(0)
	contDir, err := mns.FindInode(ctx, globalRoot, nil, ChildContainersDir, &maxTraversals)
	if err != nil {
		return fmt.Errorf("couldn't find child container dir %q: %v", ChildContainersDir, err)
	}
	if err := contDir.CreateDirectory(ctx, globalRoot, cid, fs.FilePermsFromMode(0755)); err != nil {
		return fmt.Errorf("create directory %q: %v", cid, err)
	}
	containerRoot, err := contDir.Walk(ctx, globalRoot, cid)
	if err != nil {
		return fmt.Errorf("walk to %q failed: %v", cid, err)
	}
	defer containerRoot.DecRef()

	// Create the container's root filesystem mount.
	fds := &fdDispenser{fds: goferFDs}
	rootInode, err := createRootMount(rootCtx, spec, conf, fds, nil)
	if err != nil {
		return fmt.Errorf("creating filesystem for container: %v", err)
	}

	// Mount the container's root filesystem to the newly created mount point.
	if err := mns.Mount(ctx, containerRoot, rootInode); err != nil {
		return fmt.Errorf("mount container root: %v", err)
	}

	// We have to re-walk to the dirent to find the mounted
	// directory. The old dirent is invalid at this point.
	containerRoot, err = contDir.Walk(ctx, globalRoot, cid)
	if err != nil {
		return fmt.Errorf("find container mount point %q: %v", cid, err)
	}
	cu := specutils.MakeCleanup(func() { containerRoot.DecRef() })
	defer cu.Clean()

	log.Infof("Mounted child's root fs to %q", filepath.Join(ChildContainersDir, cid))

	// Set process root here, so 'rootCtx.Value(CtxRoot)' will return it.
	procArgs.Root = containerRoot

	// Mount all submounts.
	mounts := compileMounts(spec)
	if err := mountSubmounts(rootCtx, conf, mns, containerRoot, mounts, fds); err != nil {
		return err
	}
	cu.Release()
	return nil
}

// setExecutablePath sets the procArgs.Filename by searching the PATH for an
// executable matching the procArgs.Argv[0].
func setExecutablePath(ctx context.Context, mns *fs.MountNamespace, procArgs *kernel.CreateProcessArgs) error {
	paths := fs.GetPath(procArgs.Envv)
	exe := procArgs.Argv[0]
	f, err := mns.ResolveExecutablePath(ctx, procArgs.WorkingDirectory, exe, paths)
	if err != nil {
		return fmt.Errorf("searching for executable %q, cwd: %q, $PATH=%q: %v", exe, procArgs.WorkingDirectory, strings.Join(paths, ":"), err)
	}
	procArgs.Filename = f
	return nil
}

// destroyContainerFS cleans up the filesystem by unmounting all mounts for the
// given container and deleting the container root directory.
func destroyContainerFS(ctx context.Context, cid string, k *kernel.Kernel) error {
	defer func() {
		// Flushing dirent references triggers many async close
		// operations. We must wait for those to complete before
		// returning, otherwise the caller may kill the gofer before
		// they complete, causing a cascade of failing RPCs.
		//
		// This must take place in the first deferred function, so that
		// it runs after all the other deferred DecRef() calls in this
		// function.
		log.Infof("Waiting for async filesystem operations to complete")
		fs.AsyncBarrier()
	}()

	// First get a reference to the container root directory.
	mns := k.RootMountNamespace()
	mnsRoot := mns.Root()
	defer mnsRoot.DecRef()
	containerRoot := path.Join(ChildContainersDir, cid)
	maxTraversals := uint(0)
	containerRootDirent, err := mns.FindInode(ctx, mnsRoot, nil, containerRoot, &maxTraversals)
	if err == syserror.ENOENT {
		// Container must have been destroyed already. That's fine.
		return nil
	}
	if err != nil {
		return fmt.Errorf("finding container root directory %q: %v", containerRoot, err)
	}
	defer containerRootDirent.DecRef()

	// Iterate through all submounts and unmount them. We unmount lazily by
	// setting detach=true, so we can unmount in any order.
	for _, m := range containerRootDirent.Inode.MountSource.Submounts() {
		root := m.Root()
		defer root.DecRef()

		// Do a best-effort unmount by flushing the refs and unmount
		// with "detach only = true". Unmount returns EINVAL when the mount point
		// doesn't exist, i.e. it has already been unmounted.
		log.Debugf("Unmounting container submount %q", root.BaseName())
		m.FlushDirentRefs()
		if err := mns.Unmount(ctx, root, true /* detach only */); err != nil && err != syserror.EINVAL {
			return fmt.Errorf("unmounting container submount %q: %v", root.BaseName(), err)
		}
	}

	// Unmount the container root itself.
	log.Debugf("Unmounting container root %q", containerRoot)
	containerRootDirent.Inode.MountSource.FlushDirentRefs()
	if err := mns.Unmount(ctx, containerRootDirent, true /* detach only */); err != nil {
		return fmt.Errorf("unmounting container root mount %q: %v", containerRootDirent.BaseName(), err)
	}

	// Get a reference to the parent directory and remove the root
	// container directory.
	maxTraversals = 0
	containersDirDirent, err := mns.FindInode(ctx, mnsRoot, nil, ChildContainersDir, &maxTraversals)
	if err != nil {
		return fmt.Errorf("finding containers directory %q: %v", ChildContainersDir, err)
	}
	defer containersDirDirent.DecRef()
	log.Debugf("Deleting container root %q", containerRoot)
	if err := containersDirDirent.RemoveDirectory(ctx, mnsRoot, cid); err != nil {
		return fmt.Errorf("removing directory %q: %v", containerRoot, err)
	}

	return nil
}

// mountTmp mounts an internal tmpfs at '/tmp' if it's safe to do so.
// Technically we don't have to mount tmpfs at /tmp, as we could just rely on
// the host /tmp, but this is a nice optimization, and fixes some apps that call
// mknod in /tmp. It's unsafe to mount tmpfs if:
//   1. /tmp is mounted explictly: we should not override user's wish
//   2. /tmp is not empty: mounting tmpfs would hide existing files in /tmp
//
// Note that when there are submounts inside of '/tmp', directories for the
// mount points must be present, making '/tmp' not empty anymore.
func mountTmp(ctx context.Context, conf *Config, mns *fs.MountNamespace, root *fs.Dirent, fds *fdDispenser, mounts []specs.Mount) error {
	for _, m := range mounts {
		if filepath.Clean(m.Destination) == "/tmp" {
			log.Debugf("Explict %q mount found, skipping internal tmpfs, mount: %+v", "/tmp", m)
			return nil
		}
	}

	maxTraversals := uint(0)
	tmp, err := mns.FindInode(ctx, root, root, "tmp", &maxTraversals)
	switch err {
	case nil:
		// Found '/tmp' in filesystem, check if it's empty.
		defer tmp.DecRef()
		f, err := tmp.Inode.GetFile(ctx, tmp, fs.FileFlags{Read: true, Directory: true})
		if err != nil {
			return err
		}
		defer f.DecRef()
		serializer := &fs.CollectEntriesSerializer{}
		if err := f.Readdir(ctx, serializer); err != nil {
			return err
		}
		// If more than "." and ".." is found, skip internal tmpfs to prevent hiding
		// existing files.
		if len(serializer.Order) > 2 {
			log.Infof("Skipping internal tmpfs on top %q, because it's not empty", "/tmp")
			return nil
		}
		log.Infof("Mounting internal tmpfs on top of empty %q", "/tmp")
		fallthrough

	case syserror.ENOENT:
		// No '/tmp' found (or fallthrough from above). Safe to mount internal
		// tmpfs.
		tmpMount := specs.Mount{
			Type:        tmpfs,
			Destination: "/tmp",
		}
		return mountSubmount(ctx, conf, mns, root, fds, tmpMount, mounts)

	default:
		return err
	}
}

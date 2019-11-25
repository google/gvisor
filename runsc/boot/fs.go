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

package boot

import (
	"fmt"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"

	// Include filesystem types that OCI spec might mount.
	_ "gvisor.dev/gvisor/pkg/sentry/fs/dev"
	_ "gvisor.dev/gvisor/pkg/sentry/fs/host"
	_ "gvisor.dev/gvisor/pkg/sentry/fs/proc"
	_ "gvisor.dev/gvisor/pkg/sentry/fs/sys"
	_ "gvisor.dev/gvisor/pkg/sentry/fs/tmpfs"
	_ "gvisor.dev/gvisor/pkg/sentry/fs/tty"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/context"
	"gvisor.dev/gvisor/pkg/sentry/fs"
	"gvisor.dev/gvisor/pkg/sentry/fs/gofer"
	"gvisor.dev/gvisor/pkg/sentry/fs/ramfs"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/syserror"
	"gvisor.dev/gvisor/runsc/specutils"
)

const (
	// Filesystem name for 9p gofer mounts.
	rootFsName = "9p"

	// Device name for root mount.
	rootDevice = "9pfs-/"

	// MountPrefix is the annotation prefix for mount hints.
	MountPrefix = "gvisor.dev/spec/mount"

	// Filesystems that runsc supports.
	bind     = "bind"
	devpts   = "devpts"
	devtmpfs = "devtmpfs"
	proc     = "proc"
	sysfs    = "sysfs"
	tmpfs    = "tmpfs"
	nonefs   = "none"
)

// tmpfs has some extra supported options that we must pass through.
var tmpfsAllowedOptions = []string{"mode", "uid", "gid"}

func addOverlay(ctx context.Context, conf *Config, lower *fs.Inode, name string, lowerFlags fs.MountSourceFlags) (*fs.Inode, error) {
	// Upper layer uses the same flags as lower, but it must be read-write.
	upperFlags := lowerFlags
	upperFlags.ReadOnly = false

	tmpFS := mustFindFilesystem("tmpfs")
	if !fs.IsDir(lower.StableAttr) {
		// Create overlay on top of mount file, e.g. /etc/hostname.
		msrc := fs.NewCachingMountSource(ctx, tmpFS, upperFlags)
		return fs.NewOverlayRootFile(ctx, msrc, lower, upperFlags)
	}

	// Create overlay on top of mount dir.
	upper, err := tmpFS.Mount(ctx, name+"-upper", upperFlags, "", nil)
	if err != nil {
		return nil, fmt.Errorf("creating tmpfs overlay: %v", err)
	}

	// Replicate permissions and owner from lower to upper mount point.
	attr, err := lower.UnstableAttr(ctx)
	if err != nil {
		return nil, fmt.Errorf("reading attributes from lower mount point: %v", err)
	}
	if !upper.InodeOperations.SetPermissions(ctx, upper, attr.Perms) {
		return nil, fmt.Errorf("error setting permission to upper mount point")
	}
	if err := upper.InodeOperations.SetOwner(ctx, upper, attr.Owner); err != nil {
		return nil, fmt.Errorf("setting owner to upper mount point: %v", err)
	}

	return fs.NewOverlayRoot(ctx, upper, lower, upperFlags)
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
		ok, err := parseMountOption(o, allowedKeys...)
		if err != nil {
			return nil, err
		}
		if ok {
			out = append(out, o)
		}
	}
	return out, nil
}

func parseMountOption(opt string, allowedKeys ...string) (bool, error) {
	kv := strings.SplitN(opt, "=", 3)
	if len(kv) > 2 {
		return false, fmt.Errorf("invalid option %q", opt)
	}
	return specutils.ContainsStr(allowedKeys, kv[0]), nil
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

func mountFlags(opts []string) fs.MountSourceFlags {
	mf := fs.MountSourceFlags{}
	// Note: changes to supported options must be reflected in
	// isSupportedMountFlag() as well.
	for _, o := range opts {
		switch o {
		case "rw":
			mf.ReadOnly = false
		case "ro":
			mf.ReadOnly = true
		case "noatime":
			mf.NoAtime = true
		case "noexec":
			mf.NoExec = true
		default:
			log.Warningf("ignoring unknown mount option %q", o)
		}
	}
	return mf
}

func isSupportedMountFlag(fstype, opt string) bool {
	switch opt {
	case "rw", "ro", "noatime", "noexec":
		return true
	}
	if fstype == tmpfs {
		ok, err := parseMountOption(opt, tmpfsAllowedOptions...)
		return ok && err == nil
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
	// Construct a ramfs tree of mount points. The contents never
	// change, so this can be fully caching. There's no real
	// filesystem backing this tree, so we set the filesystem to
	// nil.
	msrc := fs.NewCachingMountSource(ctx, nil, fs.MountSourceFlags{})
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

func setupContainerFS(ctx context.Context, conf *Config, mntr *containerMounter, procArgs *kernel.CreateProcessArgs) error {
	mns, err := mntr.setupFS(conf, procArgs)
	if err != nil {
		return err
	}

	// Set namespace here so that it can be found in ctx.
	procArgs.MountNamespace = mns

	return setExecutablePath(ctx, procArgs)
}

// setExecutablePath sets the procArgs.Filename by searching the PATH for an
// executable matching the procArgs.Argv[0].
func setExecutablePath(ctx context.Context, procArgs *kernel.CreateProcessArgs) error {
	paths := fs.GetPath(procArgs.Envv)
	exe := procArgs.Argv[0]
	f, err := procArgs.MountNamespace.ResolveExecutablePath(ctx, procArgs.WorkingDirectory, exe, paths)
	if err != nil {
		return fmt.Errorf("searching for executable %q, cwd: %q, $PATH=%q: %v", exe, procArgs.WorkingDirectory, strings.Join(paths, ":"), err)
	}
	procArgs.Filename = f
	return nil
}

func adjustDirentCache(k *kernel.Kernel) error {
	var hl syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &hl); err != nil {
		return fmt.Errorf("getting RLIMIT_NOFILE: %v", err)
	}
	if int64(hl.Cur) != syscall.RLIM_INFINITY {
		newSize := hl.Cur / 2
		if newSize < gofer.DefaultDirentCacheSize {
			log.Infof("Setting gofer dirent cache size to %d", newSize)
			gofer.DefaultDirentCacheSize = newSize
			k.DirentCacheLimiter = fs.NewDirentCacheLimiter(newSize)
		}
	}
	return nil
}

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

type shareType int

const (
	invalid shareType = iota

	// container shareType indicates that the mount is used by a single container.
	container

	// pod shareType indicates that the mount is used by more than one container
	// inside the pod.
	pod

	// shared shareType indicates that the mount can also be shared with a process
	// outside the pod, e.g. NFS.
	shared
)

func parseShare(val string) (shareType, error) {
	switch val {
	case "container":
		return container, nil
	case "pod":
		return pod, nil
	case "shared":
		return shared, nil
	default:
		return 0, fmt.Errorf("invalid share value %q", val)
	}
}

func (s shareType) String() string {
	switch s {
	case invalid:
		return "invalid"
	case container:
		return "container"
	case pod:
		return "pod"
	case shared:
		return "shared"
	default:
		return fmt.Sprintf("invalid share value %d", s)
	}
}

// mountHint represents extra information about mounts that are provided via
// annotations. They can override mount type, and provide sharing information
// so that mounts can be correctly shared inside the pod.
type mountHint struct {
	name  string
	share shareType
	mount specs.Mount

	// root is the inode where the volume is mounted. For mounts with 'pod' share
	// the volume is mounted once and then bind mounted inside the containers.
	root *fs.Inode
}

func (m *mountHint) setField(key, val string) error {
	switch key {
	case "source":
		if len(val) == 0 {
			return fmt.Errorf("source cannot be empty")
		}
		m.mount.Source = val
	case "type":
		return m.setType(val)
	case "share":
		share, err := parseShare(val)
		if err != nil {
			return err
		}
		m.share = share
	case "options":
		return m.setOptions(val)
	default:
		return fmt.Errorf("invalid mount annotation: %s=%s", key, val)
	}
	return nil
}

func (m *mountHint) setType(val string) error {
	switch val {
	case "tmpfs", "bind":
		m.mount.Type = val
	default:
		return fmt.Errorf("invalid type %q", val)
	}
	return nil
}

func (m *mountHint) setOptions(val string) error {
	opts := strings.Split(val, ",")
	if err := specutils.ValidateMountOptions(opts); err != nil {
		return err
	}
	// Sort options so it can be compared with container mount options later on.
	sort.Strings(opts)
	m.mount.Options = opts
	return nil
}

func (m *mountHint) isSupported() bool {
	return m.mount.Type == tmpfs && m.share == pod
}

// checkCompatible verifies that shared mount is compatible with master.
// For now enforce that all options are the same. Once bind mount is properly
// supported, then we should ensure the master is less restrictive than the
// container, e.g. master can be 'rw' while container mounts as 'ro'.
func (m *mountHint) checkCompatible(mount specs.Mount) error {
	// Remove options that don't affect to mount's behavior.
	masterOpts := filterUnsupportedOptions(m.mount)
	slaveOpts := filterUnsupportedOptions(mount)

	if len(masterOpts) != len(slaveOpts) {
		return fmt.Errorf("mount options in annotations differ from container mount, annotation: %s, mount: %s", masterOpts, slaveOpts)
	}

	sort.Strings(masterOpts)
	sort.Strings(slaveOpts)
	for i, opt := range masterOpts {
		if opt != slaveOpts[i] {
			return fmt.Errorf("mount options in annotations differ from container mount, annotation: %s, mount: %s", masterOpts, slaveOpts)
		}
	}
	return nil
}

func (m *mountHint) fileAccessType() FileAccessType {
	if m.share == container {
		return FileAccessExclusive
	}
	return FileAccessShared
}

func filterUnsupportedOptions(mount specs.Mount) []string {
	rv := make([]string, 0, len(mount.Options))
	for _, o := range mount.Options {
		if isSupportedMountFlag(mount.Type, o) {
			rv = append(rv, o)
		}
	}
	return rv
}

// podMountHints contains a collection of mountHints for the pod.
type podMountHints struct {
	mounts map[string]*mountHint
}

func newPodMountHints(spec *specs.Spec) (*podMountHints, error) {
	mnts := make(map[string]*mountHint)
	for k, v := range spec.Annotations {
		// Look for 'gvisor.dev/spec/mount' annotations and parse them.
		if strings.HasPrefix(k, MountPrefix) {
			parts := strings.Split(k, "/")
			if len(parts) != 5 {
				return nil, fmt.Errorf("invalid mount annotation: %s=%s", k, v)
			}
			name := parts[3]
			if len(name) == 0 || path.Clean(name) != name {
				return nil, fmt.Errorf("invalid mount name: %s", name)
			}
			mnt := mnts[name]
			if mnt == nil {
				mnt = &mountHint{name: name}
				mnts[name] = mnt
			}
			if err := mnt.setField(parts[4], v); err != nil {
				return nil, err
			}
		}
	}

	// Validate all hints after done parsing.
	for name, m := range mnts {
		log.Infof("Mount annotation found, name: %s, source: %q, type: %s, share: %v", name, m.mount.Source, m.mount.Type, m.share)
		if m.share == invalid {
			return nil, fmt.Errorf("share field for %q has not been set", m.name)
		}
		if len(m.mount.Source) == 0 {
			return nil, fmt.Errorf("source field for %q has not been set", m.name)
		}
		if len(m.mount.Type) == 0 {
			return nil, fmt.Errorf("type field for %q has not been set", m.name)
		}

		// Check for duplicate mount sources.
		for name2, m2 := range mnts {
			if name != name2 && m.mount.Source == m2.mount.Source {
				return nil, fmt.Errorf("mounts %q and %q have the same mount source %q", m.name, m2.name, m.mount.Source)
			}
		}
	}

	return &podMountHints{mounts: mnts}, nil
}

func (p *podMountHints) findMount(mount specs.Mount) *mountHint {
	for _, m := range p.mounts {
		if m.mount.Source == mount.Source {
			return m
		}
	}
	return nil
}

type containerMounter struct {
	root *specs.Root

	// mounts is the set of submounts for the container. It's a copy from the spec
	// that may be freely modified without affecting the original spec.
	mounts []specs.Mount

	// fds is the list of FDs to be dispensed for mounts that require it.
	fds fdDispenser

	k *kernel.Kernel

	hints *podMountHints
}

func newContainerMounter(spec *specs.Spec, goferFDs []int, k *kernel.Kernel, hints *podMountHints) *containerMounter {
	return &containerMounter{
		root:   spec.Root,
		mounts: compileMounts(spec),
		fds:    fdDispenser{fds: goferFDs},
		k:      k,
		hints:  hints,
	}
}

// processHints processes annotations that container hints about how volumes
// should be mounted (e.g. a volume shared between containers). It must be
// called for the root container only.
func (c *containerMounter) processHints(conf *Config) error {
	ctx := c.k.SupervisorContext()
	for _, hint := range c.hints.mounts {
		log.Infof("Mounting master of shared mount %q from %q type %q", hint.name, hint.mount.Source, hint.mount.Type)
		inode, err := c.mountSharedMaster(ctx, conf, hint)
		if err != nil {
			return fmt.Errorf("mounting shared master %q: %v", hint.name, err)
		}
		hint.root = inode
	}
	return nil
}

// setupFS is used to set up the file system for all containers. This is the
// main entry point method, with most of the other being internal only. It
// returns the mount namespace that is created for the container.
func (c *containerMounter) setupFS(conf *Config, procArgs *kernel.CreateProcessArgs) (*fs.MountNamespace, error) {
	log.Infof("Configuring container's file system")

	// Create context with root credentials to mount the filesystem (the current
	// user may not be privileged enough).
	rootProcArgs := *procArgs
	rootProcArgs.WorkingDirectory = "/"
	rootProcArgs.Credentials = auth.NewRootCredentials(procArgs.Credentials.UserNamespace)
	rootProcArgs.Umask = 0022
	rootProcArgs.MaxSymlinkTraversals = linux.MaxSymlinkTraversals
	rootCtx := rootProcArgs.NewContext(c.k)

	mns, err := c.createMountNamespace(rootCtx, conf)
	if err != nil {
		return nil, err
	}

	// Set namespace here so that it can be found in rootCtx.
	rootProcArgs.MountNamespace = mns

	if err := c.mountSubmounts(rootCtx, conf, mns); err != nil {
		return nil, err
	}
	return mns, nil
}

func (c *containerMounter) createMountNamespace(ctx context.Context, conf *Config) (*fs.MountNamespace, error) {
	rootInode, err := c.createRootMount(ctx, conf)
	if err != nil {
		return nil, fmt.Errorf("creating filesystem for container: %v", err)
	}
	mns, err := fs.NewMountNamespace(ctx, rootInode)
	if err != nil {
		return nil, fmt.Errorf("creating new mount namespace for container: %v", err)
	}
	return mns, nil
}

func (c *containerMounter) mountSubmounts(ctx context.Context, conf *Config, mns *fs.MountNamespace) error {
	root := mns.Root()
	defer root.DecRef()

	for _, m := range c.mounts {
		log.Debugf("Mounting %q to %q, type: %s, options: %s", m.Source, m.Destination, m.Type, m.Options)
		if hint := c.hints.findMount(m); hint != nil && hint.isSupported() {
			if err := c.mountSharedSubmount(ctx, mns, root, m, hint); err != nil {
				return fmt.Errorf("mount shared mount %q to %q: %v", hint.name, m.Destination, err)
			}
		} else {
			if err := c.mountSubmount(ctx, conf, mns, root, m); err != nil {
				return fmt.Errorf("mount submount %q: %v", m.Destination, err)
			}
		}
	}

	if err := c.mountTmp(ctx, conf, mns, root); err != nil {
		return fmt.Errorf("mount submount %q: %v", "tmp", err)
	}

	if err := c.checkDispenser(); err != nil {
		return err
	}
	return nil
}

func (c *containerMounter) checkDispenser() error {
	if !c.fds.empty() {
		return fmt.Errorf("not all gofer FDs were consumed, remaining: %v", c.fds)
	}
	return nil
}

// mountSharedMaster mounts the master of a volume that is shared among
// containers in a pod. It returns the root mount's inode.
func (c *containerMounter) mountSharedMaster(ctx context.Context, conf *Config, hint *mountHint) (*fs.Inode, error) {
	// Map mount type to filesystem name, and parse out the options that we are
	// capable of dealing with.
	fsName, opts, useOverlay, err := c.getMountNameAndOptions(conf, hint.mount)
	if err != nil {
		return nil, err
	}
	if len(fsName) == 0 {
		return nil, fmt.Errorf("mount type not supported %q", hint.mount.Type)
	}

	// Mount with revalidate because it's shared among containers.
	opts = append(opts, "cache=revalidate")

	// All filesystem names should have been mapped to something we know.
	filesystem := mustFindFilesystem(fsName)

	mf := mountFlags(hint.mount.Options)
	if useOverlay {
		// All writes go to upper, be paranoid and make lower readonly.
		mf.ReadOnly = true
	}

	inode, err := filesystem.Mount(ctx, mountDevice(hint.mount), mf, strings.Join(opts, ","), nil)
	if err != nil {
		return nil, fmt.Errorf("creating mount %q: %v", hint.name, err)
	}

	if useOverlay {
		log.Debugf("Adding overlay on top of shared mount %q", hint.name)
		inode, err = addOverlay(ctx, conf, inode, hint.mount.Type, mf)
		if err != nil {
			return nil, err
		}
	}

	return inode, nil
}

// createRootMount creates the root filesystem.
func (c *containerMounter) createRootMount(ctx context.Context, conf *Config) (*fs.Inode, error) {
	// First construct the filesystem from the spec.Root.
	mf := fs.MountSourceFlags{ReadOnly: c.root.Readonly || conf.Overlay}

	fd := c.fds.remove()
	log.Infof("Mounting root over 9P, ioFD: %d", fd)
	p9FS := mustFindFilesystem("9p")
	opts := p9MountOptions(fd, conf.FileAccess)

	if conf.OverlayfsStaleRead {
		// We can't check for overlayfs here because sandbox is chroot'ed and gofer
		// can only send mount options for specs.Mounts (specs.Root is missing
		// Options field). So assume root is always on top of overlayfs.
		opts = append(opts, "overlayfs_stale_read")
	}

	rootInode, err := p9FS.Mount(ctx, rootDevice, mf, strings.Join(opts, ","), nil)
	if err != nil {
		return nil, fmt.Errorf("creating root mount point: %v", err)
	}

	// We need to overlay the root on top of a ramfs with stub directories
	// for submount paths.  "/dev" "/sys" "/proc" and "/tmp" are always
	// mounted even if they are not in the spec.
	submounts := append(subtargets("/", c.mounts), "/dev", "/sys", "/proc", "/tmp")
	rootInode, err = addSubmountOverlay(ctx, rootInode, submounts)
	if err != nil {
		return nil, fmt.Errorf("adding submount overlay: %v", err)
	}

	if conf.Overlay && !c.root.Readonly {
		log.Debugf("Adding overlay on top of root mount")
		// Overlay a tmpfs filesystem on top of the root.
		rootInode, err = addOverlay(ctx, conf, rootInode, "root-overlay-upper", mf)
		if err != nil {
			return nil, err
		}
	}

	log.Infof("Mounted %q to %q type root", c.root.Path, "/")
	return rootInode, nil
}

// getMountNameAndOptions retrieves the fsName, opts, and useOverlay values
// used for mounts.
func (c *containerMounter) getMountNameAndOptions(conf *Config, m specs.Mount) (string, []string, bool, error) {
	var (
		fsName     string
		opts       []string
		useOverlay bool
	)

	switch m.Type {
	case devpts, devtmpfs, proc, sysfs:
		fsName = m.Type
	case nonefs:
		fsName = sysfs
	case tmpfs:
		fsName = m.Type

		var err error
		opts, err = parseAndFilterOptions(m.Options, tmpfsAllowedOptions...)
		if err != nil {
			return "", nil, false, err
		}

	case bind:
		fd := c.fds.remove()
		fsName = "9p"
		opts = p9MountOptions(fd, c.getMountAccessType(m))
		// If configured, add overlay to all writable mounts.
		useOverlay = conf.Overlay && !mountFlags(m.Options).ReadOnly

	default:
		// TODO(nlacasse): Support all the mount types and make this a fatal error.
		// Most applications will "just work" without them, so this is a warning
		// for now.
		log.Warningf("ignoring unknown filesystem type %q", m.Type)
	}
	return fsName, opts, useOverlay, nil
}

func (c *containerMounter) getMountAccessType(mount specs.Mount) FileAccessType {
	if hint := c.hints.findMount(mount); hint != nil {
		return hint.fileAccessType()
	}
	// Non-root bind mounts are always shared if no hints were provided.
	return FileAccessShared
}

// mountSubmount mounts volumes inside the container's root. Because mounts may
// be readonly, a lower ramfs overlay is added to create the mount point dir.
// Another overlay is added with tmpfs on top if Config.Overlay is true.
// 'm.Destination' must be an absolute path with '..' and symlinks resolved.
func (c *containerMounter) mountSubmount(ctx context.Context, conf *Config, mns *fs.MountNamespace, root *fs.Dirent, m specs.Mount) error {
	// Map mount type to filesystem name, and parse out the options that we are
	// capable of dealing with.
	fsName, opts, useOverlay, err := c.getMountNameAndOptions(conf, m)
	if err != nil {
		return err
	}
	if fsName == "" {
		// Filesystem is not supported (e.g. cgroup), just skip it.
		return nil
	}

	// All filesystem names should have been mapped to something we know.
	filesystem := mustFindFilesystem(fsName)

	mf := mountFlags(m.Options)
	if useOverlay {
		// All writes go to upper, be paranoid and make lower readonly.
		mf.ReadOnly = true
	}

	inode, err := filesystem.Mount(ctx, mountDevice(m), mf, strings.Join(opts, ","), nil)
	if err != nil {
		return fmt.Errorf("creating mount with source %q: %v", m.Source, err)
	}

	// If there are submounts, we need to overlay the mount on top of a ramfs
	// with stub directories for submount paths.
	submounts := subtargets(m.Destination, c.mounts)
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

// mountSharedSubmount binds mount to a previously mounted volume that is shared
// among containers in the same pod.
func (c *containerMounter) mountSharedSubmount(ctx context.Context, mns *fs.MountNamespace, root *fs.Dirent, mount specs.Mount, source *mountHint) error {
	if err := source.checkCompatible(mount); err != nil {
		return err
	}

	maxTraversals := uint(0)
	target, err := mns.FindInode(ctx, root, root, mount.Destination, &maxTraversals)
	if err != nil {
		return fmt.Errorf("can't find mount destination %q: %v", mount.Destination, err)
	}
	defer target.DecRef()

	// Take a ref on the inode that is about to be (re)-mounted.
	source.root.IncRef()
	if err := mns.Mount(ctx, target, source.root); err != nil {
		source.root.DecRef()
		return fmt.Errorf("bind mount %q error: %v", mount.Destination, err)
	}

	log.Infof("Mounted %q type shared bind to %q", mount.Destination, source.name)
	return nil
}

// addRestoreMount adds a mount to the MountSources map used for restoring a
// checkpointed container.
func (c *containerMounter) addRestoreMount(conf *Config, renv *fs.RestoreEnvironment, m specs.Mount) error {
	fsName, opts, useOverlay, err := c.getMountNameAndOptions(conf, m)
	if err != nil {
		return err
	}
	if fsName == "" {
		// Filesystem is not supported (e.g. cgroup), just skip it.
		return nil
	}

	newMount := fs.MountArgs{
		Dev:        mountDevice(m),
		Flags:      mountFlags(m.Options),
		DataString: strings.Join(opts, ","),
	}
	if useOverlay {
		newMount.Flags.ReadOnly = true
	}
	renv.MountSources[fsName] = append(renv.MountSources[fsName], newMount)
	log.Infof("Added mount at %q: %+v", fsName, newMount)
	return nil
}

// createRestoreEnvironment builds a fs.RestoreEnvironment called renv by adding
// the mounts to the environment.
func (c *containerMounter) createRestoreEnvironment(conf *Config) (*fs.RestoreEnvironment, error) {
	renv := &fs.RestoreEnvironment{
		MountSources: make(map[string][]fs.MountArgs),
	}

	// Add root mount.
	fd := c.fds.remove()
	opts := p9MountOptions(fd, conf.FileAccess)

	mf := fs.MountSourceFlags{}
	if c.root.Readonly || conf.Overlay {
		mf.ReadOnly = true
	}

	rootMount := fs.MountArgs{
		Dev:        rootDevice,
		Flags:      mf,
		DataString: strings.Join(opts, ","),
	}
	renv.MountSources[rootFsName] = append(renv.MountSources[rootFsName], rootMount)

	// Add submounts.
	var tmpMounted bool
	for _, m := range c.mounts {
		if err := c.addRestoreMount(conf, renv, m); err != nil {
			return nil, err
		}
		if filepath.Clean(m.Destination) == "/tmp" {
			tmpMounted = true
		}
	}

	// TODO(b/67958150): handle '/tmp' properly (see mountTmp()).
	if !tmpMounted {
		tmpMount := specs.Mount{
			Type:        tmpfs,
			Destination: "/tmp",
		}
		if err := c.addRestoreMount(conf, renv, tmpMount); err != nil {
			return nil, err
		}
	}

	return renv, nil
}

// mountTmp mounts an internal tmpfs at '/tmp' if it's safe to do so.
// Technically we don't have to mount tmpfs at /tmp, as we could just rely on
// the host /tmp, but this is a nice optimization, and fixes some apps that call
// mknod in /tmp. It's unsafe to mount tmpfs if:
//   1. /tmp is mounted explicitly: we should not override user's wish
//   2. /tmp is not empty: mounting tmpfs would hide existing files in /tmp
//
// Note that when there are submounts inside of '/tmp', directories for the
// mount points must be present, making '/tmp' not empty anymore.
func (c *containerMounter) mountTmp(ctx context.Context, conf *Config, mns *fs.MountNamespace, root *fs.Dirent) error {
	for _, m := range c.mounts {
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
			// Sticky bit is added to prevent accidental deletion of files from
			// another user. This is normally done for /tmp.
			Options: []string{"mode=1777"},
		}
		return c.mountSubmount(ctx, conf, mns, root, tmpMount)

	default:
		return err
	}
}

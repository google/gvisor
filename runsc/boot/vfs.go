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

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/cleanup"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/fd"
	"gvisor.dev/gvisor/pkg/fspath"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/devices/memdev"
	"gvisor.dev/gvisor/pkg/sentry/devices/ttydev"
	"gvisor.dev/gvisor/pkg/sentry/devices/tundev"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/cgroupfs"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/devpts"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/devtmpfs"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/fuse"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/gofer"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/mqfs"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/overlay"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/proc"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/sys"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/tmpfs"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/user"
	"gvisor.dev/gvisor/pkg/sentry/inet"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/runsc/config"
	"gvisor.dev/gvisor/runsc/specutils"
)

// Supported filesystems that map to different internal filesystems.
const (
	Bind   = "bind"
	Nonefs = "none"
)

// SelfOverlayFilestorePrefix is the prefix in the file name of the
// self overlay filestore file.
const SelfOverlayFilestorePrefix = ".gvisor.overlay.img."

// SelfOverlayFilestorePath returns the path at which the self overlay
// filestore file is stored for a given mount.
func SelfOverlayFilestorePath(mountSrc, sandboxID string) string {
	// We will place the filestore file in a gVisor specific hidden file inside
	// the mount being overlay-ed itself. The same volume can be overlay-ed by
	// multiple sandboxes. So make the filestore file unique to a sandbox by
	// suffixing the sandbox ID.
	return path.Join(mountSrc, selfOverlayFilestoreName(sandboxID))
}

func selfOverlayFilestoreName(sandboxID string) string {
	return SelfOverlayFilestorePrefix + sandboxID
}

// tmpfs has some extra supported options that we must pass through.
var tmpfsAllowedData = []string{"mode", "size", "uid", "gid"}

func registerFilesystems(k *kernel.Kernel) error {
	ctx := k.SupervisorContext()
	creds := auth.NewRootCredentials(k.RootUserNamespace())
	vfsObj := k.VFS()

	vfsObj.MustRegisterFilesystemType(cgroupfs.Name, &cgroupfs.FilesystemType{}, &vfs.RegisterFilesystemTypeOptions{
		AllowUserMount: true,
		AllowUserList:  true,
	})
	vfsObj.MustRegisterFilesystemType(devpts.Name, &devpts.FilesystemType{}, &vfs.RegisterFilesystemTypeOptions{
		AllowUserList: true,
		// TODO(b/29356795): Users may mount this once the terminals are in a
		//  usable state.
		AllowUserMount: false,
	})
	vfsObj.MustRegisterFilesystemType(devtmpfs.Name, &devtmpfs.FilesystemType{}, &vfs.RegisterFilesystemTypeOptions{
		AllowUserMount: true,
		AllowUserList:  true,
	})
	vfsObj.MustRegisterFilesystemType(fuse.Name, &fuse.FilesystemType{}, &vfs.RegisterFilesystemTypeOptions{
		AllowUserMount: true,
		AllowUserList:  true,
	})
	vfsObj.MustRegisterFilesystemType(gofer.Name, &gofer.FilesystemType{}, &vfs.RegisterFilesystemTypeOptions{
		AllowUserList: true,
	})
	vfsObj.MustRegisterFilesystemType(overlay.Name, &overlay.FilesystemType{}, &vfs.RegisterFilesystemTypeOptions{
		AllowUserMount: true,
		AllowUserList:  true,
	})
	vfsObj.MustRegisterFilesystemType(proc.Name, &proc.FilesystemType{}, &vfs.RegisterFilesystemTypeOptions{
		AllowUserMount: true,
		AllowUserList:  true,
	})
	vfsObj.MustRegisterFilesystemType(sys.Name, &sys.FilesystemType{}, &vfs.RegisterFilesystemTypeOptions{
		AllowUserMount: true,
		AllowUserList:  true,
	})
	vfsObj.MustRegisterFilesystemType(tmpfs.Name, &tmpfs.FilesystemType{}, &vfs.RegisterFilesystemTypeOptions{
		AllowUserMount: true,
		AllowUserList:  true,
	})
	vfsObj.MustRegisterFilesystemType(mqfs.Name, &mqfs.FilesystemType{}, &vfs.RegisterFilesystemTypeOptions{
		AllowUserMount: true,
		AllowUserList:  true,
	})

	// Setup files in devtmpfs.
	if err := memdev.Register(vfsObj); err != nil {
		return fmt.Errorf("registering memdev: %w", err)
	}
	if err := ttydev.Register(vfsObj); err != nil {
		return fmt.Errorf("registering ttydev: %w", err)
	}
	tunSupported := tundev.IsNetTunSupported(inet.StackFromContext(ctx))
	if tunSupported {
		if err := tundev.Register(vfsObj); err != nil {
			return fmt.Errorf("registering tundev: %v", err)
		}
	}

	if err := fuse.Register(vfsObj); err != nil {
		return fmt.Errorf("registering fusedev: %w", err)
	}

	a, err := devtmpfs.NewAccessor(ctx, vfsObj, creds, devtmpfs.Name)
	if err != nil {
		return fmt.Errorf("creating devtmpfs accessor: %w", err)
	}
	defer a.Release(ctx)

	if err := a.UserspaceInit(ctx); err != nil {
		return fmt.Errorf("initializing userspace: %w", err)
	}
	if err := memdev.CreateDevtmpfsFiles(ctx, a); err != nil {
		return fmt.Errorf("creating memdev devtmpfs files: %w", err)
	}
	if err := ttydev.CreateDevtmpfsFiles(ctx, a); err != nil {
		return fmt.Errorf("creating ttydev devtmpfs files: %w", err)
	}
	if tunSupported {
		if err := tundev.CreateDevtmpfsFiles(ctx, a); err != nil {
			return fmt.Errorf("creating tundev devtmpfs files: %v", err)
		}
	}

	if err := fuse.CreateDevtmpfsFile(ctx, a); err != nil {
		return fmt.Errorf("creating fusedev devtmpfs files: %w", err)
	}

	return nil
}

func setupContainerVFS(ctx context.Context, conf *config.Config, mntr *containerMounter, procArgs *kernel.CreateProcessArgs) error {
	mns, err := mntr.mountAll(conf, procArgs)
	if err != nil {
		return fmt.Errorf("failed to setupFS: %w", err)
	}
	procArgs.MountNamespace = mns

	// We are executing a file directly. Do not resolve the executable path.
	if procArgs.File != nil {
		return nil
	}
	// Resolve the executable path from working dir and environment.
	resolved, err := user.ResolveExecutablePath(ctx, procArgs)
	if err != nil {
		return err
	}
	procArgs.Filename = resolved
	return nil
}

// compileMounts returns the supported mounts from the mount spec, adding any
// mandatory mounts that are required by the OCI specification.
func compileMounts(spec *specs.Spec, conf *config.Config) []specs.Mount {
	// Keep track of whether proc and sys were mounted.
	var procMounted, sysMounted, devMounted, devptsMounted bool
	var mounts []specs.Mount

	// Mount all submounts from the spec.
	for _, m := range spec.Mounts {
		// Unconditionally drop any cgroupfs mounts. If requested, we'll add our
		// own below.
		if m.Type == cgroupfs.Name {
			continue
		}
		switch filepath.Clean(m.Destination) {
		case "/proc":
			procMounted = true
		case "/sys":
			sysMounted = true
		case "/dev":
			m.Type = devtmpfs.Name
			devMounted = true
		case "/dev/pts":
			m.Type = devpts.Name
			devptsMounted = true
		}
		mounts = append(mounts, m)
	}

	// Mount proc and sys even if the user did not ask for it, as the spec
	// says we SHOULD.
	var mandatoryMounts []specs.Mount

	if conf.Cgroupfs {
		mandatoryMounts = append(mandatoryMounts, specs.Mount{
			Type:        tmpfs.Name,
			Destination: "/sys/fs/cgroup",
		})
		mandatoryMounts = append(mandatoryMounts, specs.Mount{
			Type:        cgroupfs.Name,
			Destination: "/sys/fs/cgroup/memory",
			Options:     []string{"memory"},
		})
		mandatoryMounts = append(mandatoryMounts, specs.Mount{
			Type:        cgroupfs.Name,
			Destination: "/sys/fs/cgroup/cpu",
			Options:     []string{"cpu"},
		})
	}

	if !procMounted {
		mandatoryMounts = append(mandatoryMounts, specs.Mount{
			Type:        proc.Name,
			Destination: "/proc",
		})
	}
	if !sysMounted {
		mandatoryMounts = append(mandatoryMounts, specs.Mount{
			Type:        sys.Name,
			Destination: "/sys",
		})
	}
	if !devMounted {
		mandatoryMounts = append(mandatoryMounts, specs.Mount{
			Type:        devtmpfs.Name,
			Destination: "/dev",
		})
	}
	if !devptsMounted {
		mandatoryMounts = append(mandatoryMounts, specs.Mount{
			Type:        devpts.Name,
			Destination: "/dev/pts",
		})
	}

	// The mandatory mounts should be ordered right after the root, in case
	// there are submounts of these mandatory mounts already in the spec.
	mounts = append(mounts[:0], append(mandatoryMounts, mounts[0:]...)...)

	return mounts
}

// goferMountData creates a slice of gofer mount data.
func goferMountData(fd int, fa config.FileAccessType, conf *config.Config) []string {
	opts := []string{
		"trans=fd",
		"rfdno=" + strconv.Itoa(fd),
		"wfdno=" + strconv.Itoa(fd),
	}
	if fa == config.FileAccessShared {
		opts = append(opts, "cache=remote_revalidating")
	}
	if conf.DirectFS {
		opts = append(opts, "directfs")
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

type fdDispenser struct {
	fds []*fd.FD
}

func (f *fdDispenser) remove() int {
	return f.removeAsFD().Release()
}

func (f *fdDispenser) removeAsFD() *fd.FD {
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

type containerMounter struct {
	root *specs.Root

	// mounts is the set of submounts for the container. It's a copy from the spec
	// that may be freely modified without affecting the original spec.
	mounts []specs.Mount

	// fds is the list of FDs to be dispensed for mounts that require it.
	fds fdDispenser

	// overlayFilestoreFDs are the FDs to the regular files that will back the
	// tmpfs upper mount in the overlay mounts.
	overlayFilestoreFDs fdDispenser

	k *kernel.Kernel

	hints *podMountHints

	// productName is the value to show in
	// /sys/devices/virtual/dmi/id/product_name.
	productName string

	// sandboxID is the ID for the whole sandbox.
	sandboxID string
}

func newContainerMounter(info *containerInfo, k *kernel.Kernel, hints *podMountHints, productName string, sandboxID string) *containerMounter {
	return &containerMounter{
		root:                info.spec.Root,
		mounts:              compileMounts(info.spec, info.conf),
		fds:                 fdDispenser{fds: info.goferFDs},
		overlayFilestoreFDs: fdDispenser{fds: info.overlayFilestoreFDs},
		k:                   k,
		hints:               hints,
		productName:         productName,
		sandboxID:           sandboxID,
	}
}

func (c *containerMounter) checkDispenser() error {
	if !c.fds.empty() {
		return fmt.Errorf("not all gofer FDs were consumed, remaining: %v", c.fds)
	}
	return nil
}

func (c *containerMounter) getMountAccessType(conf *config.Config, mount *specs.Mount) config.FileAccessType {
	if hint := c.hints.findMount(mount); hint != nil {
		return hint.fileAccessType()
	}
	return conf.FileAccessMounts
}

func (c *containerMounter) mountAll(conf *config.Config, procArgs *kernel.CreateProcessArgs) (*vfs.MountNamespace, error) {
	log.Infof("Configuring container's file system")

	// Create context with root credentials to mount the filesystem (the current
	// user may not be privileged enough).
	rootCreds := auth.NewRootCredentials(procArgs.Credentials.UserNamespace)
	rootProcArgs := *procArgs
	rootProcArgs.WorkingDirectory = "/"
	rootProcArgs.Credentials = rootCreds
	rootProcArgs.Umask = 0022
	rootProcArgs.MaxSymlinkTraversals = linux.MaxSymlinkTraversals
	rootCtx := rootProcArgs.NewContext(c.k)

	mns, err := c.createMountNamespace(rootCtx, conf, rootCreds)
	if err != nil {
		return nil, fmt.Errorf("creating mount namespace: %w", err)
	}
	rootProcArgs.MountNamespace = mns

	root := mns.Root()
	root.IncRef()
	defer root.DecRef(rootCtx)
	if root.Mount().ReadOnly() {
		// Switch to ReadWrite while we setup submounts.
		if err := c.k.VFS().SetMountReadOnly(root.Mount(), false); err != nil {
			return nil, fmt.Errorf(`failed to set mount at "/" readwrite: %w`, err)
		}
		// Restore back to ReadOnly at the end.
		defer func() {
			if err := c.k.VFS().SetMountReadOnly(root.Mount(), true); err != nil {
				panic(fmt.Sprintf(`failed to restore mount at "/" back to readonly: %v`, err))
			}
		}()
	}

	// Mount submounts.
	if err := c.mountSubmounts(rootCtx, conf, mns, rootCreds); err != nil {
		return nil, fmt.Errorf("mounting submounts: %w", err)
	}

	return mns, nil
}

// createMountNamespace creates the container's root mount and namespace.
func (c *containerMounter) createMountNamespace(ctx context.Context, conf *config.Config, creds *auth.Credentials) (*vfs.MountNamespace, error) {
	fd := c.fds.remove()
	data := goferMountData(fd, conf.FileAccess, conf)

	// We can't check for overlayfs here because sandbox is chroot'ed and gofer
	// can only send mount options for specs.Mounts (specs.Root is missing
	// Options field). So assume root is always on top of overlayfs.
	data = append(data, "overlayfs_stale_read")

	// Configure the gofer dentry cache size.
	gofer.SetDentryCacheSize(conf.DCache)

	log.Infof("Mounting root with gofer, ioFD: %d", fd)
	opts := &vfs.MountOptions{
		ReadOnly: c.root.Readonly,
		GetFilesystemOptions: vfs.GetFilesystemOptions{
			Data: strings.Join(data, ","),
			InternalData: gofer.InternalFilesystemOptions{
				UniqueID: "/",
			},
		},
		InternalMount: true,
	}

	fsName := gofer.Name
	if conf.GetOverlay2().RootMount && !c.root.Readonly {
		log.Infof("Adding overlay on top of root")
		var err error
		var cleanup func()
		opts, cleanup, err = c.configureOverlay(ctx, conf, creds, opts, fsName, useOverlayFilestoreFD)
		if err != nil {
			return nil, fmt.Errorf("mounting root with overlay: %w", err)
		}
		defer cleanup()
		fsName = overlay.Name
	}

	mns, err := c.k.VFS().NewMountNamespace(ctx, creds, "", fsName, opts)
	if err != nil {
		return nil, fmt.Errorf("setting up mount namespace: %w", err)
	}
	return mns, nil
}

func useOverlayFilestoreFD(overlay2 config.Overlay2, isDir bool) bool {
	if !overlay2.IsBackedByHostFile() {
		return false
	}
	if overlay2.IsBackedBySelf() {
		// Only directory mounts can be backed by a self filestore.
		return isDir
	}
	return true
}

// configureOverlay mounts the lower layer using "lowerOpts", mounts the upper
// layer using tmpfs, and return overlay mount options. "cleanup" must be called
// after the options have been used to mount the overlay, to release refs on
// lower and upper mounts.
func (c *containerMounter) configureOverlay(ctx context.Context, conf *config.Config, creds *auth.Credentials, lowerOpts *vfs.MountOptions, lowerFSName string, useFilestoreFD func(overlay2 config.Overlay2, isDir bool) bool) (*vfs.MountOptions, func(), error) {
	// First copy options from lower layer to upper layer and overlay. Clear
	// filesystem specific options.
	upperOpts := *lowerOpts
	upperOpts.GetFilesystemOptions = vfs.GetFilesystemOptions{}

	overlayOpts := *lowerOpts
	overlayOpts.GetFilesystemOptions = vfs.GetFilesystemOptions{}

	// All writes go to the upper layer, be paranoid and make lower readonly.
	lowerOpts.ReadOnly = true
	lower, err := c.k.VFS().MountDisconnected(ctx, creds, "" /* source */, lowerFSName, lowerOpts)
	if err != nil {
		return nil, nil, err
	}
	cu := cleanup.Make(func() { lower.DecRef(ctx) })
	defer cu.Clean()

	// Determine the lower layer's root's type.
	lowerRootVD := vfs.MakeVirtualDentry(lower, lower.Root())
	stat, err := c.k.VFS().StatAt(ctx, creds, &vfs.PathOperation{
		Root:  lowerRootVD,
		Start: lowerRootVD,
	}, &vfs.StatOptions{
		Mask: linux.STATX_UID | linux.STATX_GID | linux.STATX_MODE | linux.STATX_TYPE,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to stat lower layer's root: %v", err)
	}
	if stat.Mask&linux.STATX_TYPE == 0 {
		return nil, nil, fmt.Errorf("failed to get file type of lower layer's root")
	}
	rootType := stat.Mode & linux.S_IFMT
	if rootType != linux.S_IFDIR && rootType != linux.S_IFREG {
		return nil, nil, fmt.Errorf("lower layer's root has unsupported file type %v", rootType)
	}

	// Upper is a tmpfs mount to keep all modifications inside the sandbox.
	tmpfsOpts := tmpfs.FilesystemOpts{
		RootFileType: uint16(rootType),
	}
	overlay2 := conf.GetOverlay2()
	if useFilestoreFD != nil && useFilestoreFD(overlay2, rootType == linux.S_IFDIR) {
		tmpfsOpts.FilestoreFD = c.overlayFilestoreFDs.removeAsFD()
	}
	upperOpts.GetFilesystemOptions.InternalData = tmpfsOpts
	upper, err := c.k.VFS().MountDisconnected(ctx, creds, "" /* source */, tmpfs.Name, &upperOpts)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create upper layer for overlay, opts: %+v: %v", upperOpts, err)
	}
	cu.Add(func() { upper.DecRef(ctx) })

	// If the overlay mount consists of a regular file, copy up its contents
	// from the lower layer, since in the overlay the otherwise-empty upper
	// layer file will take precedence.
	upperRootVD := vfs.MakeVirtualDentry(upper, upper.Root())
	if rootType == linux.S_IFREG {
		lowerFD, err := c.k.VFS().OpenAt(ctx, creds, &vfs.PathOperation{
			Root:  lowerRootVD,
			Start: lowerRootVD,
		}, &vfs.OpenOptions{
			Flags: linux.O_RDONLY,
		})
		if err != nil {
			return nil, nil, fmt.Errorf("failed to open lower layer root for copying: %v", err)
		}
		defer lowerFD.DecRef(ctx)
		upperFD, err := c.k.VFS().OpenAt(ctx, creds, &vfs.PathOperation{
			Root:  upperRootVD,
			Start: upperRootVD,
		}, &vfs.OpenOptions{
			Flags: linux.O_WRONLY,
		})
		if err != nil {
			return nil, nil, fmt.Errorf("failed to open upper layer root for copying: %v", err)
		}
		defer upperFD.DecRef(ctx)
		if _, err := vfs.CopyRegularFileData(ctx, upperFD, lowerFD); err != nil {
			return nil, nil, fmt.Errorf("failed to copy up overlay file: %v", err)
		}
	}

	// If host filestore is being used and it is backed by self, then we need to
	// hide the filestore from the containerized application.
	if overlay2.IsBackedBySelf() && useFilestoreFD != nil && useFilestoreFD(overlay2, rootType == linux.S_IFDIR) {
		if err := overlay.CreateWhiteout(ctx, c.k.VFS(), creds, &vfs.PathOperation{
			Root:  upperRootVD,
			Start: upperRootVD,
			Path:  fspath.Parse(selfOverlayFilestoreName(c.sandboxID)),
		}); err != nil {
			return nil, nil, fmt.Errorf("failed to create whiteout to hide self overlay filestore: %w", err)
		}
	}

	// Propagate the lower layer's root's owner, group, and mode to the upper
	// layer's root for consistency with VFS1.
	err = c.k.VFS().SetStatAt(ctx, creds, &vfs.PathOperation{
		Root:  upperRootVD,
		Start: upperRootVD,
	}, &vfs.SetStatOptions{
		Stat: linux.Statx{
			Mask: (linux.STATX_UID | linux.STATX_GID | linux.STATX_MODE) & stat.Mask,
			UID:  stat.UID,
			GID:  stat.GID,
			Mode: stat.Mode,
		},
	})
	if err != nil {
		return nil, nil, err
	}

	// Configure overlay with both layers.
	overlayOpts.GetFilesystemOptions.InternalData = overlay.FilesystemOptions{
		UpperRoot:  upperRootVD,
		LowerRoots: []vfs.VirtualDentry{lowerRootVD},
	}
	return &overlayOpts, cu.Release(), nil
}

func (c *containerMounter) mountSubmounts(ctx context.Context, conf *config.Config, mns *vfs.MountNamespace, creds *auth.Credentials) error {
	mounts, err := c.prepareMounts()
	if err != nil {
		return err
	}

	for i := range mounts {
		submount := &mounts[i]
		log.Debugf("Mounting %q to %q, type: %s, options: %s", submount.mount.Source, submount.mount.Destination, submount.mount.Type, submount.mount.Options)
		var (
			mnt *vfs.Mount
			err error
		)

		if hint := c.hints.findMount(submount.mount); hint != nil && hint.isSupported() {
			mnt, err = c.mountSharedSubmount(ctx, conf, mns, creds, submount.mount, hint)
			if err != nil {
				return fmt.Errorf("mount shared mount %q to %q: %v", hint.name, submount.mount.Destination, err)
			}
		} else {
			mnt, err = c.mountSubmount(ctx, conf, mns, creds, submount)
			if err != nil {
				return fmt.Errorf("mount submount %q: %w", submount.mount.Destination, err)
			}
		}

		if mnt != nil && mnt.ReadOnly() {
			// Switch to ReadWrite while we setup submounts.
			if err := c.k.VFS().SetMountReadOnly(mnt, false); err != nil {
				return fmt.Errorf("failed to set mount at %q readwrite: %w", submount.mount.Destination, err)
			}
			// Restore back to ReadOnly at the end.
			defer func() {
				if err := c.k.VFS().SetMountReadOnly(mnt, true); err != nil {
					panic(fmt.Sprintf("failed to restore mount at %q back to readonly: %v", submount.mount.Destination, err))
				}
			}()
		}
	}

	if err := c.mountTmp(ctx, conf, creds, mns); err != nil {
		return fmt.Errorf(`mount submount "\tmp": %w`, err)
	}
	return nil
}

type mountAndFD struct {
	mount *specs.Mount
	fd    int
}

func newNonGoferMountAndFD(mnt *specs.Mount) *mountAndFD {
	return &mountAndFD{mount: mnt, fd: -1}
}

func (c *containerMounter) prepareMounts() ([]mountAndFD, error) {
	// Associate bind mounts with their FDs before sorting since there is an
	// undocumented assumption that FDs are dispensed in the order in which
	// they are required by mounts.
	var mounts []mountAndFD
	for i := range c.mounts {
		m := &c.mounts[i]
		specutils.MaybeConvertToBindMount(m)

		// Only bind mounts use host FDs; see
		// containerMounter.getMountNameAndOptions.
		fd := -1
		if m.Type == Bind {
			fd = c.fds.remove()
		}
		mounts = append(mounts, mountAndFD{
			mount: m,
			fd:    fd,
		})
	}
	if err := c.checkDispenser(); err != nil {
		return nil, err
	}

	// Sort the mounts so that we don't place children before parents.
	sort.Slice(mounts, func(i, j int) bool {
		return len(mounts[i].mount.Destination) < len(mounts[j].mount.Destination)
	})

	return mounts, nil
}

func (c *containerMounter) mountSubmount(ctx context.Context, conf *config.Config, mns *vfs.MountNamespace, creds *auth.Credentials, submount *mountAndFD) (*vfs.Mount, error) {
	fsName, opts, useOverlay, err := c.getMountNameAndOptions(conf, submount)
	if err != nil {
		return nil, fmt.Errorf("mountOptions failed: %w", err)
	}
	if len(fsName) == 0 {
		// Filesystem is not supported (e.g. cgroup), just skip it.
		return nil, nil
	}

	if err := c.makeMountPoint(ctx, creds, mns, submount.mount.Destination); err != nil {
		return nil, fmt.Errorf("creating mount point %q: %w", submount.mount.Destination, err)
	}

	if useOverlay {
		log.Infof("Adding overlay on top of mount %q", submount.mount.Destination)
		var cleanup func()
		opts, cleanup, err = c.configureOverlay(ctx, conf, creds, opts, fsName, useOverlayFilestoreFD)
		if err != nil {
			return nil, fmt.Errorf("mounting volume with overlay at %q: %w", submount.mount.Destination, err)
		}
		defer cleanup()
		fsName = overlay.Name
	}

	root := mns.Root()
	root.IncRef()
	defer root.DecRef(ctx)
	target := &vfs.PathOperation{
		Root:  root,
		Start: root,
		Path:  fspath.Parse(submount.mount.Destination),
	}
	mnt, err := c.k.VFS().MountAt(ctx, creds, "", target, fsName, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to mount %q (type: %s): %w, opts: %v", submount.mount.Destination, submount.mount.Type, err, opts)
	}
	log.Infof("Mounted %q to %q type: %s, internal-options: %q", submount.mount.Source, submount.mount.Destination, submount.mount.Type, opts.GetFilesystemOptions.Data)
	return mnt, nil
}

// getMountNameAndOptions retrieves the fsName, opts, and useOverlay values
// used for mounts.
func (c *containerMounter) getMountNameAndOptions(conf *config.Config, m *mountAndFD) (string, *vfs.MountOptions, bool, error) {
	fsName := m.mount.Type
	useOverlay := false
	var (
		data         []string
		internalData any
	)

	// Find filesystem name and FS specific data field.
	switch m.mount.Type {
	case devpts.Name, devtmpfs.Name, proc.Name:
		// Nothing to do.

	case Nonefs:
		fsName = sys.Name

	case sys.Name:
		if len(c.productName) > 0 {
			internalData = &sys.InternalData{ProductName: c.productName}
		}

	case tmpfs.Name:
		var err error
		data, err = parseAndFilterOptions(m.mount.Options, tmpfsAllowedData...)
		if err != nil {
			return "", nil, false, err
		}

	case Bind:
		fsName = gofer.Name
		if m.fd < 0 {
			// Check that an FD was provided to fails fast.
			return "", nil, false, fmt.Errorf("gofer mount requires a connection FD")
		}
		data = goferMountData(m.fd, c.getMountAccessType(conf, m.mount), conf)
		internalData = gofer.InternalFilesystemOptions{
			UniqueID: m.mount.Destination,
		}

		// If configured, add overlay to all writable mounts.
		useOverlay = conf.GetOverlay2().SubMounts && !ParseMountOptions(m.mount.Options).ReadOnly

	case cgroupfs.Name:
		var err error
		data, err = parseAndFilterOptions(m.mount.Options, cgroupfs.SupportedMountOptions...)
		if err != nil {
			return "", nil, false, err
		}

	default:
		log.Warningf("ignoring unknown filesystem type %q", m.mount.Type)
		return "", nil, false, nil
	}

	opts := ParseMountOptions(m.mount.Options)
	opts.GetFilesystemOptions = vfs.GetFilesystemOptions{
		Data:         strings.Join(data, ","),
		InternalData: internalData,
	}

	return fsName, opts, useOverlay, nil
}

// ParseMountOptions converts specs.Mount.Options to vfs.MountOptions.
func ParseMountOptions(opts []string) *vfs.MountOptions {
	mountOpts := &vfs.MountOptions{
		InternalMount: true,
	}
	// Note: update mountHint.CheckCompatible when more options are added.
	for _, o := range opts {
		switch o {
		case "ro":
			mountOpts.ReadOnly = true
		case "noatime":
			mountOpts.Flags.NoATime = true
		case "noexec":
			mountOpts.Flags.NoExec = true
		case "rw", "atime", "exec":
			// These use the default value and don't need to be set.
		case "bind", "rbind":
			// These are the same as a mount with type="bind".
		default:
			log.Warningf("ignoring unknown mount option %q", o)
		}
	}
	return mountOpts
}

func parseKeyValue(s string) (string, string, bool) {
	tokens := strings.SplitN(s, "=", 2)
	if len(tokens) < 2 {
		return "", "", false
	}
	return strings.TrimSpace(tokens[0]), strings.TrimSpace(tokens[1]), true
}

// mountTmp mounts an internal tmpfs at '/tmp' if it's safe to do so.
// Technically we don't have to mount tmpfs at /tmp, as we could just rely on
// the host /tmp, but this is a nice optimization, and fixes some apps that call
// mknod in /tmp. It's unsafe to mount tmpfs if:
//  1. /tmp is mounted explicitly: we should not override user's wish
//  2. /tmp is not empty: mounting tmpfs would hide existing files in /tmp
//
// Note that when there are submounts inside of '/tmp', directories for the
// mount points must be present, making '/tmp' not empty anymore.
func (c *containerMounter) mountTmp(ctx context.Context, conf *config.Config, creds *auth.Credentials, mns *vfs.MountNamespace) error {
	for _, m := range c.mounts {
		// m.Destination has been cleaned, so it's to use equality here.
		if m.Destination == "/tmp" {
			log.Debugf(`Explict "/tmp" mount found, skipping internal tmpfs, mount: %+v`, m)
			return nil
		}
	}

	root := mns.Root()
	root.IncRef()
	defer root.DecRef(ctx)
	pop := vfs.PathOperation{
		Root:  root,
		Start: root,
		Path:  fspath.Parse("/tmp"),
	}
	fd, err := c.k.VFS().OpenAt(ctx, creds, &pop, &vfs.OpenOptions{Flags: linux.O_RDONLY | linux.O_DIRECTORY})
	switch {
	case err == nil:
		defer fd.DecRef(ctx)

		err := fd.IterDirents(ctx, vfs.IterDirentsCallbackFunc(func(dirent vfs.Dirent) error {
			if dirent.Name != "." && dirent.Name != ".." {
				return linuxerr.ENOTEMPTY
			}
			return nil
		}))
		switch {
		case err == nil:
			log.Infof(`Mounting internal tmpfs on top of empty "/tmp"`)
		case linuxerr.Equals(linuxerr.ENOTEMPTY, err):
			// If more than "." and ".." is found, skip internal tmpfs to prevent
			// hiding existing files.
			log.Infof(`Skipping internal tmpfs mount for "/tmp" because it's not empty`)
			return nil
		default:
			return fmt.Errorf("fd.IterDirents failed: %v", err)
		}
		fallthrough

	case linuxerr.Equals(linuxerr.ENOENT, err):
		// No '/tmp' found (or fallthrough from above). It's safe to mount internal
		// tmpfs.
		tmpMount := specs.Mount{
			Type:        tmpfs.Name,
			Destination: "/tmp",
			// Sticky bit is added to prevent accidental deletion of files from
			// another user. This is normally done for /tmp.
			Options: []string{"mode=01777"},
		}
		if _, err := c.mountSubmount(ctx, conf, mns, creds, newNonGoferMountAndFD(&tmpMount)); err != nil {
			return fmt.Errorf("mountSubmount failed: %v", err)
		}
		return nil

	case linuxerr.Equals(linuxerr.ENOTDIR, err):
		// Not a dir?! Let it be.
		return nil

	default:
		return fmt.Errorf(`opening "/tmp" inside container: %w`, err)
	}
}

// processHints processes annotations that container hints about how volumes
// should be mounted (e.g. a volume shared between containers). It must be
// called for the root container only.
func (c *containerMounter) processHints(conf *config.Config, creds *auth.Credentials) error {
	ctx := c.k.SupervisorContext()
	for _, hint := range c.hints.mounts {
		if !hint.isSupported() {
			continue
		}

		log.Infof("Mounting master of shared mount %q from %q type %q", hint.name, hint.mount.Source, hint.mount.Type)
		mnt, err := c.mountSharedMaster(ctx, conf, hint, creds)
		if err != nil {
			return fmt.Errorf("mounting shared master %q: %v", hint.name, err)
		}
		hint.vfsMount = mnt
	}
	return nil
}

// mountSharedMaster mounts the master of a volume that is shared among
// containers in a pod.
func (c *containerMounter) mountSharedMaster(ctx context.Context, conf *config.Config, hint *mountHint, creds *auth.Credentials) (*vfs.Mount, error) {
	// Map mount type to filesystem name, and parse out the options that we are
	// capable of dealing with.
	mntFD := newNonGoferMountAndFD(&hint.mount)
	fsName, opts, useOverlay, err := c.getMountNameAndOptions(conf, mntFD)
	if err != nil {
		return nil, err
	}
	if len(fsName) == 0 {
		return nil, fmt.Errorf("mount type not supported %q", hint.mount.Type)
	}

	if useOverlay {
		log.Infof("Adding overlay on top of shared mount %q", mntFD.mount.Destination)
		var cleanup func()
		// TODO(b/142076984): Use an overlay for a shared EmptyDir mount. Such a
		// mount should be backed by a self filestore, so limits can be enforced
		// by k8s on the host. For now pass nil for useFilestoreFD.
		opts, cleanup, err = c.configureOverlay(ctx, conf, creds, opts, fsName, nil /* useFilestoreFD */)
		if err != nil {
			return nil, fmt.Errorf("mounting shared volume with overlay at %q: %w", mntFD.mount.Destination, err)
		}
		defer cleanup()
		fsName = overlay.Name
	}

	return c.k.VFS().MountDisconnected(ctx, creds, "", fsName, opts)
}

// mountSharedSubmount binds mount to a previously mounted volume that is shared
// among containers in the same pod.
func (c *containerMounter) mountSharedSubmount(ctx context.Context, conf *config.Config, mns *vfs.MountNamespace, creds *auth.Credentials, mount *specs.Mount, source *mountHint) (*vfs.Mount, error) {
	if err := source.checkCompatible(mount); err != nil {
		return nil, err
	}

	// Ignore data and useOverlay because these were already applied to
	// the master mount.
	_, opts, _, err := c.getMountNameAndOptions(conf, newNonGoferMountAndFD(mount))
	if err != nil {
		return nil, err
	}
	newMnt := c.k.VFS().NewDisconnectedMount(source.vfsMount.Filesystem(), source.vfsMount.Root(), opts)
	defer newMnt.DecRef(ctx)

	root := mns.Root()
	root.IncRef()
	defer root.DecRef(ctx)
	target := &vfs.PathOperation{
		Root:  root,
		Start: root,
		Path:  fspath.Parse(mount.Destination),
	}

	if err := c.makeMountPoint(ctx, creds, mns, mount.Destination); err != nil {
		return nil, fmt.Errorf("creating mount point %q: %w", mount.Destination, err)
	}

	if err := c.k.VFS().ConnectMountAt(ctx, creds, newMnt, target); err != nil {
		return nil, err
	}
	log.Infof("Mounted %q type shared bind to %q", mount.Destination, source.name)
	return newMnt, nil
}

func (c *containerMounter) makeMountPoint(ctx context.Context, creds *auth.Credentials, mns *vfs.MountNamespace, dest string) error {
	root := mns.Root()
	root.IncRef()
	defer root.DecRef(ctx)
	target := &vfs.PathOperation{
		Root:  root,
		Start: root,
		Path:  fspath.Parse(dest),
	}
	// First check if mount point exists. When overlay is enabled, gofer doesn't
	// allow changes to the FS, making MakeSytheticMountpoint() ineffective
	// because MkdirAt fails with EROFS even if file exists.
	vd, err := c.k.VFS().GetDentryAt(ctx, creds, target, &vfs.GetDentryOptions{})
	if err == nil {
		// File exists, we're done.
		vd.DecRef(ctx)
		return nil
	}
	return c.k.VFS().MakeSyntheticMountpoint(ctx, dest, root, creds)
}

// configureRestore returns an updated context.Context including filesystem
// state used by restore defined by conf.
func (c *containerMounter) configureRestore(ctx context.Context) (context.Context, error) {
	fdmap := make(map[string]int)
	fdmap["/"] = c.fds.remove()
	mounts, err := c.prepareMounts()
	if err != nil {
		return ctx, err
	}
	for i := range c.mounts {
		submount := &mounts[i]
		if submount.fd >= 0 {
			fdmap[submount.mount.Destination] = submount.fd
		}
	}
	return context.WithValue(ctx, gofer.CtxRestoreServerFDMap, fdmap), nil
}

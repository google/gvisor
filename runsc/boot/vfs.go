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
	"sort"
	"strings"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/cleanup"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/fspath"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/devices/memdev"
	"gvisor.dev/gvisor/pkg/sentry/devices/ttydev"
	"gvisor.dev/gvisor/pkg/sentry/devices/tundev"
	"gvisor.dev/gvisor/pkg/sentry/fs/user"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/devpts"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/devtmpfs"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/fuse"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/gofer"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/overlay"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/proc"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/sys"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/tmpfs"
	"gvisor.dev/gvisor/pkg/sentry/inet"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/syserror"
	"gvisor.dev/gvisor/runsc/config"
)

func registerFilesystems(k *kernel.Kernel) error {
	ctx := k.SupervisorContext()
	creds := auth.NewRootCredentials(k.RootUserNamespace())
	vfsObj := k.VFS()

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
	vfsObj.MustRegisterFilesystemType(fuse.Name, &fuse.FilesystemType{}, &vfs.RegisterFilesystemTypeOptions{
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

	if kernel.FUSEEnabled {
		if err := fuse.Register(vfsObj); err != nil {
			return fmt.Errorf("registering fusedev: %w", err)
		}
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

	if kernel.FUSEEnabled {
		if err := fuse.CreateDevtmpfsFile(ctx, a); err != nil {
			return fmt.Errorf("creating fusedev devtmpfs files: %w", err)
		}
	}

	return nil
}

func setupContainerVFS2(ctx context.Context, conf *config.Config, mntr *containerMounter, procArgs *kernel.CreateProcessArgs) error {
	mns, err := mntr.mountAll(conf, procArgs)
	if err != nil {
		return fmt.Errorf("failed to setupFS: %w", err)
	}
	procArgs.MountNamespaceVFS2 = mns

	// Resolve the executable path from working dir and environment.
	resolved, err := user.ResolveExecutablePath(ctx, procArgs)
	if err != nil {
		return err
	}
	procArgs.Filename = resolved
	return nil
}

func (c *containerMounter) mountAll(conf *config.Config, procArgs *kernel.CreateProcessArgs) (*vfs.MountNamespace, error) {
	log.Infof("Configuring container's file system with VFS2")

	// Create context with root credentials to mount the filesystem (the current
	// user may not be privileged enough).
	rootCreds := auth.NewRootCredentials(procArgs.Credentials.UserNamespace)
	rootProcArgs := *procArgs
	rootProcArgs.WorkingDirectory = "/"
	rootProcArgs.Credentials = rootCreds
	rootProcArgs.Umask = 0022
	rootProcArgs.MaxSymlinkTraversals = linux.MaxSymlinkTraversals
	rootCtx := procArgs.NewContext(c.k)

	mns, err := c.createMountNamespaceVFS2(rootCtx, conf, rootCreds)
	if err != nil {
		return nil, fmt.Errorf("creating mount namespace: %w", err)
	}
	rootProcArgs.MountNamespaceVFS2 = mns

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
	if err := c.mountSubmountsVFS2(rootCtx, conf, mns, rootCreds); err != nil {
		return nil, fmt.Errorf("mounting submounts vfs2: %w", err)
	}

	return mns, nil
}

// createMountNamespaceVFS2 creates the container's root mount and namespace.
func (c *containerMounter) createMountNamespaceVFS2(ctx context.Context, conf *config.Config, creds *auth.Credentials) (*vfs.MountNamespace, error) {
	fd := c.fds.remove()
	data := p9MountData(fd, conf.FileAccess, true /* vfs2 */)

	if conf.OverlayfsStaleRead {
		// We can't check for overlayfs here because sandbox is chroot'ed and gofer
		// can only send mount options for specs.Mounts (specs.Root is missing
		// Options field). So assume root is always on top of overlayfs.
		data = append(data, "overlayfs_stale_read")
	}

	log.Infof("Mounting root over 9P, ioFD: %d", fd)
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
	if conf.Overlay && !c.root.Readonly {
		log.Infof("Adding overlay on top of root")
		var err error
		var cleanup func()
		opts, cleanup, err = c.configureOverlay(ctx, creds, opts, fsName)
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

// configureOverlay mounts the lower layer using "lowerOpts", mounts the upper
// layer using tmpfs, and return overlay mount options. "cleanup" must be called
// after the options have been used to mount the overlay, to release refs on
// lower and upper mounts.
func (c *containerMounter) configureOverlay(ctx context.Context, creds *auth.Credentials, lowerOpts *vfs.MountOptions, lowerFSName string) (*vfs.MountOptions, func(), error) {
	// First copy options from lower layer to upper layer and overlay. Clear
	// filesystem specific options.
	upperOpts := *lowerOpts
	upperOpts.GetFilesystemOptions = vfs.GetFilesystemOptions{}

	overlayOpts := *lowerOpts
	overlayOpts.GetFilesystemOptions = vfs.GetFilesystemOptions{}

	// Next mount upper and lower. Upper is a tmpfs mount to keep all
	// modifications inside the sandbox.
	upper, err := c.k.VFS().MountDisconnected(ctx, creds, "" /* source */, tmpfs.Name, &upperOpts)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create upper layer for overlay, opts: %+v: %v", upperOpts, err)
	}
	cu := cleanup.Make(func() { upper.DecRef(ctx) })
	defer cu.Clean()

	// All writes go to the upper layer, be paranoid and make lower readonly.
	lowerOpts.ReadOnly = true
	lower, err := c.k.VFS().MountDisconnected(ctx, creds, "" /* source */, lowerFSName, lowerOpts)
	if err != nil {
		return nil, nil, err
	}
	cu.Add(func() { lower.DecRef(ctx) })

	// Propagate the lower layer's root's owner, group, and mode to the upper
	// layer's root for consistency with VFS1.
	upperRootVD := vfs.MakeVirtualDentry(upper, upper.Root())
	lowerRootVD := vfs.MakeVirtualDentry(lower, lower.Root())
	stat, err := c.k.VFS().StatAt(ctx, creds, &vfs.PathOperation{
		Root:  lowerRootVD,
		Start: lowerRootVD,
	}, &vfs.StatOptions{
		Mask: linux.STATX_UID | linux.STATX_GID | linux.STATX_MODE,
	})
	if err != nil {
		return nil, nil, err
	}
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

func (c *containerMounter) mountSubmountsVFS2(ctx context.Context, conf *config.Config, mns *vfs.MountNamespace, creds *auth.Credentials) error {
	mounts, err := c.prepareMountsVFS2()
	if err != nil {
		return err
	}

	for i := range mounts {
		submount := &mounts[i]
		log.Debugf("Mounting %q to %q, type: %s, options: %s", submount.Source, submount.Destination, submount.Type, submount.Options)
		var (
			mnt *vfs.Mount
			err error
		)

		if hint := c.hints.findMount(submount.Mount); hint != nil && hint.isSupported() {
			mnt, err = c.mountSharedSubmountVFS2(ctx, conf, mns, creds, submount.Mount, hint)
			if err != nil {
				return fmt.Errorf("mount shared mount %q to %q: %v", hint.name, submount.Destination, err)
			}
		} else {
			mnt, err = c.mountSubmountVFS2(ctx, conf, mns, creds, submount)
			if err != nil {
				return fmt.Errorf("mount submount %q: %w", submount.Destination, err)
			}
		}

		if mnt != nil && mnt.ReadOnly() {
			// Switch to ReadWrite while we setup submounts.
			if err := c.k.VFS().SetMountReadOnly(mnt, false); err != nil {
				return fmt.Errorf("failed to set mount at %q readwrite: %w", submount.Destination, err)
			}
			// Restore back to ReadOnly at the end.
			defer func() {
				if err := c.k.VFS().SetMountReadOnly(mnt, true); err != nil {
					panic(fmt.Sprintf("failed to restore mount at %q back to readonly: %v", submount.Destination, err))
				}
			}()
		}
	}

	if err := c.mountTmpVFS2(ctx, conf, creds, mns); err != nil {
		return fmt.Errorf(`mount submount "\tmp": %w`, err)
	}
	return nil
}

type mountAndFD struct {
	specs.Mount
	fd int
}

func (c *containerMounter) prepareMountsVFS2() ([]mountAndFD, error) {
	// Associate bind mounts with their FDs before sorting since there is an
	// undocumented assumption that FDs are dispensed in the order in which
	// they are required by mounts.
	var mounts []mountAndFD
	for _, m := range c.mounts {
		fd := -1
		// Only bind mounts use host FDs; see
		// containerMounter.getMountNameAndOptionsVFS2.
		if m.Type == bind {
			fd = c.fds.remove()
		}
		mounts = append(mounts, mountAndFD{
			Mount: m,
			fd:    fd,
		})
	}
	if err := c.checkDispenser(); err != nil {
		return nil, err
	}

	// Sort the mounts so that we don't place children before parents.
	sort.Slice(mounts, func(i, j int) bool {
		return len(mounts[i].Destination) < len(mounts[j].Destination)
	})

	return mounts, nil
}

func (c *containerMounter) mountSubmountVFS2(ctx context.Context, conf *config.Config, mns *vfs.MountNamespace, creds *auth.Credentials, submount *mountAndFD) (*vfs.Mount, error) {
	fsName, opts, useOverlay, err := c.getMountNameAndOptionsVFS2(conf, submount)
	if err != nil {
		return nil, fmt.Errorf("mountOptions failed: %w", err)
	}
	if len(fsName) == 0 {
		// Filesystem is not supported (e.g. cgroup), just skip it.
		return nil, nil
	}

	if err := c.makeMountPoint(ctx, creds, mns, submount.Destination); err != nil {
		return nil, fmt.Errorf("creating mount point %q: %w", submount.Destination, err)
	}

	if useOverlay {
		log.Infof("Adding overlay on top of mount %q", submount.Destination)
		var cleanup func()
		opts, cleanup, err = c.configureOverlay(ctx, creds, opts, fsName)
		if err != nil {
			return nil, fmt.Errorf("mounting volume with overlay at %q: %w", submount.Destination, err)
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
		Path:  fspath.Parse(submount.Destination),
	}
	mnt, err := c.k.VFS().MountAt(ctx, creds, "", target, fsName, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to mount %q (type: %s): %w, opts: %v", submount.Destination, submount.Type, err, opts)
	}
	log.Infof("Mounted %q to %q type: %s, internal-options: %q", submount.Source, submount.Destination, submount.Type, opts.GetFilesystemOptions.Data)
	return mnt, nil
}

// getMountNameAndOptionsVFS2 retrieves the fsName, opts, and useOverlay values
// used for mounts.
func (c *containerMounter) getMountNameAndOptionsVFS2(conf *config.Config, m *mountAndFD) (string, *vfs.MountOptions, bool, error) {
	fsName := m.Type
	useOverlay := false
	var data []string
	var iopts interface{}

	// Find filesystem name and FS specific data field.
	switch m.Type {
	case devpts.Name, devtmpfs.Name, proc.Name, sys.Name:
		// Nothing to do.

	case nonefs:
		fsName = sys.Name

	case tmpfs.Name:
		var err error
		data, err = parseAndFilterOptions(m.Options, tmpfsAllowedData...)
		if err != nil {
			return "", nil, false, err
		}

	case bind:
		fsName = gofer.Name
		if m.fd == 0 {
			// Check that an FD was provided to fails fast. Technically FD=0 is valid,
			// but unlikely to be correct in this context.
			return "", nil, false, fmt.Errorf("9P mount requires a connection FD")
		}
		data = p9MountData(m.fd, c.getMountAccessType(m.Mount), true /* vfs2 */)
		iopts = gofer.InternalFilesystemOptions{
			UniqueID: m.Destination,
		}

		// If configured, add overlay to all writable mounts.
		useOverlay = conf.Overlay && !mountFlags(m.Options).ReadOnly

	default:
		log.Warningf("ignoring unknown filesystem type %q", m.Type)
		return "", nil, false, nil
	}

	opts := &vfs.MountOptions{
		GetFilesystemOptions: vfs.GetFilesystemOptions{
			Data:         strings.Join(data, ","),
			InternalData: iopts,
		},
		InternalMount: true,
	}

	for _, o := range m.Options {
		switch o {
		case "rw":
			opts.ReadOnly = false
		case "ro":
			opts.ReadOnly = true
		case "noatime":
			opts.Flags.NoATime = true
		case "noexec":
			opts.Flags.NoExec = true
		default:
			log.Warningf("ignoring unknown mount option %q", o)
		}
	}

	return fsName, opts, useOverlay, nil
}

// mountTmpVFS2 mounts an internal tmpfs at '/tmp' if it's safe to do so.
// Technically we don't have to mount tmpfs at /tmp, as we could just rely on
// the host /tmp, but this is a nice optimization, and fixes some apps that call
// mknod in /tmp. It's unsafe to mount tmpfs if:
//   1. /tmp is mounted explicitly: we should not override user's wish
//   2. /tmp is not empty: mounting tmpfs would hide existing files in /tmp
//
// Note that when there are submounts inside of '/tmp', directories for the
// mount points must be present, making '/tmp' not empty anymore.
func (c *containerMounter) mountTmpVFS2(ctx context.Context, conf *config.Config, creds *auth.Credentials, mns *vfs.MountNamespace) error {
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
	// TODO(gvisor.dev/issue/2782): Use O_PATH when available.
	fd, err := c.k.VFS().OpenAt(ctx, creds, &pop, &vfs.OpenOptions{Flags: linux.O_RDONLY | linux.O_DIRECTORY})
	switch err {
	case nil:
		defer fd.DecRef(ctx)

		err := fd.IterDirents(ctx, vfs.IterDirentsCallbackFunc(func(dirent vfs.Dirent) error {
			if dirent.Name != "." && dirent.Name != ".." {
				return syserror.ENOTEMPTY
			}
			return nil
		}))
		switch err {
		case nil:
			log.Infof(`Mounting internal tmpfs on top of empty "/tmp"`)
		case syserror.ENOTEMPTY:
			// If more than "." and ".." is found, skip internal tmpfs to prevent
			// hiding existing files.
			log.Infof(`Skipping internal tmpfs mount for "/tmp" because it's not empty`)
			return nil
		default:
			return err
		}
		fallthrough

	case syserror.ENOENT:
		// No '/tmp' found (or fallthrough from above). It's safe to mount internal
		// tmpfs.
		tmpMount := specs.Mount{
			Type:        tmpfs.Name,
			Destination: "/tmp",
			// Sticky bit is added to prevent accidental deletion of files from
			// another user. This is normally done for /tmp.
			Options: []string{"mode=01777"},
		}
		_, err := c.mountSubmountVFS2(ctx, conf, mns, creds, &mountAndFD{Mount: tmpMount})
		return err

	case syserror.ENOTDIR:
		// Not a dir?! Let it be.
		return nil

	default:
		return fmt.Errorf(`opening "/tmp" inside container: %w`, err)
	}
}

// processHintsVFS2 processes annotations that container hints about how volumes
// should be mounted (e.g. a volume shared between containers). It must be
// called for the root container only.
func (c *containerMounter) processHintsVFS2(conf *config.Config, creds *auth.Credentials) error {
	ctx := c.k.SupervisorContext()
	for _, hint := range c.hints.mounts {
		// TODO(b/142076984): Only support tmpfs for now. Bind mounts require a
		// common gofer to mount all shared volumes.
		if hint.mount.Type != tmpfs.Name {
			continue
		}

		log.Infof("Mounting master of shared mount %q from %q type %q", hint.name, hint.mount.Source, hint.mount.Type)
		mnt, err := c.mountSharedMasterVFS2(ctx, conf, hint, creds)
		if err != nil {
			return fmt.Errorf("mounting shared master %q: %v", hint.name, err)
		}
		hint.vfsMount = mnt
	}
	return nil
}

// mountSharedMasterVFS2 mounts the master of a volume that is shared among
// containers in a pod.
func (c *containerMounter) mountSharedMasterVFS2(ctx context.Context, conf *config.Config, hint *mountHint, creds *auth.Credentials) (*vfs.Mount, error) {
	// Map mount type to filesystem name, and parse out the options that we are
	// capable of dealing with.
	mntFD := &mountAndFD{Mount: hint.mount}
	fsName, opts, useOverlay, err := c.getMountNameAndOptionsVFS2(conf, mntFD)
	if err != nil {
		return nil, err
	}
	if len(fsName) == 0 {
		return nil, fmt.Errorf("mount type not supported %q", hint.mount.Type)
	}

	if useOverlay {
		log.Infof("Adding overlay on top of shared mount %q", mntFD.Destination)
		var cleanup func()
		opts, cleanup, err = c.configureOverlay(ctx, creds, opts, fsName)
		if err != nil {
			return nil, fmt.Errorf("mounting shared volume with overlay at %q: %w", mntFD.Destination, err)
		}
		defer cleanup()
		fsName = overlay.Name
	}

	return c.k.VFS().MountDisconnected(ctx, creds, "", fsName, opts)
}

// mountSharedSubmount binds mount to a previously mounted volume that is shared
// among containers in the same pod.
func (c *containerMounter) mountSharedSubmountVFS2(ctx context.Context, conf *config.Config, mns *vfs.MountNamespace, creds *auth.Credentials, mount specs.Mount, source *mountHint) (*vfs.Mount, error) {
	if err := source.checkCompatible(mount); err != nil {
		return nil, err
	}

	// Ignore data and useOverlay because these were already applied to
	// the master mount.
	_, opts, _, err := c.getMountNameAndOptionsVFS2(conf, &mountAndFD{Mount: mount})
	if err != nil {
		return nil, err
	}
	newMnt, err := c.k.VFS().NewDisconnectedMount(source.vfsMount.Filesystem(), source.vfsMount.Root(), opts)
	if err != nil {
		return nil, err
	}
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
func (c *containerMounter) configureRestore(ctx context.Context, conf *config.Config) (context.Context, error) {
	fdmap := make(map[string]int)
	fdmap["/"] = c.fds.remove()
	mounts, err := c.prepareMountsVFS2()
	if err != nil {
		return ctx, err
	}
	for i := range c.mounts {
		submount := &mounts[i]
		if submount.fd >= 0 {
			fdmap[submount.Destination] = submount.fd
		}
	}
	return context.WithValue(ctx, gofer.CtxRestoreServerFDMap, fdmap), nil
}

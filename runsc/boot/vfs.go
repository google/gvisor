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
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/cgroupfs"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/devpts"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/devtmpfs"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/fuse"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/gofer"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/overlay"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/proc"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/sys"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/tmpfs"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/verity"
	"gvisor.dev/gvisor/pkg/sentry/inet"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/syserror"
	"gvisor.dev/gvisor/runsc/config"
	"gvisor.dev/gvisor/runsc/specutils"
)

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
	vfsObj.MustRegisterFilesystemType(verity.Name, &verity.FilesystemType{}, &vfs.RegisterFilesystemTypeOptions{
		AllowUserList:  true,
		AllowUserMount: true,
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

	// We can't check for overlayfs here because sandbox is chroot'ed and gofer
	// can only send mount options for specs.Mounts (specs.Root is missing
	// Options field). So assume root is always on top of overlayfs.
	data = append(data, "overlayfs_stale_read")

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
	upperOpts.GetFilesystemOptions.InternalData = tmpfs.FilesystemOpts{
		RootFileType: uint16(rootType),
	}
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

func (c *containerMounter) mountSubmountsVFS2(ctx context.Context, conf *config.Config, mns *vfs.MountNamespace, creds *auth.Credentials) error {
	mounts, err := c.prepareMountsVFS2()
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
			mnt, err = c.mountSharedSubmountVFS2(ctx, conf, mns, creds, submount.mount, hint)
			if err != nil {
				return fmt.Errorf("mount shared mount %q to %q: %v", hint.name, submount.mount.Destination, err)
			}
		} else {
			mnt, err = c.mountSubmountVFS2(ctx, conf, mns, creds, submount)
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

	if err := c.mountTmpVFS2(ctx, conf, creds, mns); err != nil {
		return fmt.Errorf(`mount submount "\tmp": %w`, err)
	}
	return nil
}

type mountAndFD struct {
	mount *specs.Mount
	fd    int
}

func (c *containerMounter) prepareMountsVFS2() ([]mountAndFD, error) {
	// Associate bind mounts with their FDs before sorting since there is an
	// undocumented assumption that FDs are dispensed in the order in which
	// they are required by mounts.
	var mounts []mountAndFD
	for i := range c.mounts {
		m := &c.mounts[i]
		specutils.MaybeConvertToBindMount(m)

		// Only bind mounts use host FDs; see
		// containerMounter.getMountNameAndOptionsVFS2.
		fd := -1
		if m.Type == bind {
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

func (c *containerMounter) mountSubmountVFS2(ctx context.Context, conf *config.Config, mns *vfs.MountNamespace, creds *auth.Credentials, submount *mountAndFD) (*vfs.Mount, error) {
	fsName, opts, useOverlay, err := c.getMountNameAndOptionsVFS2(conf, submount)
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
		opts, cleanup, err = c.configureOverlay(ctx, creds, opts, fsName)
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

// getMountNameAndOptionsVFS2 retrieves the fsName, opts, and useOverlay values
// used for mounts.
func (c *containerMounter) getMountNameAndOptionsVFS2(conf *config.Config, m *mountAndFD) (string, *vfs.MountOptions, bool, error) {
	fsName := m.mount.Type
	useOverlay := false
	var (
		data         []string
		internalData interface{}
	)

	verityData, verityOpts, verityRequested, remainingMOpts, err := parseVerityMountOptions(m.mount.Options)
	if err != nil {
		return "", nil, false, err
	}
	m.mount.Options = remainingMOpts

	// Find filesystem name and FS specific data field.
	switch m.mount.Type {
	case devpts.Name, devtmpfs.Name, proc.Name, sys.Name:
		// Nothing to do.

	case nonefs:
		fsName = sys.Name

	case tmpfs.Name:
		var err error
		data, err = parseAndFilterOptions(m.mount.Options, tmpfsAllowedData...)
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
		data = p9MountData(m.fd, c.getMountAccessType(conf, m.mount), true /* vfs2 */)
		internalData = gofer.InternalFilesystemOptions{
			UniqueID: m.mount.Destination,
		}

		// If configured, add overlay to all writable mounts.
		useOverlay = conf.Overlay && !mountFlags(m.mount.Options).ReadOnly

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

	opts := &vfs.MountOptions{
		GetFilesystemOptions: vfs.GetFilesystemOptions{
			Data:         strings.Join(data, ","),
			InternalData: internalData,
		},
		InternalMount: true,
	}

	for _, o := range m.mount.Options {
		switch o {
		case "rw":
			opts.ReadOnly = false
		case "ro":
			opts.ReadOnly = true
		case "noatime":
			opts.Flags.NoATime = true
		case "noexec":
			opts.Flags.NoExec = true
		case "bind", "rbind":
			// These are the same as a mount with type="bind".
		default:
			log.Warningf("ignoring unknown mount option %q", o)
		}
	}

	if verityRequested {
		verityData = verityData + "root_name=" + path.Base(m.mount.Destination)
		verityOpts.LowerName = fsName
		verityOpts.LowerGetFSOptions = opts.GetFilesystemOptions
		fsName = verity.Name
		opts = &vfs.MountOptions{
			GetFilesystemOptions: vfs.GetFilesystemOptions{
				Data:         verityData,
				InternalData: verityOpts,
			},
			InternalMount: true,
		}
	}

	return fsName, opts, useOverlay, nil
}

func parseKeyValue(s string) (string, string, bool) {
	tokens := strings.SplitN(s, "=", 2)
	if len(tokens) < 2 {
		return "", "", false
	}
	return strings.TrimSpace(tokens[0]), strings.TrimSpace(tokens[1]), true
}

// parseAndFilterOptions scans the provided mount options for verity-related
// mount options. It returns the parsed set of verity mount options, as well as
// the filtered set of mount options unrelated to verity.
func parseVerityMountOptions(mopts []string) (string, verity.InternalFilesystemOptions, bool, []string, error) {
	nonVerity := []string{}
	found := false
	var rootHash string
	verityOpts := verity.InternalFilesystemOptions{
		Action: verity.PanicOnViolation,
	}
	for _, o := range mopts {
		if !strings.HasPrefix(o, "verity.") {
			nonVerity = append(nonVerity, o)
			continue
		}

		k, v, ok := parseKeyValue(o)
		if !ok {
			return "", verityOpts, found, nonVerity, fmt.Errorf("invalid verity mount option with no value: %q", o)
		}

		found = true
		switch k {
		case "verity.roothash":
			rootHash = v
		case "verity.action":
			switch v {
			case "error":
				verityOpts.Action = verity.ErrorOnViolation
			case "panic":
				verityOpts.Action = verity.PanicOnViolation
			default:
				log.Warningf("Invalid verity action %q", v)
				verityOpts.Action = verity.PanicOnViolation
			}
		default:
			return "", verityOpts, found, nonVerity, fmt.Errorf("unknown verity mount option: %q", k)
		}
	}
	verityOpts.AllowRuntimeEnable = len(rootHash) == 0
	verityData := "root_hash=" + rootHash + ","
	return verityData, verityOpts, found, nonVerity, nil
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
		_, err := c.mountSubmountVFS2(ctx, conf, mns, creds, &mountAndFD{mount: &tmpMount})
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
	mntFD := &mountAndFD{mount: &hint.mount}
	fsName, opts, useOverlay, err := c.getMountNameAndOptionsVFS2(conf, mntFD)
	if err != nil {
		return nil, err
	}
	if len(fsName) == 0 {
		return nil, fmt.Errorf("mount type not supported %q", hint.mount.Type)
	}

	if useOverlay {
		log.Infof("Adding overlay on top of shared mount %q", mntFD.mount.Destination)
		var cleanup func()
		opts, cleanup, err = c.configureOverlay(ctx, creds, opts, fsName)
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
func (c *containerMounter) mountSharedSubmountVFS2(ctx context.Context, conf *config.Config, mns *vfs.MountNamespace, creds *auth.Credentials, mount *specs.Mount, source *mountHint) (*vfs.Mount, error) {
	if err := source.checkCompatible(mount); err != nil {
		return nil, err
	}

	// Ignore data and useOverlay because these were already applied to
	// the master mount.
	_, opts, _, err := c.getMountNameAndOptionsVFS2(conf, &mountAndFD{mount: mount})
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
func (c *containerMounter) configureRestore(ctx context.Context) (context.Context, error) {
	fdmap := make(map[string]int)
	fdmap["/"] = c.fds.remove()
	mounts, err := c.prepareMountsVFS2()
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

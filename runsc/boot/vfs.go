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
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/fspath"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/devices/memdev"
	"gvisor.dev/gvisor/pkg/sentry/devices/ttydev"
	"gvisor.dev/gvisor/pkg/sentry/fs/user"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/devpts"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/devtmpfs"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/gofer"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/overlay"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/proc"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/sys"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/tmpfs"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/syserror"
)

func registerFilesystems(ctx context.Context, vfsObj *vfs.VirtualFilesystem, creds *auth.Credentials) error {
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

	// Setup files in devtmpfs.
	if err := memdev.Register(vfsObj); err != nil {
		return fmt.Errorf("registering memdev: %w", err)
	}
	if err := ttydev.Register(vfsObj); err != nil {
		return fmt.Errorf("registering ttydev: %w", err)
	}
	a, err := devtmpfs.NewAccessor(ctx, vfsObj, creds, devtmpfs.Name)
	if err != nil {
		return fmt.Errorf("creating devtmpfs accessor: %w", err)
	}
	defer a.Release()

	if err := a.UserspaceInit(ctx); err != nil {
		return fmt.Errorf("initializing userspace: %w", err)
	}
	if err := memdev.CreateDevtmpfsFiles(ctx, a); err != nil {
		return fmt.Errorf("creating devtmpfs files: %w", err)
	}
	if err := ttydev.CreateDevtmpfsFiles(ctx, a); err != nil {
		return fmt.Errorf("creating devtmpfs files: %w", err)
	}
	return nil
}

func setupContainerVFS2(ctx context.Context, conf *Config, mntr *containerMounter, procArgs *kernel.CreateProcessArgs) error {
	if err := mntr.k.VFS().Init(); err != nil {
		return fmt.Errorf("failed to initialize VFS: %w", err)
	}
	mns, err := mntr.setupVFS2(ctx, conf, procArgs)
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

func (c *containerMounter) setupVFS2(ctx context.Context, conf *Config, procArgs *kernel.CreateProcessArgs) (*vfs.MountNamespace, error) {
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

	if err := registerFilesystems(rootCtx, c.k.VFS(), rootCreds); err != nil {
		return nil, fmt.Errorf("register filesystems: %w", err)
	}

	mns, err := c.createMountNamespaceVFS2(rootCtx, conf, rootCreds)
	if err != nil {
		return nil, fmt.Errorf("creating mount namespace: %w", err)
	}
	rootProcArgs.MountNamespaceVFS2 = mns

	// Mount submounts.
	if err := c.mountSubmountsVFS2(rootCtx, conf, mns, rootCreds); err != nil {
		return nil, fmt.Errorf("mounting submounts vfs2: %w", err)
	}
	return mns, nil
}

func (c *containerMounter) createMountNamespaceVFS2(ctx context.Context, conf *Config, creds *auth.Credentials) (*vfs.MountNamespace, error) {
	fd := c.fds.remove()
	opts := strings.Join(p9MountData(fd, conf.FileAccess, true /* vfs2 */), ",")

	log.Infof("Mounting root over 9P, ioFD: %d", fd)
	mns, err := c.k.VFS().NewMountNamespace(ctx, creds, "", gofer.Name, &vfs.GetFilesystemOptions{Data: opts})
	if err != nil {
		return nil, fmt.Errorf("setting up mount namespace: %w", err)
	}
	return mns, nil
}

func (c *containerMounter) mountSubmountsVFS2(ctx context.Context, conf *Config, mns *vfs.MountNamespace, creds *auth.Credentials) error {
	mounts, err := c.prepareMountsVFS2()
	if err != nil {
		return err
	}

	for i := range mounts {
		submount := &mounts[i]
		log.Debugf("Mounting %q to %q, type: %s, options: %s", submount.Source, submount.Destination, submount.Type, submount.Options)
		if err := c.mountSubmountVFS2(ctx, conf, mns, creds, submount); err != nil {
			return err
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

func (c *containerMounter) mountSubmountVFS2(ctx context.Context, conf *Config, mns *vfs.MountNamespace, creds *auth.Credentials, submount *mountAndFD) error {
	root := mns.Root()
	defer root.DecRef()
	target := &vfs.PathOperation{
		Root:  root,
		Start: root,
		Path:  fspath.Parse(submount.Destination),
	}
	fsName, opts, err := c.getMountNameAndOptionsVFS2(conf, submount)
	if err != nil {
		return fmt.Errorf("mountOptions failed: %w", err)
	}
	if len(fsName) == 0 {
		// Filesystem is not supported (e.g. cgroup), just skip it.
		return nil
	}

	if err := c.makeSyntheticMount(ctx, submount.Destination, root, creds); err != nil {
		return err
	}
	if err := c.k.VFS().MountAt(ctx, creds, "", target, fsName, opts); err != nil {
		return fmt.Errorf("failed to mount %q (type: %s): %w, opts: %v", submount.Destination, submount.Type, err, opts)
	}
	log.Infof("Mounted %q to %q type: %s, internal-options: %q", submount.Source, submount.Destination, submount.Type, opts.GetFilesystemOptions.Data)
	return nil
}

// getMountNameAndOptionsVFS2 retrieves the fsName, opts, and useOverlay values
// used for mounts.
func (c *containerMounter) getMountNameAndOptionsVFS2(conf *Config, m *mountAndFD) (string, *vfs.MountOptions, error) {
	var (
		fsName string
		data   []string
	)

	// Find filesystem name and FS specific data field.
	switch m.Type {
	case devpts.Name, devtmpfs.Name, proc.Name, sys.Name:
		fsName = m.Type
	case nonefs:
		fsName = sys.Name
	case tmpfs.Name:
		fsName = m.Type

		var err error
		data, err = parseAndFilterOptions(m.Options, tmpfsAllowedData...)
		if err != nil {
			return "", nil, err
		}

	case bind:
		fsName = gofer.Name
		data = p9MountData(m.fd, c.getMountAccessType(m.Mount), true /* vfs2 */)

	default:
		log.Warningf("ignoring unknown filesystem type %q", m.Type)
	}

	opts := &vfs.MountOptions{
		GetFilesystemOptions: vfs.GetFilesystemOptions{
			Data: strings.Join(data, ","),
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

	if conf.Overlay {
		// All writes go to upper, be paranoid and make lower readonly.
		opts.ReadOnly = true
	}
	return fsName, opts, nil
}

func (c *containerMounter) makeSyntheticMount(ctx context.Context, currentPath string, root vfs.VirtualDentry, creds *auth.Credentials) error {
	target := &vfs.PathOperation{
		Root:  root,
		Start: root,
		Path:  fspath.Parse(currentPath),
	}
	_, err := c.k.VFS().StatAt(ctx, creds, target, &vfs.StatOptions{})
	if err == nil {
		// Mount point exists, nothing else to do.
		return nil
	}
	if err != syserror.ENOENT {
		return fmt.Errorf("stat failed for %q during mount point creation: %w", currentPath, err)
	}

	// Recurse to ensure parent is created and then create the mount point.
	if err := c.makeSyntheticMount(ctx, path.Dir(currentPath), root, creds); err != nil {
		return err
	}
	log.Debugf("Creating dir %q for mount point", currentPath)
	mkdirOpts := &vfs.MkdirOptions{Mode: 0777, ForSyntheticMountpoint: true}
	if err := c.k.VFS().MkdirAt(ctx, creds, target, mkdirOpts); err != nil {
		return fmt.Errorf("failed to create directory %q for mount: %w", currentPath, err)
	}
	return nil
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
func (c *containerMounter) mountTmpVFS2(ctx context.Context, conf *Config, creds *auth.Credentials, mns *vfs.MountNamespace) error {
	for _, m := range c.mounts {
		// m.Destination has been cleaned, so it's to use equality here.
		if m.Destination == "/tmp" {
			log.Debugf(`Explict "/tmp" mount found, skipping internal tmpfs, mount: %+v`, m)
			return nil
		}
	}

	root := mns.Root()
	defer root.DecRef()
	pop := vfs.PathOperation{
		Root:  root,
		Start: root,
		Path:  fspath.Parse("/tmp"),
	}
	// TODO(gvisor.dev/issue/2782): Use O_PATH when available.
	statx, err := c.k.VFS().StatAt(ctx, creds, &pop, &vfs.StatOptions{})
	switch err {
	case nil:
		// Found '/tmp' in filesystem, check if it's empty.
		if linux.FileMode(statx.Mode).FileType() != linux.ModeDirectory {
			// Not a dir?! Leave it be.
			return nil
		}
		if statx.Nlink > 2 {
			// If more than "." and ".." is found, skip internal tmpfs to prevent
			// hiding existing files.
			log.Infof(`Skipping internal tmpfs mount for "/tmp" because it's not empty`)
			return nil
		}
		log.Infof(`Mounting internal tmpfs on top of empty "/tmp"`)
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
		return c.mountSubmountVFS2(ctx, conf, mns, creds, &mountAndFD{Mount: tmpMount})

	default:
		return fmt.Errorf(`stating "/tmp" inside container: %w`, err)
	}
}

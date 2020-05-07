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
	"strconv"
	"strings"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/fspath"
	"gvisor.dev/gvisor/pkg/sentry/devices/memdev"
	"gvisor.dev/gvisor/pkg/sentry/fs"
	devpts2 "gvisor.dev/gvisor/pkg/sentry/fsimpl/devpts"
	devtmpfsimpl "gvisor.dev/gvisor/pkg/sentry/fsimpl/devtmpfs"
	goferimpl "gvisor.dev/gvisor/pkg/sentry/fsimpl/gofer"
	procimpl "gvisor.dev/gvisor/pkg/sentry/fsimpl/proc"
	sysimpl "gvisor.dev/gvisor/pkg/sentry/fsimpl/sys"
	tmpfsimpl "gvisor.dev/gvisor/pkg/sentry/fsimpl/tmpfs"
	"gvisor.dev/gvisor/pkg/syserror"

	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
)

func registerFilesystems(ctx context.Context, vfsObj *vfs.VirtualFilesystem, creds *auth.Credentials) error {
	vfsObj.MustRegisterFilesystemType(devpts2.Name, &devpts2.FilesystemType{}, &vfs.RegisterFilesystemTypeOptions{
		AllowUserList: true,
		// TODO(b/29356795): Users may mount this once the terminals are in a
		//  usable state.
		AllowUserMount: false,
	})
	vfsObj.MustRegisterFilesystemType(devtmpfsimpl.Name, &devtmpfsimpl.FilesystemType{}, &vfs.RegisterFilesystemTypeOptions{
		AllowUserMount: true,
		AllowUserList:  true,
	})
	vfsObj.MustRegisterFilesystemType(goferimpl.Name, &goferimpl.FilesystemType{}, &vfs.RegisterFilesystemTypeOptions{
		AllowUserList: true,
	})
	vfsObj.MustRegisterFilesystemType(procimpl.Name, &procimpl.FilesystemType{}, &vfs.RegisterFilesystemTypeOptions{
		AllowUserMount: true,
		AllowUserList:  true,
	})
	vfsObj.MustRegisterFilesystemType(sysimpl.Name, &sysimpl.FilesystemType{}, &vfs.RegisterFilesystemTypeOptions{
		AllowUserMount: true,
		AllowUserList:  true,
	})
	vfsObj.MustRegisterFilesystemType(tmpfsimpl.Name, &tmpfsimpl.FilesystemType{}, &vfs.RegisterFilesystemTypeOptions{
		AllowUserMount: true,
		AllowUserList:  true,
	})

	// Setup files in devtmpfs.
	if err := memdev.Register(vfsObj); err != nil {
		return fmt.Errorf("registering memdev: %w", err)
	}
	a, err := devtmpfsimpl.NewAccessor(ctx, vfsObj, creds, devtmpfsimpl.Name)
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
	return setExecutablePathVFS2(ctx, procArgs)
}

func setExecutablePathVFS2(ctx context.Context, procArgs *kernel.CreateProcessArgs) error {
	exe := procArgs.Argv[0]

	// Absolute paths can be used directly.
	if path.IsAbs(exe) {
		procArgs.Filename = exe
		return nil
	}

	// Paths with '/' in them should be joined to the working directory, or
	// to the root if working directory is not set.
	if strings.IndexByte(exe, '/') > 0 {
		if !path.IsAbs(procArgs.WorkingDirectory) {
			return fmt.Errorf("working directory %q must be absolute", procArgs.WorkingDirectory)
		}
		procArgs.Filename = path.Join(procArgs.WorkingDirectory, exe)
		return nil
	}

	// Paths with a '/' are relative to the CWD.
	if strings.IndexByte(exe, '/') > 0 {
		procArgs.Filename = path.Join(procArgs.WorkingDirectory, exe)
		return nil
	}

	// Otherwise, We must lookup the name in the paths, starting from the
	// root directory.
	root := procArgs.MountNamespaceVFS2.Root()
	defer root.DecRef()

	paths := fs.GetPath(procArgs.Envv)
	creds := procArgs.Credentials

	for _, p := range paths {
		binPath := path.Join(p, exe)
		pop := &vfs.PathOperation{
			Root:               root,
			Start:              root,
			Path:               fspath.Parse(binPath),
			FollowFinalSymlink: true,
		}
		opts := &vfs.OpenOptions{
			FileExec: true,
			Flags:    linux.O_RDONLY,
		}
		dentry, err := root.Mount().Filesystem().VirtualFilesystem().OpenAt(ctx, creds, pop, opts)
		if err == syserror.ENOENT || err == syserror.EACCES {
			// Didn't find it here.
			continue
		}
		if err != nil {
			return err
		}
		dentry.DecRef()

		procArgs.Filename = binPath
		return nil
	}

	return fmt.Errorf("executable %q not found in $PATH=%q", exe, strings.Join(paths, ":"))
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
	opts := strings.Join(p9MountOptionsVFS2(fd, conf.FileAccess), ",")

	log.Infof("Mounting root over 9P, ioFD: %d", fd)
	mns, err := c.k.VFS().NewMountNamespace(ctx, creds, "", rootFsName, &vfs.GetFilesystemOptions{Data: opts})
	if err != nil {
		return nil, fmt.Errorf("setting up mount namespace: %w", err)
	}
	return mns, nil
}

func (c *containerMounter) mountSubmountsVFS2(ctx context.Context, conf *Config, mns *vfs.MountNamespace, creds *auth.Credentials) error {
	c.prepareMountsVFS2()

	for _, submount := range c.mounts {
		log.Debugf("Mounting %q to %q, type: %s, options: %s", submount.Source, submount.Destination, submount.Type, submount.Options)
		if err := c.mountSubmountVFS2(ctx, conf, mns, creds, &submount); err != nil {
			return err
		}
	}

	// TODO(gvisor.dev/issue/1487): implement mountTmp from fs.go.

	return c.checkDispenser()
}

func (c *containerMounter) prepareMountsVFS2() {
	// Sort the mounts so that we don't place children before parents.
	sort.Slice(c.mounts, func(i, j int) bool { return len(c.mounts[i].Destination) < len(c.mounts[j].Destination) })
}

// TODO(gvisor.dev/issue/1487): Implement submount options similar to the VFS1 version.
func (c *containerMounter) mountSubmountVFS2(ctx context.Context, conf *Config, mns *vfs.MountNamespace, creds *auth.Credentials, submount *specs.Mount) error {
	root := mns.Root()
	defer root.DecRef()
	target := &vfs.PathOperation{
		Root:  root,
		Start: root,
		Path:  fspath.Parse(submount.Destination),
	}

	fsName, options, useOverlay, err := c.getMountNameAndOptionsVFS2(conf, *submount)
	if err != nil {
		return fmt.Errorf("mountOptions failed: %w", err)
	}
	if fsName == "" {
		// Filesystem is not supported (e.g. cgroup), just skip it.
		return nil
	}

	if err := c.makeSyntheticMount(ctx, submount.Destination, root, creds); err != nil {
		return err
	}
	log.Debugf("directory exists or made directory for submount: %s", submount.Destination)

	opts := &vfs.MountOptions{
		GetFilesystemOptions: vfs.GetFilesystemOptions{
			Data: strings.Join(options, ","),
		},
		InternalMount: true,
	}

	// All writes go to upper, be paranoid and make lower readonly.
	opts.ReadOnly = useOverlay

	if err := c.k.VFS().MountAt(ctx, creds, "", target, fsName, opts); err != nil {
		return fmt.Errorf("failed to mount %q (type: %s): %w, opts: %v", submount.Destination, submount.Type, err, opts)
	}
	log.Infof("Mounted %q to %q type: %s, internal-options: %q", submount.Source, submount.Destination, submount.Type, opts)
	return nil
}

// getMountNameAndOptionsVFS2 retrieves the fsName, opts, and useOverlay values
// used for mounts.
func (c *containerMounter) getMountNameAndOptionsVFS2(conf *Config, m specs.Mount) (string, []string, bool, error) {
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
		opts = p9MountOptionsVFS2(fd, c.getMountAccessType(m))
		// If configured, add overlay to all writable mounts.
		useOverlay = conf.Overlay && !mountFlags(m.Options).ReadOnly

	default:
		log.Warningf("ignoring unknown filesystem type %q", m.Type)
	}
	return fsName, opts, useOverlay, nil
}

// p9MountOptions creates a slice of options for a p9 mount.
// TODO(gvisor.dev/issue/1624): Remove this version once privateunixsocket is
// deleted, along with the rest of VFS1.
func p9MountOptionsVFS2(fd int, fa FileAccessType) []string {
	opts := []string{
		"trans=fd",
		"rfdno=" + strconv.Itoa(fd),
		"wfdno=" + strconv.Itoa(fd),
	}
	if fa == FileAccessShared {
		opts = append(opts, "cache=remote_revalidating")
	}
	return opts
}

func (c *containerMounter) makeSyntheticMount(ctx context.Context, currentPath string, root vfs.VirtualDentry, creds *auth.Credentials) error {
	target := &vfs.PathOperation{
		Root:  root,
		Start: root,
		Path:  fspath.Parse(currentPath),
	}

	_, err := c.k.VFS().StatAt(ctx, creds, target, &vfs.StatOptions{})
	switch {
	case err == syserror.ENOENT:
		if err := c.makeSyntheticMount(ctx, path.Dir(currentPath), root, creds); err != nil {
			return err
		}
		mkdirOpts := &vfs.MkdirOptions{Mode: 0777, ForSyntheticMountpoint: true}
		if err := c.k.VFS().MkdirAt(ctx, creds, target, mkdirOpts); err != nil {
			return fmt.Errorf("failed to makedir for mount %+v: %w", target, err)
		}
		return nil

	case err != nil:
		return fmt.Errorf("stat failed for mount %+v: %w", target, err)

	default:
		return nil
	}
}

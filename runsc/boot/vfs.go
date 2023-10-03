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
	"regexp"
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
	"gvisor.dev/gvisor/pkg/sentry/devices/accel"
	"gvisor.dev/gvisor/pkg/sentry/devices/memdev"
	"gvisor.dev/gvisor/pkg/sentry/devices/nvproxy"
	"gvisor.dev/gvisor/pkg/sentry/devices/ttydev"
	"gvisor.dev/gvisor/pkg/sentry/devices/tundev"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/cgroupfs"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/devpts"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/devtmpfs"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/erofs"
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

func registerFilesystems(k *kernel.Kernel, info *containerInfo) error {
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
	vfsObj.MustRegisterFilesystemType(erofs.Name, &erofs.FilesystemType{}, &vfs.RegisterFilesystemTypeOptions{
		AllowUserList: true,
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

	// Register devices.
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

	// Setup files in devtmpfs.
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

	if err := nvproxyRegisterDevicesAndCreateFiles(ctx, info, k, vfsObj, a); err != nil {
		return err
	}

	if err := tpuProxyRegisterDevicesAndCreateFiles(ctx, info, k, vfsObj, a); err != nil {
		return err
	}

	return nil
}

func setupContainerVFS(ctx context.Context, info *containerInfo, mntr *containerMounter, procArgs *kernel.CreateProcessArgs) error {
	// Create context with root credentials to mount the filesystem (the current
	// user may not be privileged enough).
	rootCreds := auth.NewRootCredentials(procArgs.Credentials.UserNamespace)
	rootProcArgs := *procArgs
	rootProcArgs.WorkingDirectory = "/"
	rootProcArgs.Credentials = rootCreds
	rootProcArgs.Umask = 0022
	rootProcArgs.MaxSymlinkTraversals = linux.MaxSymlinkTraversals
	rootCtx := rootProcArgs.NewContext(mntr.k)

	mns, err := mntr.mountAll(rootCtx, rootCreds, info.conf, &rootProcArgs)
	if err != nil {
		return fmt.Errorf("failed to setupFS: %w", err)
	}
	procArgs.MountNamespace = mns

	mnsRoot := mns.Root(rootCtx)
	defer mnsRoot.DecRef(rootCtx)

	if err := createDeviceFiles(rootCtx, rootCreds, info, mntr.k.VFS(), mnsRoot); err != nil {
		return fmt.Errorf("failed to create device files: %w", err)
	}

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
//
// This function must NOT add/remove any gofer mounts or change their order.
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
	if !conf.HostFifo.AllowOpen() {
		opts = append(opts, "disable_fifo_open")
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

	// overlayMediums contains information about how the gofer mounts have been
	// overlaid. The first entry is for rootfs and the following entries are for
	// bind mounts in `mounts` slice above (in the same order).
	overlayMediums []OverlayMedium

	k *kernel.Kernel

	// hints is the set of pod mount hints for the sandbox.
	hints *PodMountHints

	// sharedMounts is a map of shared mounts that can be reused across
	// containers.
	sharedMounts map[string]*vfs.Mount

	// productName is the value to show in
	// /sys/devices/virtual/dmi/id/product_name.
	productName string

	// sandboxID is the ID for the whole sandbox.
	sandboxID string
}

func newContainerMounter(info *containerInfo, k *kernel.Kernel, hints *PodMountHints, sharedMounts map[string]*vfs.Mount, productName string, sandboxID string) *containerMounter {
	return &containerMounter{
		root:                info.spec.Root,
		mounts:              compileMounts(info.spec, info.conf),
		fds:                 fdDispenser{fds: info.goferFDs},
		overlayFilestoreFDs: fdDispenser{fds: info.overlayFilestoreFDs},
		overlayMediums:      info.overlayMediums,
		k:                   k,
		hints:               hints,
		sharedMounts:        sharedMounts,
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

func getMountAccessType(conf *config.Config, mount *specs.Mount, hint *MountHint) config.FileAccessType {
	if hint != nil {
		return hint.fileAccessType()
	}
	return conf.FileAccessMounts
}

func (c *containerMounter) mountAll(rootCtx context.Context, rootCreds *auth.Credentials, conf *config.Config, rootProcArgs *kernel.CreateProcessArgs) (*vfs.MountNamespace, error) {
	log.Infof("Configuring container's file system")

	mns, err := c.createMountNamespace(rootCtx, conf, rootCreds)
	if err != nil {
		return nil, fmt.Errorf("creating mount namespace: %w", err)
	}
	rootProcArgs.MountNamespace = mns

	root := mns.Root(rootCtx)
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
	ioFD := c.fds.remove()
	data := goferMountData(ioFD, conf.FileAccess, conf)

	// We can't check for overlayfs here because sandbox is chroot'ed and gofer
	// can only send mount options for specs.Mounts (specs.Root is missing
	// Options field). So assume root is always on top of overlayfs.
	data = append(data, "overlayfs_stale_read")

	// Configure the gofer dentry cache size.
	gofer.SetDentryCacheSize(conf.DCache)

	log.Infof("Mounting root with gofer, ioFD: %d", ioFD)
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
	if c.overlayMediums[0].IsEnabled() {
		log.Infof("Adding overlay on top of root")
		var (
			err              error
			cleanup          func()
			overlayFilestore *fd.FD
		)
		if c.overlayMediums[0].IsBackedByHostFile() {
			overlayFilestore = c.overlayFilestoreFDs.removeAsFD()
		}
		opts, cleanup, err = c.configureOverlay(ctx, conf, creds, opts, fsName, overlayFilestore, c.overlayMediums[0])
		if err != nil {
			return nil, fmt.Errorf("mounting root with overlay: %w", err)
		}
		defer cleanup()
		fsName = overlay.Name
	}

	// The namespace root mount can't be changed, so let's mount a dummy
	// read-only tmpfs here. It simplifies creation of containers without
	// leaking the root file system.
	mns, err := c.k.VFS().NewMountNamespace(ctx, creds, "rootfs", "tmpfs",
		&vfs.MountOptions{ReadOnly: true}, c.k)
	if err != nil {
		return nil, fmt.Errorf("setting up mount namespace: %w", err)
	}
	defer mns.DecRef(ctx)

	mnt, err := c.k.VFS().MountDisconnected(ctx, creds, "root", fsName, opts)
	if err != nil {
		return nil, fmt.Errorf("creating root file system: %w", err)
	}
	defer mnt.DecRef(ctx)
	root := mns.Root(ctx)
	defer root.DecRef(ctx)
	target := &vfs.PathOperation{
		Root:  root,
		Start: root,
	}
	if err := c.k.VFS().ConnectMountAt(ctx, creds, mnt, target); err != nil {
		return nil, fmt.Errorf("mounting root file system: %w", err)
	}

	mns.IncRef()
	return mns, nil
}

// configureOverlay mounts the lower layer using "lowerOpts", mounts the upper
// layer using tmpfs, and return overlay mount options. "cleanup" must be called
// after the options have been used to mount the overlay, to release refs on
// lower and upper mounts.
func (c *containerMounter) configureOverlay(ctx context.Context, conf *config.Config, creds *auth.Credentials, lowerOpts *vfs.MountOptions, lowerFSName string, filestoreFD *fd.FD, medium OverlayMedium) (*vfs.MountOptions, func(), error) {
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
		FilestoreFD:  filestoreFD,
		// If a mount is being overlaid, it should not be limited by the default
		// tmpfs size limit.
		DisableDefaultSizeLimit: true,
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

	// We need to hide the filestore from the containerized application.
	if medium == SelfMedium {
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

		if submount.hint != nil && submount.hint.shouldShareMount() {
			sharedMount, ok := c.sharedMounts[submount.hint.Mount.Source]
			if !ok {
				return fmt.Errorf("shared mount %q not found", submount.hint.Name)
			}
			mnt, err = c.mountSharedSubmount(ctx, conf, mns, creds, submount.mount, submount.hint, sharedMount)
			if err != nil {
				return fmt.Errorf("mount shared mount %q to %q: %v", submount.hint.Name, submount.mount.Destination, err)
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
		return fmt.Errorf(`mount submount "/tmp": %w`, err)
	}
	return nil
}

type mountInfo struct {
	mount              *specs.Mount
	fd                 int
	hint               *MountHint
	overlayMedium      OverlayMedium
	overlayFilestoreFD *fd.FD
}

func newNonGoferMountInfo(mount *specs.Mount) *mountInfo {
	return &mountInfo{mount: mount, fd: -1}
}

func (c *containerMounter) prepareMounts() ([]mountInfo, error) {
	// Associate bind mounts with their FDs before sorting since there is an
	// undocumented assumption that FDs are dispensed in the order in which
	// they are required by mounts.
	var mounts []mountInfo
	goferMntIdx := 1 // First index is for rootfs.
	for i := range c.mounts {
		m := &c.mounts[i]
		specutils.MaybeConvertToBindMount(m)

		// Only bind mounts use host FDs; see
		// containerMounter.getMountNameAndOptions.
		info := mountInfo{
			mount:         m,
			fd:            -1,
			hint:          c.hints.FindMount(m),
			overlayMedium: NoOverlay,
		}
		if specutils.IsGoferMount(*m) {
			info.fd = c.fds.remove()
			info.overlayMedium = c.overlayMediums[goferMntIdx]
			if info.overlayMedium.IsBackedByHostFile() {
				info.overlayFilestoreFD = c.overlayFilestoreFDs.removeAsFD()
			}
			goferMntIdx++
		}
		mounts = append(mounts, info)
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

func (c *containerMounter) mountSubmount(ctx context.Context, conf *config.Config, mns *vfs.MountNamespace, creds *auth.Credentials, submount *mountInfo) (*vfs.Mount, error) {
	fsName, opts, err := getMountNameAndOptions(conf, submount, c.productName)
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

	if submount.overlayMedium.IsEnabled() {
		log.Infof("Adding overlay on top of mount %q", submount.mount.Destination)
		var cleanup func()
		opts, cleanup, err = c.configureOverlay(ctx, conf, creds, opts, fsName, submount.overlayFilestoreFD, submount.overlayMedium)
		if err != nil {
			return nil, fmt.Errorf("mounting volume with overlay at %q: %w", submount.mount.Destination, err)
		}
		defer cleanup()
		fsName = overlay.Name
	}

	root := mns.Root(ctx)
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
func getMountNameAndOptions(conf *config.Config, m *mountInfo, productName string) (string, *vfs.MountOptions, error) {
	fsName := m.mount.Type
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
		sysData := &sys.InternalData{EnableAccelSysfs: conf.TPUProxy}
		if len(productName) > 0 {
			sysData.ProductName = productName
		}
		internalData = sysData

	case tmpfs.Name:
		var err error
		data, err = parseAndFilterOptions(m.mount.Options, tmpfsAllowedData...)
		if err != nil {
			return "", nil, err
		}

	case Bind:
		fsName = gofer.Name
		if m.fd < 0 {
			// Check that an FD was provided to fails fast.
			return "", nil, fmt.Errorf("gofer mount requires a connection FD")
		}
		data = goferMountData(m.fd, getMountAccessType(conf, m.mount, m.hint), conf)
		internalData = gofer.InternalFilesystemOptions{
			UniqueID: m.mount.Destination,
		}

	case cgroupfs.Name:
		var err error
		data, err = parseAndFilterOptions(m.mount.Options, cgroupfs.SupportedMountOptions...)
		if err != nil {
			return "", nil, err
		}

	default:
		log.Warningf("ignoring unknown filesystem type %q", m.mount.Type)
		return "", nil, nil
	}

	opts := ParseMountOptions(m.mount.Options)
	opts.GetFilesystemOptions = vfs.GetFilesystemOptions{
		Data:         strings.Join(data, ","),
		InternalData: internalData,
	}

	return fsName, opts, nil
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

	root := mns.Root(ctx)
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
		if _, err := c.mountSubmount(ctx, conf, mns, creds, newNonGoferMountInfo(&tmpMount)); err != nil {
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
// should be mounted (e.g. a volume shared between containers).
// Precondition: Must be only called once during the loader sequence
// for the root container.
// Postcondition: Initialized l.sharedMounts on success.
func (l *Loader) processHints(conf *config.Config, creds *auth.Credentials) error {
	ctx := l.k.SupervisorContext()
	var sharedMounts map[string]*vfs.Mount
	for _, hint := range l.mountHints.Mounts {
		if !hint.shouldShareMount() {
			continue
		}

		log.Infof("Mounting master of shared mount %q from %q type %q", hint.Name, hint.Mount.Source, hint.Mount.Type)
		mnt, err := l.mountSharedMaster(ctx, conf, hint, creds)
		if err != nil {
			return fmt.Errorf("mounting shared master %q: %v", hint.Name, err)
		}
		if sharedMounts == nil {
			sharedMounts = make(map[string]*vfs.Mount)
		}
		sharedMounts[hint.Mount.Source] = mnt
	}
	l.sharedMounts = sharedMounts
	return nil
}

// mountSharedMaster mounts the master of a volume that is shared among
// containers in a pod.
func (l *Loader) mountSharedMaster(ctx context.Context, conf *config.Config, hint *MountHint, creds *auth.Credentials) (*vfs.Mount, error) {
	// Map mount type to filesystem name, and parse out the options that we are
	// capable of dealing with.
	mntInfo := newNonGoferMountInfo(&hint.Mount)
	fsName, opts, err := getMountNameAndOptions(conf, mntInfo, l.productName)
	if err != nil {
		return nil, err
	}
	if len(fsName) == 0 {
		return nil, fmt.Errorf("mount type not supported %q", hint.Mount.Type)
	}
	return l.k.VFS().MountDisconnected(ctx, creds, "", fsName, opts)
}

// mountSharedSubmount binds mount to a previously mounted volume that is shared
// among containers in the same pod.
func (c *containerMounter) mountSharedSubmount(ctx context.Context, conf *config.Config, mns *vfs.MountNamespace, creds *auth.Credentials, mount *specs.Mount, srcHint *MountHint, srcMount *vfs.Mount) (*vfs.Mount, error) {
	if err := srcHint.checkCompatible(mount); err != nil {
		return nil, err
	}

	// Ignore data and useOverlay because these were already applied to
	// the master mount.
	_, opts, err := getMountNameAndOptions(conf, newNonGoferMountInfo(mount), c.productName)
	if err != nil {
		return nil, err
	}
	newMnt := c.k.VFS().NewDisconnectedMount(srcMount.Filesystem(), srcMount.Root(), opts)
	defer newMnt.DecRef(ctx)

	root := mns.Root(ctx)
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
	log.Infof("Mounted %q type shared bind to %q", mount.Destination, srcHint.Name)
	return newMnt, nil
}

func (c *containerMounter) makeMountPoint(ctx context.Context, creds *auth.Credentials, mns *vfs.MountNamespace, dest string) error {
	root := mns.Root(ctx)
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

func createDeviceFiles(ctx context.Context, creds *auth.Credentials, info *containerInfo, vfsObj *vfs.VirtualFilesystem, root vfs.VirtualDentry) error {
	if info.spec.Linux == nil {
		return nil
	}
	for _, dev := range info.spec.Linux.Devices {
		pop := vfs.PathOperation{
			Root:  root,
			Start: root,
			Path:  fspath.Parse(dev.Path),
		}
		opts := vfs.MknodOptions{
			Mode: linux.FileMode(dev.FileMode.Perm()),
		}
		// See https://github.com/opencontainers/runtime-spec/blob/main/config-linux.md#devices.
		switch dev.Type {
		case "b":
			opts.Mode |= linux.S_IFBLK
			opts.DevMajor = uint32(dev.Major)
			opts.DevMinor = uint32(dev.Minor)
		case "c", "u":
			opts.Mode |= linux.S_IFCHR
			opts.DevMajor = uint32(dev.Major)
			opts.DevMinor = uint32(dev.Minor)
		case "p":
			opts.Mode |= linux.S_IFIFO
		default:
			return fmt.Errorf("specified device at %q has invalid type %q", dev.Path, dev.Type)
		}
		if dev.Path == "/dev/nvidia-uvm" && info.nvidiaUVMDevMajor != 0 && opts.DevMajor != info.nvidiaUVMDevMajor {
			// nvidia-uvm's major device number is dynamically assigned, so the
			// number that it has on the host may differ from the number that
			// it has in sentry VFS; switch from the former to the latter.
			log.Infof("Switching /dev/nvidia-uvm device major number from %d to %d", dev.Major, info.nvidiaUVMDevMajor)
			opts.DevMajor = info.nvidiaUVMDevMajor
		}
		if err := vfsObj.MkdirAllAt(ctx, path.Dir(dev.Path), root, creds, &vfs.MkdirOptions{
			Mode: 0o755,
		}, true /* mustBeDir */); err != nil {
			return fmt.Errorf("failed to create ancestor directories of %q: %w", dev.Path, err)
		}
		// EEXIST is silently ignored; compare
		// opencontainers/runc:libcontainer/rootfs_linux.go:createDeviceNode().
		created := true
		if err := vfsObj.MknodAt(ctx, creds, &pop, &opts); err != nil && !linuxerr.Equals(linuxerr.EEXIST, err) {
			if linuxerr.Equals(linuxerr.EEXIST, err) {
				created = false
			} else {
				return fmt.Errorf("failed to create device file at %q: %w", dev.Path, err)
			}
		}
		if created && (dev.UID != nil || dev.GID != nil) {
			var opts vfs.SetStatOptions
			if dev.UID != nil {
				opts.Stat.Mask |= linux.STATX_UID
				opts.Stat.UID = *dev.UID
			}
			if dev.GID != nil {
				opts.Stat.Mask |= linux.STATX_GID
				opts.Stat.GID = *dev.GID
			}
			if err := vfsObj.SetStatAt(ctx, creds, &pop, &opts); err != nil {
				return fmt.Errorf("failed to set UID/GID for device file %q: %w", dev.Path, err)
			}
		}
	}
	return nil
}

func tpuProxyRegisterDevicesAndCreateFiles(ctx context.Context, info *containerInfo, k *kernel.Kernel, vfsObj *vfs.VirtualFilesystem, a *devtmpfs.Accessor) error {
	if !info.conf.TPUProxy {
		return nil
	}
	// At this point /dev/accel just contains the TPU devices have been mounted
	// into the sandbox chroot. Enumerate all of them and create sentry devices.
	paths, err := filepath.Glob("/dev/accel*")
	if err != nil {
		return fmt.Errorf("enumerating accel device files: %w", err)
	}
	for _, path := range paths {
		accelDeviceRegex := regexp.MustCompile(`^/dev/accel(\d+)$`)
		if ms := accelDeviceRegex.FindStringSubmatch(path); ms != nil {
			deviceNum, _ := strconv.ParseUint(ms[1], 10, 32)
			if err := accel.Register(vfsObj, uint32(deviceNum)); err != nil {
				return fmt.Errorf("registering accel driver: %w", err)
			}
			if err := accel.CreateDevtmpfsFile(ctx, a, uint32(deviceNum)); err != nil {
				return fmt.Errorf("creating accel device file %q: %w", deviceNum, err)
			}
		}
	}
	return nil
}

func nvproxyRegisterDevicesAndCreateFiles(ctx context.Context, info *containerInfo, k *kernel.Kernel, vfsObj *vfs.VirtualFilesystem, a *devtmpfs.Accessor) error {
	if !specutils.GPUFunctionalityRequested(info.spec, info.conf) {
		return nil
	}
	uvmDevMajor, err := k.VFS().GetDynamicCharDevMajor()
	if err != nil {
		return fmt.Errorf("reserving device major number for nvidia-uvm: %w", err)
	}
	if err := nvproxy.Register(vfsObj, uvmDevMajor); err != nil {
		return fmt.Errorf("registering nvproxy driver: %w", err)
	}
	info.nvidiaUVMDevMajor = uvmDevMajor
	if info.conf.NVProxyDocker {
		// In Docker mode, create all the device files now.
		// In non-Docker mode, these are instead created as part of
		// `createDeviceFiles`, using the spec's Device list.
		minors, err := specutils.FindAllGPUDevices("/")
		if err != nil {
			return fmt.Errorf("getting nvidia devices: %w", err)
		}
		if err := nvproxy.CreateDriverDevtmpfsFiles(ctx, a, uvmDevMajor); err != nil {
			return fmt.Errorf("creating nvproxy devtmpfs files: %w", err)
		}
		for _, minor := range minors {
			if err := nvproxy.CreateIndexDevtmpfsFile(ctx, a, minor); err != nil {
				return fmt.Errorf("creating nvproxy devtmpfs file for device minor %d: %w", minor, err)
			}
		}
	}
	return nil
}

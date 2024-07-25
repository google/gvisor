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
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/abi/nvgpu"
	"gvisor.dev/gvisor/pkg/abi/tpu"
	"gvisor.dev/gvisor/pkg/cleanup"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/devutil"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/fd"
	"gvisor.dev/gvisor/pkg/fspath"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/devices/accel"
	"gvisor.dev/gvisor/pkg/sentry/devices/memdev"
	"gvisor.dev/gvisor/pkg/sentry/devices/nvproxy"
	"gvisor.dev/gvisor/pkg/sentry/devices/tpuproxy"
	"gvisor.dev/gvisor/pkg/sentry/devices/ttydev"
	"gvisor.dev/gvisor/pkg/sentry/devices/tundev"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/cgroupfs"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/dev"
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
	"gvisor.dev/gvisor/pkg/sentry/pgalloc"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/runsc/config"
	"gvisor.dev/gvisor/runsc/specutils"
)

// Supported filesystems that map to different internal filesystems.
const (
	Bind   = "bind"
	Nonefs = "none"
)

// SelfFilestorePrefix is the prefix of the self filestore file name.
const SelfFilestorePrefix = ".gvisor.filestore."

const (
	pciPathGlobTPUv4   = "/sys/devices/pci0000:*/*/accel/accel*"
	pciPathGlobTPUv5   = "/sys/devices/pci0000:*/*/vfio-dev/vfio*"
	iommuGroupPathGlob = "/sys/kernel/iommu_groups/*/devices/*"
)

// SelfFilestorePath returns the path at which the self filestore file is
// stored for a given mount.
func SelfFilestorePath(mountSrc, sandboxID string) string {
	// We will place the filestore file in a gVisor specific hidden file inside
	// the mount being overlaid itself. The same volume can be overlaid by
	// multiple sandboxes. So make the filestore file unique to a sandbox by
	// suffixing the sandbox ID.
	return path.Join(mountSrc, selfFilestoreName(sandboxID))
}

func selfFilestoreName(sandboxID string) string {
	return SelfFilestorePrefix + sandboxID
}

// tmpfs has some extra supported options that we must pass through.
var tmpfsAllowedData = []string{"mode", "size", "uid", "gid"}

func registerFilesystems(k *kernel.Kernel, info *containerInfo) error {
	ctx := k.SupervisorContext()
	vfsObj := k.VFS()

	vfsObj.MustRegisterFilesystemType(cgroupfs.Name, &cgroupfs.FilesystemType{}, &vfs.RegisterFilesystemTypeOptions{
		AllowUserMount: true,
		AllowUserList:  true,
	})
	vfsObj.MustRegisterFilesystemType(devpts.Name, &devpts.FilesystemType{}, &vfs.RegisterFilesystemTypeOptions{
		AllowUserList: true,
		// TODO(b/29356795): Users may mount this once the terminals are in a
		//  usable state.
		AllowUserMount: true,
	})
	vfsObj.MustRegisterFilesystemType(dev.Name, &dev.FilesystemType{}, &vfs.RegisterFilesystemTypeOptions{})
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

	if err := nvproxyRegisterDevices(info, vfsObj); err != nil {
		return err
	}

	if err := tpuProxyRegisterDevices(info, vfsObj); err != nil {
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

	mns, err := mntr.mountAll(rootCtx, rootCreds, info.spec, info.conf, &rootProcArgs)
	if err != nil {
		return fmt.Errorf("failed to setupFS: %w", err)
	}
	procArgs.MountNamespace = mns

	// If cgroups are mounted, then only check for the cgroup mounts per
	// container. Otherwise the root cgroups will be enabled.
	if mntr.cgroupsMounted {
		cgroupRegistry := mntr.k.CgroupRegistry()
		for _, ctrl := range kernel.CgroupCtrls {
			cg, err := cgroupRegistry.FindCgroup(ctx, ctrl, "/"+mntr.containerID)
			if err != nil {
				return fmt.Errorf("cgroup mount for controller %v not found", ctrl)
			}
			if procArgs.InitialCgroups == nil {
				procArgs.InitialCgroups = make(map[kernel.Cgroup]struct{}, len(kernel.CgroupCtrls))
			}
			procArgs.InitialCgroups[cg] = struct{}{}
		}
	}

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
func compileMounts(spec *specs.Spec, conf *config.Config, containerID string) []specs.Mount {
	// Keep track of whether proc and sys were mounted.
	var procMounted, sysMounted, devMounted, devptsMounted, cgroupsMounted bool
	var mounts []specs.Mount

	// Mount all submounts from the spec.
	for _, m := range spec.Mounts {
		// Mount all the cgroup controllers when "/sys/fs/cgroup" mount
		// is present. If any other cgroup controller mounts are there,
		// it will be a no-op, drop them.
		if m.Type == cgroupfs.Name && cgroupsMounted {
			continue
		}

		switch filepath.Clean(m.Destination) {
		case "/proc":
			procMounted = true
		case "/sys":
			sysMounted = true
		case "/dev":
			m.Type = dev.Name
			devMounted = true
		case "/dev/pts":
			m.Type = devpts.Name
			devptsMounted = true
		case "/sys/fs/cgroup":
			cgroupsMounted = true
		}

		mounts = append(mounts, m)
	}

	// Mount proc and sys even if the user did not ask for it, as the spec
	// says we SHOULD.
	var mandatoryMounts []specs.Mount

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
			Type:        dev.Name,
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

// consumeMountOptions consumes mount options from opts based on allowedKeys
// and returns the remaining and consumed options.
func consumeMountOptions(opts []string, allowedKeys ...string) ([]string, []string, error) {
	var rem, out []string
	for _, o := range opts {
		ok, err := parseMountOption(o, allowedKeys...)
		if err != nil {
			return nil, nil, err
		}
		if ok {
			out = append(out, o)
		} else {
			rem = append(rem, o)
		}
	}
	return rem, out, nil
}

func parseMountOption(opt string, allowedKeys ...string) (bool, error) {
	kv := strings.SplitN(opt, "=", 3)
	if len(kv) > 2 {
		return false, fmt.Errorf("invalid option %q", opt)
	}
	return slices.Contains(allowedKeys, kv[0]), nil
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

	// goferFDs is the list of FDs to be dispensed for gofer mounts.
	goferFDs fdDispenser

	// goferFilestoreFDs are FDs to the regular files that will back the tmpfs or
	// overlayfs mount for certain gofer mounts.
	goferFilestoreFDs fdDispenser

	// devGoferFD is the FD to attach the sandbox to the dev gofer.
	devGoferFD *fd.FD

	// goferMountConfs contains information about how the gofer mounts have been
	// configured. The first entry is for rootfs and the following entries are
	// for bind mounts in Spec.Mounts (in the same order).
	goferMountConfs []GoferMountConf

	k *kernel.Kernel

	// hints is the set of pod mount hints for the sandbox.
	hints *PodMountHints

	// sharedMounts is a map of shared mounts that can be reused across
	// containers.
	sharedMounts map[string]*vfs.Mount

	// productName is the value to show in
	// /sys/devices/virtual/dmi/id/product_name.
	productName string

	// containerID is the ID for the container.
	containerID string

	// sandboxID is the ID for the whole sandbox.
	sandboxID     string
	containerName string

	// cgroupsMounted indicates if cgroups are mounted in the container.
	// This is used to set the InitialCgroups before starting the container
	// process.
	cgroupsMounted bool
}

func newContainerMounter(info *containerInfo, k *kernel.Kernel, hints *PodMountHints, sharedMounts map[string]*vfs.Mount, productName string, sandboxID string) *containerMounter {
	return &containerMounter{
		root:              info.spec.Root,
		mounts:            compileMounts(info.spec, info.conf, info.procArgs.ContainerID),
		goferFDs:          fdDispenser{fds: info.goferFDs},
		goferFilestoreFDs: fdDispenser{fds: info.goferFilestoreFDs},
		devGoferFD:        info.devGoferFD,
		goferMountConfs:   info.goferMountConfs,
		k:                 k,
		hints:             hints,
		sharedMounts:      sharedMounts,
		productName:       productName,
		containerID:       info.cid,
		sandboxID:         sandboxID,
		containerName:     info.containerName,
	}
}

func (c *containerMounter) checkDispenser() error {
	if !c.goferFDs.empty() {
		return fmt.Errorf("not all gofer FDs were consumed, remaining: %v", c.goferFDs)
	}
	if !c.goferFilestoreFDs.empty() {
		return fmt.Errorf("not all gofer Filestore FDs were consumed, remaining: %v", c.goferFilestoreFDs)
	}
	if c.devGoferFD != nil && c.devGoferFD.FD() >= 0 {
		return fmt.Errorf("dev gofer FD was not consumed: %d", c.devGoferFD.FD())
	}
	return nil
}

func getMountAccessType(conf *config.Config, hint *MountHint) config.FileAccessType {
	if hint != nil {
		return hint.fileAccessType()
	}
	return conf.FileAccessMounts
}

func (c *containerMounter) mountAll(rootCtx context.Context, rootCreds *auth.Credentials, spec *specs.Spec, conf *config.Config, rootProcArgs *kernel.CreateProcessArgs) (*vfs.MountNamespace, error) {
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
	if err := c.mountSubmounts(rootCtx, spec, conf, mns, rootCreds); err != nil {
		return nil, fmt.Errorf("mounting submounts: %w", err)
	}

	return mns, nil
}

// createMountNamespace creates the container's root mount and namespace.
func (c *containerMounter) createMountNamespace(ctx context.Context, conf *config.Config, creds *auth.Credentials) (*vfs.MountNamespace, error) {
	ioFD := c.goferFDs.remove()
	rootfsConf := c.goferMountConfs[0]

	var (
		fsName string
		opts   *vfs.MountOptions
	)
	switch {
	case rootfsConf.ShouldUseLisafs():
		fsName = gofer.Name

		data := goferMountData(ioFD, conf.FileAccess, conf)

		// We can't check for overlayfs here because sandbox is chroot'ed and gofer
		// can only send mount options for specs.Mounts (specs.Root is missing
		// Options field). So assume root is always on top of overlayfs.
		data = append(data, "overlayfs_stale_read")

		// Configure the gofer dentry cache size.
		gofer.SetDentryCacheSize(conf.DCache)

		opts = &vfs.MountOptions{
			ReadOnly: c.root.Readonly,
			GetFilesystemOptions: vfs.GetFilesystemOptions{
				InternalMount: true,
				Data:          strings.Join(data, ","),
				InternalData: gofer.InternalFilesystemOptions{
					UniqueID: vfs.RestoreID{
						ContainerName: c.containerName,
						Path:          "/",
					},
				},
			},
		}

	case rootfsConf.ShouldUseErofs():
		fsName = erofs.Name
		opts = &vfs.MountOptions{
			ReadOnly: c.root.Readonly,
			GetFilesystemOptions: vfs.GetFilesystemOptions{
				InternalMount: true,
				Data:          fmt.Sprintf("ifd=%d", ioFD),
				InternalData: erofs.InternalFilesystemOptions{
					UniqueID: vfs.RestoreID{
						ContainerName: c.containerName,
						Path:          "/",
					},
				},
			},
		}

	default:
		return nil, fmt.Errorf("unsupported rootfs config: %+v", rootfsConf)
	}

	log.Infof("Mounting root with %s, ioFD: %d", fsName, ioFD)

	if rootfsConf.ShouldUseOverlayfs() {
		log.Infof("Adding overlay on top of root")
		var (
			err         error
			cleanup     func()
			filestoreFD *fd.FD
		)
		if rootfsConf.IsFilestorePresent() {
			filestoreFD = c.goferFilestoreFDs.removeAsFD()
		}
		opts, cleanup, err = c.configureOverlay(ctx, conf, creds, opts, fsName, filestoreFD, rootfsConf, "/")
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
		&vfs.MountOptions{ReadOnly: true, Locked: true}, c.k)
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
func (c *containerMounter) configureOverlay(ctx context.Context, conf *config.Config, creds *auth.Credentials, lowerOpts *vfs.MountOptions, lowerFSName string, filestoreFD *fd.FD, mountConf GoferMountConf, dst string) (*vfs.MountOptions, func(), error) {
	// First copy options from lower layer to upper layer and overlay. Clear
	// filesystem specific options.
	upperOpts := *lowerOpts
	upperOpts.GetFilesystemOptions = vfs.GetFilesystemOptions{InternalMount: true}

	overlayOpts := *lowerOpts
	overlayOpts.GetFilesystemOptions = vfs.GetFilesystemOptions{InternalMount: true}

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
		// If a mount is being overlaid, it should not be limited by the default
		// tmpfs size limit.
		DisableDefaultSizeLimit: true,
	}
	if filestoreFD != nil {
		// Create memory file for disk-backed overlays.
		mf, err := createPrivateMemoryFile(filestoreFD.ReleaseToFile("overlay-filestore"), vfs.RestoreID{ContainerName: c.containerName, Path: dst})
		if err != nil {
			return nil, nil, fmt.Errorf("failed to create memory file for overlay: %v", err)
		}
		tmpfsOpts.MemoryFile = mf
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
	if mountConf.IsSelfBacked() {
		if err := overlay.CreateWhiteout(ctx, c.k.VFS(), creds, &vfs.PathOperation{
			Root:  upperRootVD,
			Start: upperRootVD,
			Path:  fspath.Parse(selfFilestoreName(c.sandboxID)),
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

func (c *containerMounter) mountSubmounts(ctx context.Context, spec *specs.Spec, conf *config.Config, mns *vfs.MountNamespace, creds *auth.Credentials) error {
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

		if submount.hint != nil && submount.hint.ShouldShareMount() {
			sharedMount, err := c.getSharedMount(ctx, spec, conf, submount, creds)
			if err != nil {
				return fmt.Errorf("getting shared mount %q: %w", submount.hint.Name, err)
			}
			mnt, err = c.mountSharedSubmount(ctx, conf, mns, creds, submount, sharedMount)
			if err != nil {
				return fmt.Errorf("mount shared mount %q to %q: %v", submount.hint.Name, submount.mount.Destination, err)
			}
		} else if submount.mount.Type == cgroupfs.Name {
			// Mount all the cgroups controllers.
			if err := c.mountCgroupSubmounts(ctx, spec, conf, mns, creds, submount); err != nil {
				return fmt.Errorf("mount cgroup %q: %w", submount.mount.Destination, err)
			}
		} else {
			mnt, err = c.mountSubmount(ctx, spec, conf, mns, creds, submount)
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

	if err := c.mountTmp(ctx, spec, conf, creds, mns); err != nil {
		return fmt.Errorf(`mount submount "/tmp": %w`, err)
	}
	return nil
}

type mountInfo struct {
	mount          *specs.Mount
	goferFD        *fd.FD
	hint           *MountHint
	goferMountConf GoferMountConf
	filestoreFD    *fd.FD
}

func (c *containerMounter) prepareMounts() ([]mountInfo, error) {
	// If device gofer exists, connect to it.
	if c.devGoferFD != nil {
		if err := c.k.AddDevGofer(c.containerName, c.devGoferFD.Release()); err != nil {
			return nil, err
		}
	}
	// Associate bind mounts with their FDs before sorting since there is an
	// undocumented assumption that FDs are dispensed in the order in which
	// they are required by mounts.
	var mounts []mountInfo
	goferMntIdx := 1 // First index is for rootfs.
	for i := range c.mounts {
		info := mountInfo{
			mount: &c.mounts[i],
			hint:  c.hints.FindMount(c.mounts[i].Source),
		}
		specutils.MaybeConvertToBindMount(info.mount)
		if specutils.IsGoferMount(*info.mount) {
			info.goferMountConf = c.goferMountConfs[goferMntIdx]
			if info.goferMountConf.ShouldUseLisafs() {
				info.goferFD = c.goferFDs.removeAsFD()
			}
			if info.goferMountConf.IsFilestorePresent() {
				info.filestoreFD = c.goferFilestoreFDs.removeAsFD()
			}
			if info.goferMountConf.ShouldUseTmpfs() {
				specutils.ChangeMountType(info.mount, tmpfs.Name)
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

func (c *containerMounter) mountSubmount(ctx context.Context, spec *specs.Spec, conf *config.Config, mns *vfs.MountNamespace, creds *auth.Credentials, submount *mountInfo) (*vfs.Mount, error) {
	fsName, opts, err := getMountNameAndOptions(spec, conf, submount, c.productName, c.containerName)
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

	if submount.goferMountConf.ShouldUseOverlayfs() {
		log.Infof("Adding overlay on top of mount %q", submount.mount.Destination)
		var cleanup func()
		opts, cleanup, err = c.configureOverlay(ctx, conf, creds, opts, fsName, submount.filestoreFD, submount.goferMountConf, submount.mount.Destination)
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
func getMountNameAndOptions(spec *specs.Spec, conf *config.Config, m *mountInfo, productName, containerName string) (string, *vfs.MountOptions, error) {
	fsName := m.mount.Type
	var (
		mopts        = m.mount.Options
		data         []string
		internalData any
	)

	// Find filesystem name and FS specific data field.
	switch m.mount.Type {
	case devpts.Name, dev.Name:
		// Nothing to do.

	case Nonefs:
		fsName = sys.Name

	case proc.Name:
		internalData = newProcInternalData(spec)

	case sys.Name:
		sysData := &sys.InternalData{EnableTPUProxyPaths: specutils.TPUProxyIsEnabled(spec, conf)}
		if len(productName) > 0 {
			sysData.ProductName = productName
		}
		internalData = sysData

	case tmpfs.Name:
		var err error
		mopts, data, err = consumeMountOptions(mopts, tmpfsAllowedData...)
		if err != nil {
			return "", nil, err
		}
		if m.filestoreFD != nil {
			mf, err := createPrivateMemoryFile(m.filestoreFD.ReleaseToFile("tmpfs-filestore"), vfs.RestoreID{ContainerName: containerName, Path: m.mount.Destination})
			if err != nil {
				return "", nil, fmt.Errorf("failed to create memory file for tmpfs: %v", err)
			}
			internalData = tmpfs.FilesystemOpts{
				MemoryFile: mf,
				// If a mount is being overlaid with tmpfs, it should not be limited by
				// the default tmpfs size limit.
				DisableDefaultSizeLimit: true,
			}
		}

	case Bind:
		fsName = gofer.Name
		if m.goferFD == nil {
			// Check that an FD was provided to fails fast.
			return "", nil, fmt.Errorf("gofer mount requires a connection FD")
		}
		var err error
		mopts, data, err = consumeMountOptions(mopts, gofer.SupportedMountOptions...)
		if err != nil {
			return "", nil, err
		}
		data = append(data, goferMountData(m.goferFD.Release(), getMountAccessType(conf, m.hint), conf)...)
		internalData = gofer.InternalFilesystemOptions{
			UniqueID: vfs.RestoreID{
				ContainerName: containerName,
				Path:          m.mount.Destination,
			},
		}

	case cgroupfs.Name:
		var err error
		mopts, data, err = consumeMountOptions(mopts, cgroupfs.SupportedMountOptions...)
		if err != nil {
			return "", nil, err
		}

	default:
		log.Warningf("ignoring unknown filesystem type %q", m.mount.Type)
		return "", nil, nil
	}

	opts := ParseMountOptions(mopts)
	opts.GetFilesystemOptions = vfs.GetFilesystemOptions{
		Data:          strings.Join(data, ","),
		InternalData:  internalData,
		InternalMount: true,
	}

	return fsName, opts, nil
}

// ParseMountOptions converts specs.Mount.Options to vfs.MountOptions.
func ParseMountOptions(opts []string) *vfs.MountOptions {
	mountOpts := &vfs.MountOptions{
		GetFilesystemOptions: vfs.GetFilesystemOptions{
			InternalMount: true,
		},
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

func createPrivateMemoryFile(file *os.File, restoreID vfs.RestoreID) (*pgalloc.MemoryFile, error) {
	mfOpts := pgalloc.MemoryFileOpts{
		// Private memory files are usually backed by files on disk. Ideally we
		// would confirm with fstatfs(2) but that is prohibited by seccomp.
		DiskBackedFile: true,
		// Disk backed files need to be decommited on destroy to release disk space.
		DecommitOnDestroy: true,
		// sentry's seccomp filters don't allow the mmap(2) syscalls that
		// pgalloc.IMAWorkAroundForMemFile() uses. Users of private memory files
		// are expected to have performed the work around outside the sandbox.
		DisableIMAWorkAround: true,
		// Private memory files need to be restored correctly using this ID.
		RestoreID: restoreID.String(),
	}
	return pgalloc.NewMemoryFile(file, mfOpts)
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
func (c *containerMounter) mountTmp(ctx context.Context, spec *specs.Spec, conf *config.Config, creds *auth.Credentials, mns *vfs.MountNamespace) error {
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
		if _, err := c.mountSubmount(ctx, spec, conf, mns, creds, &mountInfo{mount: &tmpMount}); err != nil {
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

func (c *containerMounter) getSharedMount(ctx context.Context, spec *specs.Spec, conf *config.Config, mount *mountInfo, creds *auth.Credentials) (*vfs.Mount, error) {
	sharedMount, ok := c.sharedMounts[mount.hint.Mount.Source]
	if ok {
		log.Infof("Using existing shared mount %q from %q type %q", mount.hint.Name, mount.hint.Mount.Source, mount.hint.Mount.Type)
		if mount.goferFD != nil {
			panic(fmt.Errorf("extra goferFD provided for shared mount %q", mount.hint.Name))
		}
		if mount.filestoreFD != nil {
			mount.filestoreFD.Close()
		}
		return sharedMount, nil
	}
	log.Infof("Mounting master of shared mount %q from %q type %q", mount.hint.Name, mount.hint.Mount.Source, mount.hint.Mount.Type)
	sharedMount, err := c.mountSharedMaster(ctx, spec, conf, mount, creds)
	if err != nil {
		return nil, fmt.Errorf("mounting shared master %q: %v", mount.hint.Name, err)
	}
	c.sharedMounts[mount.hint.Mount.Source] = sharedMount
	return sharedMount, nil
}

// mountCgroupMounts mounts the cgroups which are shared across all containers.
// Postcondition: Initialized k.cgroupMounts on success.
func (l *Loader) mountCgroupMounts(conf *config.Config, creds *auth.Credentials) error {
	ctx := l.k.SupervisorContext()
	for _, sopts := range kernel.CgroupCtrls {
		mopts := &vfs.MountOptions{
			GetFilesystemOptions: vfs.GetFilesystemOptions{
				Data:          string(sopts),
				InternalMount: true,
			},
		}
		fs, root, err := l.k.VFS().NewFilesystem(ctx, creds, "cgroup", cgroupfs.Name, mopts)
		if err != nil {
			return err
		}

		mount := l.k.VFS().NewDisconnectedMount(fs, root, mopts)
		// Private so that mounts created by containers do not appear
		// in other container's cgroup paths.
		l.k.VFS().SetMountPropagation(mount, linux.MS_PRIVATE, false)
		l.k.AddCgroupMount(string(sopts), &kernel.CgroupMount{
			Fs:    fs,
			Root:  root,
			Mount: mount,
		})
	}
	log.Infof("created cgroup mounts for controllers %v", kernel.CgroupCtrls)
	return nil
}

// mountCgroupSubmounts mounts all the cgroup controller submounts for the
// container. The cgroup submounts are created under the root controller mount
// with containerID as the directory name and then bind mounts this directory
// inside the container's mount namespace.
func (c *containerMounter) mountCgroupSubmounts(ctx context.Context, spec *specs.Spec, conf *config.Config, mns *vfs.MountNamespace, creds *auth.Credentials, submount *mountInfo) error {
	root := mns.Root(ctx)
	defer root.DecRef(ctx)

	// Mount "/sys/fs/cgroup" in the container's mount namespace.
	submount.mount.Type = tmpfs.Name
	mnt, err := c.mountSubmount(ctx, spec, conf, mns, creds, submount)
	if err != nil {
		return err
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

	// Mount all the cgroup controllers in the container's mount namespace.
	mountCtx := vfs.WithRoot(vfs.WithMountNamespace(ctx, mns), root)
	for _, ctrl := range kernel.CgroupCtrls {
		ctrlName := string(ctrl)
		cgroupMnt := c.k.GetCgroupMount(ctrlName)
		if cgroupMnt == nil {
			return fmt.Errorf("cgroup mount for controller %s not found", ctrlName)
		}

		cgroupMntVD := vfs.MakeVirtualDentry(cgroupMnt.Mount, cgroupMnt.Root)
		sourcePop := vfs.PathOperation{
			Root:  cgroupMntVD,
			Start: cgroupMntVD,
			// Use the containerID as the cgroup path.
			Path: fspath.Parse(c.containerID),
		}
		if err := c.k.VFS().MkdirAt(mountCtx, creds, &sourcePop, &vfs.MkdirOptions{
			Mode: 0755,
		}); err != nil {
			log.Infof("error in creating directory %v", err)
			return err
		}

		// Bind mount the new cgroup directory into the container's mount namespace.
		destination := "/sys/fs/cgroup/" + ctrlName
		if err := c.k.VFS().MakeSyntheticMountpoint(mountCtx, destination, root, creds); err != nil {
			// Log a warning, but attempt the mount anyway.
			log.Warningf("Failed to create mount point %q: %v", destination, err)
		}

		target := &vfs.PathOperation{
			Root:  root,
			Start: root,
			Path:  fspath.Parse(destination),
		}
		if err := c.k.VFS().BindAt(mountCtx, creds, &sourcePop, target, false); err != nil {
			log.Infof("error in bind mounting %v", err)
			return err
		}
	}
	c.cgroupsMounted = true
	return nil
}

// mountSharedMaster mounts the master of a volume that is shared among
// containers in a pod.
func (c *containerMounter) mountSharedMaster(ctx context.Context, spec *specs.Spec, conf *config.Config, mntInfo *mountInfo, creds *auth.Credentials) (*vfs.Mount, error) {
	// Mount the master using the options from the hint (mount annotations).
	origOpts := mntInfo.mount.Options
	mntInfo.mount.Options = mntInfo.hint.Mount.Options
	fsName, opts, err := getMountNameAndOptions(spec, conf, mntInfo, c.productName, c.containerName)
	mntInfo.mount.Options = origOpts
	if err != nil {
		return nil, err
	}
	if len(fsName) == 0 {
		return nil, fmt.Errorf("mount type not supported %q", mntInfo.hint.Mount.Type)
	}
	return c.k.VFS().MountDisconnected(ctx, creds, "", fsName, opts)
}

// mountSharedSubmount binds mount to a previously mounted volume that is shared
// among containers in the same pod.
func (c *containerMounter) mountSharedSubmount(ctx context.Context, conf *config.Config, mns *vfs.MountNamespace, creds *auth.Credentials, mntInfo *mountInfo, sharedMount *vfs.Mount) (*vfs.Mount, error) {
	if err := mntInfo.hint.checkCompatible(mntInfo.mount); err != nil {
		return nil, err
	}

	// Generate mount point specific opts using mntInfo.mount.
	opts := ParseMountOptions(mntInfo.mount.Options)
	newMnt := c.k.VFS().NewDisconnectedMount(sharedMount.Filesystem(), sharedMount.Root(), opts)
	defer newMnt.DecRef(ctx)

	root := mns.Root(ctx)
	defer root.DecRef(ctx)
	target := &vfs.PathOperation{
		Root:  root,
		Start: root,
		Path:  fspath.Parse(mntInfo.mount.Destination),
	}

	if err := c.makeMountPoint(ctx, creds, mns, mntInfo.mount.Destination); err != nil {
		return nil, fmt.Errorf("creating mount point %q: %w", mntInfo.mount.Destination, err)
	}

	if err := c.k.VFS().ConnectMountAt(ctx, creds, newMnt, target); err != nil {
		return nil, err
	}
	log.Infof("Mounted %q type shared bind to %q", mntInfo.mount.Destination, mntInfo.hint.Name)
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
func (c *containerMounter) configureRestore(fdmap map[vfs.RestoreID]int, mfmap map[string]*pgalloc.MemoryFile) error {
	// Compare createMountNamespace(); rootfs always consumes a gofer FD and a
	// filestore FD is consumed if the rootfs GoferMountConf indicates so.
	rootKey := vfs.RestoreID{ContainerName: c.containerName, Path: "/"}
	fdmap[rootKey] = c.goferFDs.remove()

	if rootfsConf := c.goferMountConfs[0]; rootfsConf.IsFilestorePresent() {
		mf, err := createPrivateMemoryFile(c.goferFilestoreFDs.removeAsFD().ReleaseToFile("overlay-filestore"), rootKey)
		if err != nil {
			return fmt.Errorf("failed to create private memory file for mount rootfs: %w", err)
		}
		mfmap[rootKey.String()] = mf
	}
	// prepareMounts() consumes the remaining FDs for submounts.
	mounts, err := c.prepareMounts()
	if err != nil {
		return err
	}
	for i := range mounts {
		submount := &mounts[i]
		if submount.goferFD != nil {
			key := vfs.RestoreID{ContainerName: c.containerName, Path: submount.mount.Destination}
			fdmap[key] = submount.goferFD.Release()
		}
		if submount.filestoreFD != nil {
			key := vfs.RestoreID{ContainerName: c.containerName, Path: submount.mount.Destination}
			mf, err := createPrivateMemoryFile(submount.filestoreFD.ReleaseToFile("overlay-filestore"), key)
			if err != nil {
				return fmt.Errorf("failed to create private memory file for mount %q: %w", submount.mount.Destination, err)
			}
			mfmap[key.String()] = mf
		}
	}
	return nil
}

func createDeviceFiles(ctx context.Context, creds *auth.Credentials, info *containerInfo, vfsObj *vfs.VirtualFilesystem, root vfs.VirtualDentry) error {
	if info.spec.Linux != nil {
		// Create any device files specified in the spec.
		for _, dev := range info.spec.Linux.Devices {
			if err := createDeviceFile(ctx, creds, info, vfsObj, root, dev); err != nil {
				return err
			}
		}
	}
	if specutils.GPUFunctionalityRequestedViaHook(info.spec, info.conf) {
		// When using nvidia-container-runtime-hook, devices are not injected into
		// spec.Linux.Devices. So manually create appropriate device files.
		mode := os.FileMode(0666)
		nvidiaDevs := []specs.LinuxDevice{
			specs.LinuxDevice{Path: "/dev/nvidiactl", Type: "c", Major: nvgpu.NV_MAJOR_DEVICE_NUMBER, Minor: nvgpu.NV_CONTROL_DEVICE_MINOR, FileMode: &mode},
			specs.LinuxDevice{Path: "/dev/nvidia-uvm", Type: "c", Major: int64(info.nvidiaUVMDevMajor), Minor: nvgpu.NVIDIA_UVM_PRIMARY_MINOR_NUMBER, FileMode: &mode},
		}
		devClient := devutil.GoferClientFromContext(ctx)
		if devClient == nil {
			return fmt.Errorf("dev gofer client not found in context")
		}
		names, err := devClient.DirentNames(ctx)
		if err != nil {
			return fmt.Errorf("failed to get names of dirents from dev gofer: %w", err)
		}
		nvidiaDeviceRegex := regexp.MustCompile(`^nvidia(\d+)$`)
		for _, name := range names {
			ms := nvidiaDeviceRegex.FindStringSubmatch(name)
			if ms == nil {
				continue
			}
			minor, err := strconv.ParseUint(ms[1], 10, 32)
			if err != nil {
				return fmt.Errorf("invalid nvidia device name %q: %w", name, err)
			}
			nvidiaDevs = append(nvidiaDevs, specs.LinuxDevice{Path: fmt.Sprintf("/dev/nvidia%d", minor), Type: "c", Major: nvgpu.NV_MAJOR_DEVICE_NUMBER, Minor: int64(minor), FileMode: &mode})
		}
		for _, nvidiaDev := range nvidiaDevs {
			if err := createDeviceFile(ctx, creds, info, vfsObj, root, nvidiaDev); err != nil {
				return err
			}
		}
	}
	return nil
}

func createDeviceFile(ctx context.Context, creds *auth.Credentials, info *containerInfo, vfsObj *vfs.VirtualFilesystem, root vfs.VirtualDentry, devSpec specs.LinuxDevice) error {
	mode := linux.FileMode(devSpec.FileMode.Perm())
	var major, minor uint32
	// See https://github.com/opencontainers/runtime-spec/blob/main/config-linux.md#devices.
	switch devSpec.Type {
	case "b":
		mode |= linux.S_IFBLK
		major = uint32(devSpec.Major)
		minor = uint32(devSpec.Minor)
	case "c", "u":
		mode |= linux.S_IFCHR
		major = uint32(devSpec.Major)
		minor = uint32(devSpec.Minor)
	case "p":
		mode |= linux.S_IFIFO
	default:
		return fmt.Errorf("specified device at %q has invalid type %q", devSpec.Path, devSpec.Type)
	}
	if devSpec.Path == "/dev/nvidia-uvm" && info.nvidiaUVMDevMajor != 0 && major != info.nvidiaUVMDevMajor {
		// nvidia-uvm's major device number is dynamically assigned, so the
		// number that it has on the host may differ from the number that
		// it has in sentry VFS; switch from the former to the latter.
		log.Infof("Switching /dev/nvidia-uvm device major number from %d to %d", devSpec.Major, info.nvidiaUVMDevMajor)
		major = info.nvidiaUVMDevMajor
	}
	return dev.CreateDeviceFile(ctx, vfsObj, creds, root, devSpec.Path, major, minor, mode, devSpec.UID, devSpec.GID)
}

// registerTPUDevice registers a TPU device in vfsObj based on the given device ID.
func registerTPUDevice(vfsObj *vfs.VirtualFilesystem, minor, deviceNum uint32, deviceID int64) error {
	switch deviceID {
	case tpu.TPUV4DeviceID, tpu.TPUV4liteDeviceID:
		return accel.RegisterTPUDevice(vfsObj, minor, deviceID == tpu.TPUV4liteDeviceID)
	case tpu.TPUV5eDeviceID, tpu.TPUV5pDeviceID:
		return tpuproxy.RegisterTPUDevice(vfsObj, minor, deviceNum)
	default:
		return fmt.Errorf("unsupported TPU device with ID: 0x%x", deviceID)
	}
}

// pathGlobToPathRegex is a map that points a TPU PCI path glob to its path regex.
// TPU v4 devices are accessible via /sys/devices/pci0000:00/<pci_address>/accel/accel# on the host.
// TPU v5 devices are accessible via at /sys/devices/pci0000:00/<pci_address>/vfio-dev/vfio# on the host.
var pathGlobToPathRegex = map[string]string{
	pciPathGlobTPUv4: `^/sys/devices/pci0000:[[:xdigit:]]{2}/\d+:\d+:\d+\.\d+/accel/accel(\d+)$`,
	pciPathGlobTPUv5: `^/sys/devices/pci0000:[[:xdigit:]]{2}/\d+:\d+:\d+\.\d+/vfio-dev/vfio(\d+)$`,
}

func tpuProxyRegisterDevices(info *containerInfo, vfsObj *vfs.VirtualFilesystem) error {
	if !specutils.TPUProxyIsEnabled(info.spec, info.conf) {
		return nil
	}
	// Enumerate all potential PCI paths where TPU devices are available and register the found TPU devices.
	for pciPathGlobal, pathRegex := range pathGlobToPathRegex {
		pciAddrs, err := filepath.Glob(pciPathGlobal)
		if err != nil {
			return fmt.Errorf("enumerating PCI device files: %w", err)
		}
		pciPathRegex := regexp.MustCompile(pathRegex)
		for _, pciPath := range pciAddrs {
			ms := pciPathRegex.FindStringSubmatch(pciPath)
			if ms == nil {
				continue
			}
			deviceNum, err := strconv.ParseUint(ms[1], 10, 32)
			if err != nil {
				return fmt.Errorf("parsing PCI device number: %w", err)
			}
			var deviceIDBytes []byte
			if deviceIDBytes, err = os.ReadFile(path.Join(pciPath, "device/device")); err != nil {
				return fmt.Errorf("reading PCI device ID: %w", err)
			}
			deviceIDStr := strings.Replace(string(deviceIDBytes), "0x", "", -1)
			deviceID, err := strconv.ParseInt(strings.TrimSpace(deviceIDStr), 16, 64)
			if err != nil {
				return fmt.Errorf("parsing PCI device ID: %w", err)
			}
			// VFIO iommu groups correspond to the device minor number. Use these
			// paths to get the correct minor number for the sentry-internal TPU
			// device files.
			var minorNum int
			switch deviceID {
			case tpu.TPUV4DeviceID, tpu.TPUV4liteDeviceID:
				minorNum = int(deviceNum)
			case tpu.TPUV5eDeviceID, tpu.TPUV5pDeviceID:
				groupPaths, err := filepath.Glob(iommuGroupPathGlob)
				if err != nil {
					return fmt.Errorf("enumerating IOMMU group files: %w", err)
				}
				for _, groupPath := range groupPaths {
					pci := path.Base(groupPath)
					if strings.Contains(pciPath, pci) {
						minor, err := strconv.Atoi(strings.Split(groupPath, "/")[4])
						if err != nil {
							return fmt.Errorf("parsing IOMMU group minor number: %w", err)
						}
						minorNum = minor
						break
					}
				}
			default:
				return fmt.Errorf("unsupported TPU device with ID: 0x%x", deviceID)
			}
			if err := registerTPUDevice(vfsObj, uint32(minorNum), uint32(deviceNum), deviceID); err != nil {
				return fmt.Errorf("registering TPU driver: %w", err)
			}
		}
	}
	if err := tpuproxy.RegisterVfioDevice(vfsObj); err != nil {
		return fmt.Errorf("registering vfio driver: %w", err)
	}
	return nil
}

func nvproxyRegisterDevices(info *containerInfo, vfsObj *vfs.VirtualFilesystem) error {
	if !specutils.NVProxyEnabled(info.spec, info.conf) {
		return nil
	}
	uvmDevMajor, err := vfsObj.GetDynamicCharDevMajor()
	if err != nil {
		return fmt.Errorf("reserving device major number for nvidia-uvm: %w", err)
	}
	if err := nvproxy.Register(vfsObj, info.nvidiaDriverVersion, uvmDevMajor); err != nil {
		return fmt.Errorf("registering nvproxy driver: %w", err)
	}
	info.nvidiaUVMDevMajor = uvmDevMajor
	return nil
}

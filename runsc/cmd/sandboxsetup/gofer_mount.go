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

package sandboxsetup

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/unet"
	"gvisor.dev/gvisor/runsc/cmd/util"
	"gvisor.dev/gvisor/runsc/config"
	"gvisor.dev/gvisor/runsc/specutils"
)

// ProcFDBindMount is the path where /proc/self/fd is bind-mounted inside the
// gofer's mount tree. Redhat distros don't allow bind-mounts in /proc/self
// directories due to SELinux rules.
const ProcFDBindMount = "/proc/fs"

// vfioPathDir is the directory containing VFIO device nodes.
const vfioPathDir = "/dev/vfio"

// MountOpener opens a mount source when the gofer process cannot access it
// directly (e.g. due to permission restrictions in a user namespace). It
// returns the opened file for the mount source. The caller is responsible
// for closing the returned file. It may be nil if all mounts are directly
// accessible.
type MountOpener func(m *specs.Mount) (*os.File, error)

// NewSocket creates a unet.Socket from a file descriptor.
// It fatally exits if the socket cannot be created.
func NewSocket(ioFD int) *unet.Socket {
	socket, err := unet.NewSocket(ioFD)
	if err != nil {
		util.Fatalf("creating server on FD %d: %v", ioFD, err)
	}
	return socket
}

// WriteMounts serializes the given mounts as JSON and writes them to the
// given file descriptor.
func WriteMounts(mountsFD int, mounts []specs.Mount) error {
	bytes, err := json.Marshal(mounts)
	if err != nil {
		return err
	}

	f := os.NewFile(uintptr(mountsFD), "mounts file")
	defer f.Close()

	for written := 0; written < len(bytes); {
		w, err := f.Write(bytes[written:])
		if err != nil {
			return err
		}
		written += w
	}
	return nil
}

// SetupRootFS prepares the root filesystem for the gofer process. It mounts
// the container root, sets up submounts and /dev, and optionally remounts
// root as read-only. If chroot mode is active, it also performs a
// pivot_root.
//
// mountConfs must be indexed such that mountConfs[0] is the root filesystem
// configuration and subsequent entries correspond to spec mounts with
// mount configs.
func SetupRootFS(spec *specs.Spec, conf *config.Config, mountConfs []specutils.GoferMountConf, devIoFD int, mountOpener MountOpener) error {
	// Convert all shared mounts into slaves to be sure that nothing will be
	// propagated outside of our namespace.
	procPath := "/proc"
	if err := specutils.SafeMount("", "/", "", unix.MS_SLAVE|unix.MS_REC, "", procPath); err != nil {
		util.Fatalf("error converting mounts: %v", err)
	}

	root := spec.Root.Path
	if !conf.TestOnlyAllowRunAsCurrentUserWithoutChroot {
		// runsc can't be re-executed without /proc, so we create a tmpfs mount,
		// mount ./proc and ./root there, then move this mount to the root and after
		// setCapsAndCallSelf, runsc will chroot into /root.
		//
		// We need a directory to construct a new root and we know that
		// runsc can't start without /proc, so we can use it for this.
		flags := uintptr(unix.MS_NOSUID | unix.MS_NODEV | unix.MS_NOEXEC)
		if err := specutils.SafeMount("runsc-root", "/proc/fs", "tmpfs", flags, "", procPath); err != nil {
			util.Fatalf("error mounting tmpfs: %v", err)
		}
		if err := unix.Mount("", "/proc/fs", "", unix.MS_UNBINDABLE, ""); err != nil {
			util.Fatalf("error setting MS_UNBINDABLE")
		}
		// Prepare tree structure for pivot_root(2).
		if err := os.Mkdir("/proc/fs/proc", 0755); err != nil {
			util.Fatalf("error creating /proc/fs/proc: %v", err)
		}
		if err := os.Mkdir("/proc/fs/root", 0755); err != nil {
			util.Fatalf("error creating /proc/fs/root: %v", err)
		}
		if err := os.Mkdir("/proc/fs/etc", 0755); err != nil {
			util.Fatalf("error creating /proc/fs/etc: %v", err)
		}
		// This cannot use SafeMount because there's no available procfs. But we
		// know that /proc/fs is an empty tmpfs mount, so this is safe.
		if err := unix.Mount("/proc", "/proc/fs/proc", "", flags|unix.MS_RDONLY|unix.MS_BIND|unix.MS_REC, ""); err != nil {
			util.Fatalf("error mounting /proc/fs/proc: %v", err)
		}
		// self/fd is bind-mounted, so that the FD returned by
		// OpenProcSelfFD() does not allow escapes with walking ".." .
		if err := unix.Mount("/proc/fs/proc/self/fd", "/proc/fs/"+ProcFDBindMount,
			"", unix.MS_RDONLY|unix.MS_BIND|flags, ""); err != nil {
			util.Fatalf("error mounting proc/self/fd: %v", err)
		}
		if err := CopyFile("/proc/fs/etc/localtime", "/etc/localtime"); err != nil {
			log.Warningf("Failed to copy /etc/localtime: %v. UTC timezone will be used.", err)
		}
		root = "/proc/fs/root"
		procPath = "/proc/fs/proc"
	}

	rootfsConf := mountConfs[0]
	if rootfsConf.ShouldUseLisafs() {
		// Mount root path followed by submounts.
		if err := specutils.SafeMount(spec.Root.Path, root, "bind", unix.MS_BIND|unix.MS_REC, "", procPath); err != nil {
			return fmt.Errorf("mounting root on root (%q) err: %v", root, err)
		}

		flags := uint32(unix.MS_SLAVE | unix.MS_REC)
		if spec.Linux != nil && spec.Linux.RootfsPropagation != "" {
			flags = specutils.PropOptionsToFlags([]string{spec.Linux.RootfsPropagation})
		}
		if err := specutils.SafeMount("", root, "", uintptr(flags), "", procPath); err != nil {
			return fmt.Errorf("mounting root (%q) with flags: %#x, err: %v", root, flags, err)
		}
	}

	// Replace the current spec, with the clean spec with symlinks resolved.
	if err := SetupMounts(conf, spec.Mounts, root, procPath, mountConfs, mountOpener); err != nil {
		util.Fatalf("error setting up FS: %v", err)
	}

	// Set up /dev directory if needed.
	if devIoFD >= 0 {
		if err := SetupDev(spec, conf, root, procPath); err != nil {
			util.Fatalf("error setting up /dev: %v", err)
		}
	}

	// Check if root needs to be remounted as readonly.
	if rootfsConf.ShouldUseLisafs() && (spec.Root.Readonly || rootfsConf.ShouldUseOverlayfs()) {
		// If root is a mount point but not read-only, we can change mount options
		// to make it read-only for extra safety.
		// unix.MS_NOSUID and unix.MS_NODEV are included here not only
		// for safety reasons but also because they can be locked and
		// any attempts to unset them will fail.  See
		// mount_namespaces(7) for more details.
		log.Infof("Remounting root as readonly: %q", root)
		flags := uintptr(unix.MS_BIND | unix.MS_REMOUNT | unix.MS_RDONLY | unix.MS_NOSUID | unix.MS_NODEV)
		if err := specutils.SafeMount(root, root, "bind", flags, "", procPath); err != nil {
			return fmt.Errorf("remounting root as read-only with source: %q, target: %q, flags: %#x, err: %v", root, root, flags, err)
		}
	}

	if !conf.TestOnlyAllowRunAsCurrentUserWithoutChroot {
		if err := PivotRoot("/proc/fs"); err != nil {
			util.Fatalf("failed to change the root file system: %v", err)
		}
		if err := os.Chdir("/"); err != nil {
			util.Fatalf("failed to change working directory")
		}
	}
	return nil
}

// SetupMounts bind-mounts all mounts specified in the spec in their correct
// location inside root. It resolves relative paths and symlinks, and creates
// directories as needed.
//
// mountConfs is indexed such that mountConfs[0] is the root filesystem
// configuration, and mount iteration starts at index 1.
// mountOpener is called when the gofer process cannot directly access a mount
// source. It may be nil if all mounts are directly accessible.
func SetupMounts(conf *config.Config, mounts []specs.Mount, root, procPath string, mountConfs []specutils.GoferMountConf, mountOpener MountOpener) (retErr error) {
	mountIdx := 1 // First index is for rootfs.
	for _, m := range mounts {
		if !specutils.HasMountConfig(m) {
			continue
		}
		mountConf := mountConfs[mountIdx]
		mountIdx++
		if !mountConf.ShouldUseLisafs() {
			continue
		}

		dst, err := ResolveSymlinks(root, m.Destination)
		if err != nil {
			return fmt.Errorf("resolving symlinks to %q: %v", m.Destination, err)
		}

		flags := specutils.OptionsToFlags(m.Options) | unix.MS_BIND
		if mountConf.ShouldUseOverlayfs() {
			// Force mount read-only if writes are not going to be sent to it.
			flags |= unix.MS_RDONLY
		}

		log.Infof("Mounting src: %q, dst: %q, flags: %#x", m.Source, dst, flags)
		src := m.Source
		var srcFile *os.File
		if err := unix.Access(src, unix.R_OK); err != nil {
			if mountOpener == nil {
				return fmt.Errorf("cannot access mount source %q and no mount opener provided: %v", src, err)
			}
			// The current process doesn't have enough permissions
			// to open the mount, so let's try to open it via the
			// caller-provided opener.
			srcFile, err = mountOpener(&m)
			if err != nil {
				return fmt.Errorf("opening %s: %w", m.Source, err)
			}
			src = fmt.Sprintf("%s/self/fd/%d", procPath, srcFile.Fd())
		}
		err = specutils.SafeSetupAndMount(src, dst, m.Type, flags, procPath)
		if srcFile != nil {
			srcFile.Close()
		}
		if err != nil {
			return fmt.Errorf("mounting %+v: %v", m, err)
		}

		dstFD, err := unix.Open(dst, unix.O_PATH|unix.O_CLOEXEC, 0)
		if err != nil {
			return fmt.Errorf("Open(%s, _, _): %w", dst, err)
		}
		defer unix.Close(dstFD)
		// Apply mount options after creating all mount points.
		// Otherwise they can be remounted into read-only.
		defer func(dstFD int, flags uint32, dst string) {
			path := fmt.Sprintf("/proc/self/fd/%d", dstFD)
			// The gofer process doesn't execute anything natively.
			flags |= unix.MS_NOSUID

			statfs := unix.Statfs_t{}
			if err := unix.Statfs(path, &statfs); err != nil {
				retErr = fmt.Errorf("stat dst: %q", dst)
				return
			}
			lockedFlags := uint32(0)
			for _, f := range []struct {
				st, ms int
			}{
				// MS_NOSUID are always set.
				{unix.ST_RDONLY, unix.MS_RDONLY},
				{unix.ST_NOEXEC, unix.MS_NOEXEC},
				{unix.ST_NODEV, unix.MS_NODEV},
				{unix.ST_NOATIME, unix.MS_NOATIME},
				{unix.ST_NODIRATIME, unix.MS_NODIRATIME},
				{unix.ST_RELATIME, unix.MS_RELATIME},
			} {
				if int(statfs.Flags)&f.st == f.st {
					lockedFlags |= uint32(f.ms)
				}
			}
			if lockedFlags&unix.MS_NOATIME|unix.MS_RELATIME == 0 {
				lockedFlags |= unix.MS_STRICTATIME
			}

			// The previous SafeSetupAndMount creates a new bind-mount, but
			// it doesn't change mount flags. A separate MS_BIND|MS_REMOUNT
			// has to be done to apply the mount options.
			if err := unix.Mount("", path, "", uintptr(flags|lockedFlags|unix.MS_REMOUNT), ""); err != nil {
				retErr = fmt.Errorf("mount dst: %q, flags: %#x, err: %v", dst, flags, err)
				return
			}
		}(dstFD, flags, dst)

		// Set propagation options that cannot be set together with other options.
		flags = specutils.PropOptionsToFlags(m.Options)
		if flags != 0 {
			if err := specutils.SafeMount("", dst, "", uintptr(flags), "", procPath); err != nil {
				return fmt.Errorf("mount dst: %q, flags: %#x, err: %v", dst, flags, err)
			}
		}
	}
	return nil
}

// ShouldExposeNvidiaDevice returns true if path refers to an Nvidia device
// which should be exposed to the container.
//
// Precondition: nvproxy is enabled.
func ShouldExposeNvidiaDevice(path string) bool {
	if !strings.HasPrefix(path, "/dev/nvidia") {
		return false
	}
	if path == "/dev/nvidiactl" || path == "/dev/nvidia-uvm" {
		return true
	}
	nvidiaDevPathReg := regexp.MustCompile(`^/dev/nvidia(\d+)$`)
	return nvidiaDevPathReg.MatchString(path)
}

// ShouldExposeVFIODevice returns true if path refers to a VFIO device
// which should be exposed to the container.
func ShouldExposeVFIODevice(path string) bool {
	return strings.HasPrefix(path, vfioPathDir)
}

// ShouldExposeTpuDevice returns true if path refers to a TPU device which
// should be exposed to the container.
//
// Precondition: tpuproxy is enabled.
func ShouldExposeTpuDevice(path string) bool {
	valid, _ := util.IsTPUDeviceValid(path)
	return valid || ShouldExposeVFIODevice(path)
}

// SetupDev mounts devices from the OCI spec into the gofer's /dev directory.
func SetupDev(spec *specs.Spec, conf *config.Config, root, procPath string) error {
	if err := os.MkdirAll(filepath.Join(root, "dev"), 0777); err != nil {
		return fmt.Errorf("creating dev directory: %v", err)
	}
	// Mount any devices specified in the spec.
	if spec.Linux == nil {
		return nil
	}
	nvproxyEnabled := specutils.NVProxyEnabled(spec, conf)
	tpuproxyEnabled := specutils.TPUProxyIsEnabled(spec, conf)
	for _, dev := range spec.Linux.Devices {
		shouldMount := (nvproxyEnabled && ShouldExposeNvidiaDevice(dev.Path)) ||
			(tpuproxyEnabled && ShouldExposeTpuDevice(dev.Path))
		if !shouldMount {
			continue
		}
		dst := filepath.Join(root, dev.Path)
		log.Infof("Mounting device %q as bind mount at %q", dev.Path, dst)
		if err := specutils.SafeSetupAndMount(dev.Path, dst, "bind", unix.MS_BIND, procPath); err != nil {
			return fmt.Errorf("mounting %q: %v", dev.Path, err)
		}
	}
	return nil
}

// ResolveMounts resolves relative paths and symlinks in mount point
// destinations. It also adjusts mount options based on the underlying
// filesystem type.
//
// Note: mount points must already be in place for resolution to work.
// Otherwise, it may follow symlinks to locations that would be overwritten
// with another mount point and return the wrong location. In short, make sure
// SetupMounts() has been called before.
func ResolveMounts(conf *config.Config, mounts []specs.Mount, root string, mountConfs []specutils.GoferMountConf) ([]specs.Mount, error) {
	mountIdx := 1 // First index is for rootfs.
	cleanMounts := make([]specs.Mount, 0, len(mounts))
	for _, m := range mounts {
		if !specutils.HasMountConfig(m) {
			cleanMounts = append(cleanMounts, m)
			continue
		}
		mountConf := mountConfs[mountIdx]
		mountIdx++
		if !mountConf.ShouldUseLisafs() {
			cleanMounts = append(cleanMounts, m)
			continue
		}
		dst, err := ResolveSymlinks(root, m.Destination)
		if err != nil {
			return nil, fmt.Errorf("resolving symlinks to %q: %v", m.Destination, err)
		}
		relDst, err := filepath.Rel(root, dst)
		if err != nil {
			panic(fmt.Sprintf("%q could not be made relative to %q: %v", dst, root, err))
		}

		opts, err := AdjustMountOptions(conf, filepath.Join(root, relDst), m.Options)
		if err != nil {
			return nil, err
		}

		cpy := m
		cpy.Destination = filepath.Join("/", relDst)
		cpy.Options = opts
		cleanMounts = append(cleanMounts, cpy)
	}
	return cleanMounts, nil
}

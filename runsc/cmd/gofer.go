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

package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"runtime/debug"
	"strings"

	"github.com/google/subcommands"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/devices/tpuproxy"
	"gvisor.dev/gvisor/pkg/unet"
	"gvisor.dev/gvisor/runsc/boot"
	"gvisor.dev/gvisor/runsc/cmd/util"
	"gvisor.dev/gvisor/runsc/config"
	"gvisor.dev/gvisor/runsc/flag"
	"gvisor.dev/gvisor/runsc/fsgofer"
	"gvisor.dev/gvisor/runsc/fsgofer/filter"
	"gvisor.dev/gvisor/runsc/profile"
	"gvisor.dev/gvisor/runsc/specutils"
)

var caps = []string{
	"CAP_CHOWN",
	"CAP_DAC_OVERRIDE",
	"CAP_DAC_READ_SEARCH",
	"CAP_FOWNER",
	"CAP_FSETID",
	"CAP_SYS_CHROOT",
}

// goferCaps is the minimal set of capabilities needed by the Gofer to operate
// on files.
var goferCaps = &specs.LinuxCapabilities{
	Bounding:  caps,
	Effective: caps,
	Permitted: caps,
}

// goferSyncFDs contains file descriptors that are used for synchronization
// of the Gofer startup process against other processes.
type goferSyncFDs struct {
	// nvproxyFD is a file descriptor that is used to wait until
	// nvproxy-related setup is done. This setup involves creating mounts in the
	// Gofer process's mount namespace.
	// If this is set, this FD is the first that the Gofer waits for.
	nvproxyFD int
	// usernsFD is a file descriptor that is used to wait until
	// user namespace ID mappings are established in the Gofer's userns.
	// If this is set, this FD is the second that the Gofer waits for.
	usernsFD int
	// procMountFD is a file descriptor that has to be closed when the
	// procfs mount isn't needed anymore. It is read by the procfs unmounter
	// process.
	// If this is set, this FD is the last that the Gofer interacts with and
	// closes.
	procMountFD int
}

// Gofer implements subcommands.Command for the "gofer" command, which starts a
// filesystem gofer.  This command should not be called directly.
type Gofer struct {
	bundleDir  string
	ioFDs      intFlags
	devIoFD    int
	applyCaps  bool
	setUpRoot  bool
	mountConfs boot.GoferMountConfFlags

	specFD        int
	mountsFD      int
	profileFDs    profile.FDArgs
	syncFDs       goferSyncFDs
	stopProfiling func()
}

// Name implements subcommands.Command.
func (*Gofer) Name() string {
	return "gofer"
}

// Synopsis implements subcommands.Command.
func (g *Gofer) Synopsis() string {
	return fmt.Sprintf("launch a gofer process that proxies access to container files")
}

// Usage implements subcommands.Command.
func (*Gofer) Usage() string {
	return `gofer [flags]`
}

// SetFlags implements subcommands.Command.
func (g *Gofer) SetFlags(f *flag.FlagSet) {
	f.StringVar(&g.bundleDir, "bundle", "", "path to the root of the bundle directory, defaults to the current directory")
	f.BoolVar(&g.applyCaps, "apply-caps", true, "if true, apply capabilities to restrict what the Gofer process can do")
	f.BoolVar(&g.setUpRoot, "setup-root", true, "if true, set up an empty root for the process")

	// Open FDs that are donated to the gofer.
	f.Var(&g.ioFDs, "io-fds", "list of FDs to connect gofer servers. Follows the same order as --gofer-mount-confs. FDs are only donated if the mount is backed by lisafs.")
	f.Var(&g.mountConfs, "gofer-mount-confs", "information about how the gofer mounts have been configured. They must follow this order: root first, then mounts as defined in the spec.")
	f.IntVar(&g.devIoFD, "dev-io-fd", -1, "optional FD to connect /dev gofer server")
	f.IntVar(&g.specFD, "spec-fd", -1, "required fd with the container spec")
	f.IntVar(&g.mountsFD, "mounts-fd", -1, "mountsFD is the file descriptor to write list of mounts after they have been resolved (direct paths, no symlinks).")

	// Add synchronization FD flags.
	g.syncFDs.setFlags(f)

	// Profiling flags.
	g.profileFDs.SetFromFlags(f)
}

// Execute implements subcommands.Command.
func (g *Gofer) Execute(_ context.Context, f *flag.FlagSet, args ...any) subcommands.ExitStatus {
	if g.bundleDir == "" || len(g.ioFDs) < 1 || g.specFD < 0 {
		f.Usage()
		return subcommands.ExitUsageError
	}

	conf := args[0].(*config.Config)

	// Set traceback level
	debug.SetTraceback(conf.Traceback)

	specFile := os.NewFile(uintptr(g.specFD), "spec file")
	defer specFile.Close()
	spec, err := specutils.ReadSpecFromFile(g.bundleDir, specFile, conf)
	if err != nil {
		util.Fatalf("reading spec: %v", err)
	}

	g.syncFDs.syncNVProxy()
	g.syncFDs.syncUsernsForRootless()

	if g.setUpRoot {
		if err := g.setupRootFS(spec, conf); err != nil {
			util.Fatalf("Error setting up root FS: %v", err)
		}
		if !conf.TestOnlyAllowRunAsCurrentUserWithoutChroot {
			cleanupUnmounter := g.syncFDs.spawnProcUnmounter()
			defer cleanupUnmounter()
		}
	}
	if g.applyCaps {
		overrides := g.syncFDs.flags()
		overrides["apply-caps"] = "false"
		overrides["setup-root"] = "false"
		args := prepareArgs(g.Name(), f, overrides)
		util.Fatalf("setCapsAndCallSelf(%v, %v): %v", args, goferCaps, setCapsAndCallSelf(args, goferCaps))
		panic("unreachable")
	}

	// Start profiling. This will be a noop if no profiling arguments were passed.
	profileOpts := g.profileFDs.ToOpts()
	g.stopProfiling = profile.Start(profileOpts)

	// At this point we won't re-execute, so it's safe to limit via rlimits. Any
	// limit >= 0 works. If the limit is lower than the current number of open
	// files, then Setrlimit will succeed, and the next open will fail.
	if conf.FDLimit > -1 {
		rlimit := unix.Rlimit{
			Cur: uint64(conf.FDLimit),
			Max: uint64(conf.FDLimit),
		}
		switch err := unix.Setrlimit(unix.RLIMIT_NOFILE, &rlimit); err {
		case nil:
		case unix.EPERM:
			log.Warningf("FD limit %d is higher than the current hard limit or system-wide maximum", conf.FDLimit)
		default:
			util.Fatalf("Failed to set RLIMIT_NOFILE: %v", err)
		}
	}

	// Find what path is going to be served by this gofer.
	root := spec.Root.Path
	if !conf.TestOnlyAllowRunAsCurrentUserWithoutChroot {
		root = "/root"
	}

	// Resolve mount points paths, then replace mounts from our spec and send the
	// mount list over to the sandbox, so they are both in sync.
	//
	// Note that all mount points have been mounted in the proper location in
	// setupRootFS().
	cleanMounts, err := g.resolveMounts(conf, spec.Mounts, root)
	if err != nil {
		util.Fatalf("Failure to resolve mounts: %v", err)
	}
	spec.Mounts = cleanMounts
	go func() {
		if err := g.writeMounts(cleanMounts); err != nil {
			panic(fmt.Sprintf("Failed to write mounts: %v", err))
		}
	}()

	specutils.LogSpecDebug(spec, conf.OCISeccomp)

	// fsgofer should run with a umask of 0, because we want to preserve file
	// modes exactly as sent by the sandbox, which will have applied its own umask.
	unix.Umask(0)

	procFDPath := procFDBindMount
	if conf.TestOnlyAllowRunAsCurrentUserWithoutChroot {
		procFDPath = "/proc/self/fd"
	}
	if err := fsgofer.OpenProcSelfFD(procFDPath); err != nil {
		util.Fatalf("failed to open /proc/self/fd: %v", err)
	}

	// procfs isn't needed anymore.
	g.syncFDs.unmountProcfs()

	if err := unix.Chroot(root); err != nil {
		util.Fatalf("failed to chroot to %q: %v", root, err)
	}
	if err := unix.Chdir("/"); err != nil {
		util.Fatalf("changing working dir: %v", err)
	}
	log.Infof("Process chroot'd to %q", root)

	// Initialize filters.
	opts := filter.Options{
		UDSOpenEnabled:   conf.GetHostUDS().AllowOpen(),
		UDSCreateEnabled: conf.GetHostUDS().AllowCreate(),
		ProfileEnabled:   len(profileOpts) > 0,
		DirectFS:         conf.DirectFS,
	}
	if err := filter.Install(opts); err != nil {
		util.Fatalf("installing seccomp filters: %v", err)
	}

	return g.serve(spec, conf, root)
}

func newSocket(ioFD int) *unet.Socket {
	socket, err := unet.NewSocket(ioFD)
	if err != nil {
		util.Fatalf("creating server on FD %d: %v", ioFD, err)
	}
	return socket
}

func (g *Gofer) serve(spec *specs.Spec, conf *config.Config, root string) subcommands.ExitStatus {
	type connectionConfig struct {
		sock      *unet.Socket
		mountPath string
		readonly  bool
	}
	cfgs := make([]connectionConfig, 0, len(spec.Mounts)+1)
	server := fsgofer.NewLisafsServer(fsgofer.Config{
		// These are global options. Ignore readonly configuration, that is set on
		// a per connection basis.
		HostUDS:            conf.GetHostUDS(),
		HostFifo:           conf.HostFifo,
		DonateMountPointFD: conf.DirectFS,
	})

	ioFDs := g.ioFDs
	rootfsConf := g.mountConfs[0]
	if rootfsConf.ShouldUseLisafs() {
		// Start with root mount, then add any other additional mount as needed.
		cfgs = append(cfgs, connectionConfig{
			sock:      newSocket(ioFDs[0]),
			mountPath: "/", // fsgofer process is always chroot()ed. So serve root.
			readonly:  spec.Root.Readonly || rootfsConf.ShouldUseOverlayfs(),
		})
		log.Infof("Serving %q mapped to %q on FD %d (ro: %t)", "/", root, ioFDs[0], cfgs[0].readonly)
		ioFDs = ioFDs[1:]
	}

	mountIdx := 1 // first one is the root
	for _, m := range spec.Mounts {
		if !specutils.IsGoferMount(m) {
			continue
		}
		mountConf := g.mountConfs[mountIdx]
		mountIdx++
		if !mountConf.ShouldUseLisafs() {
			continue
		}
		if !filepath.IsAbs(m.Destination) {
			util.Fatalf("mount destination must be absolute: %q", m.Destination)
		}

		if len(ioFDs) == 0 {
			util.Fatalf("no FD found for mount. Did you forget --io-fd? FDs: %d, Mount: %+v", len(g.ioFDs), m)
		}
		ioFD := ioFDs[0]
		ioFDs = ioFDs[1:]
		readonly := specutils.IsReadonlyMount(m.Options) || mountConf.ShouldUseOverlayfs()
		cfgs = append(cfgs, connectionConfig{
			sock:      newSocket(ioFD),
			mountPath: m.Destination,
			readonly:  readonly,
		})
		log.Infof("Serving %q mapped on FD %d (ro: %t)", m.Destination, ioFD, readonly)
	}

	if len(ioFDs) > 0 {
		util.Fatalf("too many FDs passed for mounts. mounts: %d, FDs: %d", len(cfgs), len(g.ioFDs))
	}

	if g.devIoFD >= 0 {
		cfgs = append(cfgs, connectionConfig{
			sock:      newSocket(g.devIoFD),
			mountPath: "/dev",
		})
		log.Infof("Serving /dev mapped on FD %d (ro: false)", g.devIoFD)
	}

	for _, cfg := range cfgs {
		conn, err := server.CreateConnection(cfg.sock, cfg.mountPath, cfg.readonly)
		if err != nil {
			util.Fatalf("starting connection on FD %d for gofer mount failed: %v", cfg.sock.FD(), err)
		}
		server.StartConnection(conn)
	}
	server.Wait()
	server.Destroy()
	log.Infof("All lisafs servers exited.")
	if g.stopProfiling != nil {
		g.stopProfiling()
	}
	return subcommands.ExitSuccess
}

func (g *Gofer) writeMounts(mounts []specs.Mount) error {
	bytes, err := json.Marshal(mounts)
	if err != nil {
		return err
	}

	f := os.NewFile(uintptr(g.mountsFD), "mounts file")
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

// Redhat distros don't allow to create bind-mounts in /proc/self directories.
// It is protected by selinux rules.
const procFDBindMount = "/proc/fs"

func (g *Gofer) setupRootFS(spec *specs.Spec, conf *config.Config) error {
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
		// self/fd is bind-mounted, so that the FD return by
		// OpenProcSelfFD() does not allow escapes with walking ".." .
		if err := unix.Mount("/proc/fs/proc/self/fd", "/proc/fs/"+procFDBindMount,
			"", unix.MS_RDONLY|unix.MS_BIND|flags, ""); err != nil {
			util.Fatalf("error mounting proc/self/fd: %v", err)
		}
		if err := copyFile("/proc/fs/etc/localtime", "/etc/localtime"); err != nil {
			log.Warningf("Failed to copy /etc/localtime: %v. UTC timezone will be used.", err)
		}
		root = "/proc/fs/root"
		procPath = "/proc/fs/proc"
	}

	rootfsConf := g.mountConfs[0]
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
	if err := g.setupMounts(conf, spec.Mounts, root, procPath); err != nil {
		util.Fatalf("error setting up FS: %v", err)
	}

	// Set up /dev directory is needed.
	if g.devIoFD >= 0 {
		g.setupDev(spec, conf, root, procPath)
	}

	// Create working directory if needed.
	if spec.Process.Cwd != "" {
		dst, err := resolveSymlinks(root, spec.Process.Cwd)
		if err != nil {
			return fmt.Errorf("resolving symlinks to %q: %v", spec.Process.Cwd, err)
		}
		log.Infof("Create working directory %q if needed", spec.Process.Cwd)
		if err := os.MkdirAll(dst, 0755); err != nil {
			return fmt.Errorf("creating working directory %q: %v", spec.Process.Cwd, err)
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
		if err := pivotRoot("/proc/fs"); err != nil {
			util.Fatalf("failed to change the root file system: %v", err)
		}
		if err := os.Chdir("/"); err != nil {
			util.Fatalf("failed to change working directory")
		}
	}
	return nil
}

// setupMounts bind mounts all mounts specified in the spec in their correct
// location inside root. It will resolve relative paths and symlinks. It also
// creates directories as needed.
func (g *Gofer) setupMounts(conf *config.Config, mounts []specs.Mount, root, procPath string) error {
	mountIdx := 1 // First index is for rootfs.
	for _, m := range mounts {
		if !specutils.IsGoferMount(m) {
			continue
		}
		mountConf := g.mountConfs[mountIdx]
		mountIdx++
		if !mountConf.ShouldUseLisafs() {
			continue
		}

		dst, err := resolveSymlinks(root, m.Destination)
		if err != nil {
			return fmt.Errorf("resolving symlinks to %q: %v", m.Destination, err)
		}

		flags := specutils.OptionsToFlags(m.Options) | unix.MS_BIND
		if mountConf.ShouldUseOverlayfs() {
			// Force mount read-only if writes are not going to be sent to it.
			flags |= unix.MS_RDONLY
		}

		log.Infof("Mounting src: %q, dst: %q, flags: %#x", m.Source, dst, flags)
		if err := specutils.SafeSetupAndMount(m.Source, dst, m.Type, flags, procPath); err != nil {
			return fmt.Errorf("mounting %+v: %v", m, err)
		}

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

// shouldExposeNvidiaDevice returns true if path refers to an Nvidia device
// which should be exposed to the container.
//
// Precondition: nvproxy is enabled.
func shouldExposeNvidiaDevice(path string) bool {
	if !strings.HasPrefix(path, "/dev/nvidia") {
		return false
	}
	if path == "/dev/nvidiactl" || path == "/dev/nvidia-uvm" {
		return true
	}
	nvidiaDevPathReg := regexp.MustCompile(`^/dev/nvidia(\d+)$`)
	return nvidiaDevPathReg.MatchString(path)
}

// shouldExposeVfioDevice returns true if path refers to an VFIO device
// which shuold be exposed to the container.
func shouldExposeVFIODevice(path string) bool {
	return strings.HasPrefix(path, filepath.Dir(tpuproxy.VFIOPath))
}

// shouldExposeTpuDevice returns true if path refers to a TPU device which
// should be exposed to the container.
//
// Precondition: tpuproxy is enabled.
func shouldExposeTpuDevice(path string) bool {
	_, valid, _ := util.ExtractTPUDeviceMinor(path)
	return valid || shouldExposeVFIODevice(path)
}

func (g *Gofer) setupDev(spec *specs.Spec, conf *config.Config, root, procPath string) error {
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
		shouldMount := (nvproxyEnabled && shouldExposeNvidiaDevice(dev.Path)) ||
			(tpuproxyEnabled && shouldExposeTpuDevice(dev.Path))
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

// resolveMounts resolved relative paths and symlinks to mount points.
//
// Note: mount points must already be in place for resolution to work.
// Otherwise, it may follow symlinks to locations that would be overwritten
// with another mount point and return the wrong location. In short, make sure
// setupMounts() has been called before.
func (g *Gofer) resolveMounts(conf *config.Config, mounts []specs.Mount, root string) ([]specs.Mount, error) {
	mountIdx := 1 // First index is for rootfs.
	cleanMounts := make([]specs.Mount, 0, len(mounts))
	for _, m := range mounts {
		if !specutils.IsGoferMount(m) {
			cleanMounts = append(cleanMounts, m)
			continue
		}
		mountConf := g.mountConfs[mountIdx]
		mountIdx++
		if !mountConf.ShouldUseLisafs() {
			cleanMounts = append(cleanMounts, m)
			continue
		}
		dst, err := resolveSymlinks(root, m.Destination)
		if err != nil {
			return nil, fmt.Errorf("resolving symlinks to %q: %v", m.Destination, err)
		}
		relDst, err := filepath.Rel(root, dst)
		if err != nil {
			panic(fmt.Sprintf("%q could not be made relative to %q: %v", dst, root, err))
		}

		opts, err := adjustMountOptions(conf, filepath.Join(root, relDst), m.Options)
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

// ResolveSymlinks walks 'rel' having 'root' as the root directory. If there are
// symlinks, they are evaluated relative to 'root' to ensure the end result is
// the same as if the process was running inside the container.
func resolveSymlinks(root, rel string) (string, error) {
	return resolveSymlinksImpl(root, root, rel, 255)
}

func resolveSymlinksImpl(root, base, rel string, followCount uint) (string, error) {
	if followCount == 0 {
		return "", fmt.Errorf("too many symlinks to follow, path: %q", filepath.Join(base, rel))
	}

	rel = filepath.Clean(rel)
	for _, name := range strings.Split(rel, string(filepath.Separator)) {
		if name == "" {
			continue
		}
		// Note that Join() resolves things like ".." and returns a clean path.
		path := filepath.Join(base, name)
		if !strings.HasPrefix(path, root) {
			// One cannot '..' their way out of root.
			base = root
			continue
		}
		fi, err := os.Lstat(path)
		if err != nil {
			if !os.IsNotExist(err) {
				return "", err
			}
			// Not found means there is no symlink to check. Just keep walking dirs.
			base = path
			continue
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			link, err := os.Readlink(path)
			if err != nil {
				return "", err
			}
			if filepath.IsAbs(link) {
				base = root
			}
			base, err = resolveSymlinksImpl(root, base, link, followCount-1)
			if err != nil {
				return "", err
			}
			continue
		}
		base = path
	}
	return base, nil
}

// adjustMountOptions adds filesystem-specific gofer mount options.
func adjustMountOptions(conf *config.Config, path string, opts []string) ([]string, error) {
	rv := make([]string, len(opts))
	copy(rv, opts)

	statfs := unix.Statfs_t{}
	if err := unix.Statfs(path, &statfs); err != nil {
		return nil, err
	}
	switch statfs.Type {
	case unix.OVERLAYFS_SUPER_MAGIC:
		rv = append(rv, "overlayfs_stale_read")
	case unix.NFS_SUPER_MAGIC:
		// The gofer client implements remote file handle sharing for performance.
		// However, remote filesystems like NFS rely on close(2) syscall for
		// flushing file data to the server. Such handle sharing prevents the
		// application's close(2) syscall from being propagated to the host. Hence
		// disable file handle sharing, so NFS files are flushed correctly.
		rv = append(rv, "disable_file_handle_sharing")
	}
	return rv, nil
}

// setFlags sets sync FD flags on the given FlagSet.
func (g *goferSyncFDs) setFlags(f *flag.FlagSet) {
	f.IntVar(&g.nvproxyFD, "sync-nvproxy-fd", -1, "file descriptor that the gofer waits on until nvproxy setup is done")
	f.IntVar(&g.usernsFD, "sync-userns-fd", -1, "file descriptor the gofer waits on until userns mappings are set up")
	f.IntVar(&g.procMountFD, "proc-mount-sync-fd", -1, "file descriptor that the gofer writes to when /proc isn't needed anymore and can be unmounted")
}

// flags returns the flags necessary to pass along the current sync FD values
// to a re-executed version of this process.
func (g *goferSyncFDs) flags() map[string]string {
	return map[string]string{
		"sync-nvproxy-fd":    fmt.Sprintf("%d", g.nvproxyFD),
		"sync-userns-fd":     fmt.Sprintf("%d", g.usernsFD),
		"proc-mount-sync-fd": fmt.Sprintf("%d", g.procMountFD),
	}
}

// waitForFD waits for the other end of a given FD to be closed.
// `fd` is closed unconditionally after that.
// This should only be called for actual FDs (i.e. `fd` >= 0).
func waitForFD(fd int, fdName string) error {
	log.Debugf("Waiting on %s %d...", fdName, fd)
	f := os.NewFile(uintptr(fd), fdName)
	defer f.Close()
	var b [1]byte
	if n, err := f.Read(b[:]); n != 0 || err != io.EOF {
		return fmt.Errorf("failed to sync on %s: %v: %v", fdName, n, err)
	}
	log.Debugf("Synced on %s %d.", fdName, fd)
	return nil
}

// spawnProcMounter executes the /proc unmounter process.
// It returns a function to wait on the proc unmounter process, which
// should be called (via defer) in case of errors in order to clean up the
// unmounter process properly.
// When procfs is no longer needed, `unmountProcfs` should be called.
func (g *goferSyncFDs) spawnProcUnmounter() func() {
	if g.procMountFD != -1 {
		util.Fatalf("procMountFD is set")
	}
	// /proc is umounted from a forked process, because the
	// current one may re-execute itself without capabilities.
	cmd, w := execProcUmounter()
	// Clear FD_CLOEXEC. This process may be re-executed. procMountFD
	// should remain open.
	if _, _, errno := unix.RawSyscall(unix.SYS_FCNTL, w.Fd(), unix.F_SETFD, 0); errno != 0 {
		util.Fatalf("error clearing CLOEXEC: %v", errno)
	}
	g.procMountFD = int(w.Fd())
	return func() {
		g.procMountFD = -1
		w.Close()
		cmd.Wait()
	}
}

// unmountProcfs signals the proc unmounter process that procfs is no longer
// needed.
func (g *goferSyncFDs) unmountProcfs() {
	if g.procMountFD < 0 {
		return
	}
	umountProc(g.procMountFD)
	g.procMountFD = -1
}

// syncUsernsForRootless waits on usernsFD to be closed and then sets
// UID/GID to 0. Note that this function calls runtime.LockOSThread().
// This function is a no-op if usernsFD is -1.
//
// Postcondition: All callers must re-exec themselves after this returns,
// unless usernsFD was -1.
func (g *goferSyncFDs) syncUsernsForRootless() {
	if g.usernsFD < 0 {
		return
	}
	syncUsernsForRootless(g.usernsFD)
	g.usernsFD = -1
}

// syncUsernsForRootless waits on usernsFD to be closed and then sets
// UID/GID to 0. Note that this function calls runtime.LockOSThread().
//
// Postcondition: All callers must re-exec themselves after this returns.
func syncUsernsForRootless(fd int) {
	if err := waitForFD(fd, "userns sync FD"); err != nil {
		util.Fatalf("failed to sync on userns FD: %v", err)
	}

	// SETUID changes UID on the current system thread, so we have
	// to re-execute current binary.
	runtime.LockOSThread()
	if _, _, errno := unix.RawSyscall(unix.SYS_SETUID, 0, 0, 0); errno != 0 {
		util.Fatalf("failed to set UID: %v", errno)
	}
	if _, _, errno := unix.RawSyscall(unix.SYS_SETGID, 0, 0, 0); errno != 0 {
		util.Fatalf("failed to set GID: %v", errno)
	}
}

// syncNVProxy waits on nvproxyFD to be closed.
// Used for synchronization during nvproxy setup which is done from the
// non-gofer process.
// This function is a no-op if nvProxySyncFD is -1.
func (g *goferSyncFDs) syncNVProxy() {
	if g.nvproxyFD < 0 {
		return
	}
	if err := waitForFD(g.nvproxyFD, "nvproxy sync FD"); err != nil {
		util.Fatalf("failed to sync on NVProxy FD: %v", err)
	}
	g.nvproxyFD = -1
}

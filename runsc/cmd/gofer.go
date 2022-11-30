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
	"runtime"
	"runtime/debug"
	"strings"

	"github.com/google/subcommands"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/p9"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/unet"
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

// Gofer implements subcommands.Command for the "gofer" command, which starts a
// filesystem gofer.  This command should not be called directly.
type Gofer struct {
	bundleDir string
	ioFDs     intFlags
	applyCaps bool
	setUpRoot bool

	specFD       int
	mountsFD     int
	syncUsernsFD int

	profileFDs    profile.FDArgs
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
	f.Var(&g.ioFDs, "io-fds", "list of FDs to connect gofer servers. They must follow this order: root first, then mounts as defined in the spec")
	f.IntVar(&g.specFD, "spec-fd", -1, "required fd with the container spec")
	f.IntVar(&g.mountsFD, "mounts-fd", -1, "mountsFD is the file descriptor to write list of mounts after they have been resolved (direct paths, no symlinks).")
	f.IntVar(&g.syncUsernsFD, "sync-userns-fd", -1, "file descriptor used to synchronize rootless user namespace initialization.")

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

	if g.syncUsernsFD >= 0 {
		f := os.NewFile(uintptr(g.syncUsernsFD), "sync FD")
		defer f.Close()
		var b [1]byte
		if n, err := f.Read(b[:]); n != 0 || err != io.EOF {
			util.Fatalf("failed to sync: %v: %v", n, err)
		}

		f.Close()
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

	if g.setUpRoot {
		if err := setupRootFS(spec, conf); err != nil {
			util.Fatalf("Error setting up root FS: %v", err)
		}
	}
	if g.applyCaps {
		// Disable caps when calling myself again.
		// Note: minimal argument handling for the default case to keep it simple.
		args := os.Args
		args = append(args, "--apply-caps=false", "--setup-root=false", "--sync-userns-fd=-1")
		util.Fatalf("setCapsAndCallSelf(%v, %v): %v", args, goferCaps, setCapsAndCallSelf(args, goferCaps))
		panic("unreachable")
	}

	if g.syncUsernsFD >= 0 {
		// syncUsernsFD is set, but runsc hasn't been re-exeuted with a new UID and GID.
		// We expcec that setCapsAndCallSelfsetCapsAndCallSelf has to be called in this case.
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
	cleanMounts, err := resolveMounts(conf, spec.Mounts, root)
	if err != nil {
		util.Fatalf("Failure to resolve mounts: %v", err)
	}
	spec.Mounts = cleanMounts
	go func() {
		if err := g.writeMounts(cleanMounts); err != nil {
			panic(fmt.Sprintf("Failed to write mounts: %v", err))
		}
	}()

	specutils.LogSpec(spec)

	// fsgofer should run with a umask of 0, because we want to preserve file
	// modes exactly as sent by the sandbox, which will have applied its own umask.
	unix.Umask(0)

	if err := fsgofer.OpenProcSelfFD(); err != nil {
		util.Fatalf("failed to open /proc/self/fd: %v", err)
	}

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
	}
	if err := filter.Install(opts); err != nil {
		util.Fatalf("installing seccomp filters: %v", err)
	}

	if conf.Lisafs {
		return g.serveLisafs(spec, conf, root)
	}
	return g.serve9P(spec, conf, root)
}

func newSocket(ioFD int) *unet.Socket {
	socket, err := unet.NewSocket(ioFD)
	if err != nil {
		util.Fatalf("creating server on FD %d: %v", ioFD, err)
	}
	return socket
}

func (g *Gofer) serveLisafs(spec *specs.Spec, conf *config.Config, root string) subcommands.ExitStatus {
	type connectionConfig struct {
		sock      *unet.Socket
		mountPath string
		readonly  bool
	}
	cfgs := make([]connectionConfig, 0, len(spec.Mounts)+1)
	server := fsgofer.NewLisafsServer(fsgofer.Config{
		// These are global options. Ignore readonly configuration, that is set on
		// a per connection basis.
		HostUDS:  conf.GetHostUDS(),
		HostFifo: conf.HostFifo,
	})
	overlay2 := conf.GetOverlay2()

	// Start with root mount, then add any other additional mount as needed.
	cfgs = append(cfgs, connectionConfig{
		sock:      newSocket(g.ioFDs[0]),
		mountPath: "/", // fsgofer process is always chroot()ed. So serve root.
		readonly:  spec.Root.Readonly || overlay2.RootMount,
	})
	log.Infof("Serving %q mapped to %q on FD %d (ro: %t)", "/", root, g.ioFDs[0], cfgs[0].readonly)

	mountIdx := 1 // first one is the root
	for _, m := range spec.Mounts {
		if !specutils.IsGoferMount(m) {
			continue
		}

		if !filepath.IsAbs(m.Destination) {
			util.Fatalf("mount destination must be absolute: %q", m.Destination)
		}
		if mountIdx >= len(g.ioFDs) {
			util.Fatalf("no FD found for mount. Did you forget --io-fd? FDs: %d, Mount: %+v", len(g.ioFDs), m)
		}

		cfgs = append(cfgs, connectionConfig{
			sock:      newSocket(g.ioFDs[mountIdx]),
			mountPath: m.Destination,
			readonly:  isReadonlyMount(m.Options) || overlay2.SubMounts,
		})

		log.Infof("Serving %q mapped on FD %d (ro: %t)", m.Destination, g.ioFDs[mountIdx], cfgs[mountIdx].readonly)
		mountIdx++
	}

	if mountIdx != len(g.ioFDs) {
		util.Fatalf("too many FDs passed for mounts. mounts: %d, FDs: %d", mountIdx, len(g.ioFDs))
	}
	cfgs = cfgs[:mountIdx]

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

func (g *Gofer) serve9P(spec *specs.Spec, conf *config.Config, root string) subcommands.ExitStatus {
	// Start with root mount, then add any other additional mount as needed.
	overlay2 := conf.GetOverlay2()
	ats := make([]p9.Attacher, 0, len(spec.Mounts)+1)
	ap, err := fsgofer.NewAttachPoint("/", fsgofer.Config{
		ROMount:  spec.Root.Readonly || overlay2.RootMount,
		HostUDS:  conf.GetHostUDS(),
		HostFifo: conf.HostFifo,
	})
	if err != nil {
		util.Fatalf("creating attach point: %v", err)
	}
	ats = append(ats, ap)
	log.Infof("Serving %q mapped to %q on FD %d (ro: %t)", "/", root, g.ioFDs[0], spec.Root.Readonly)

	mountIdx := 1 // first one is the root
	for _, m := range spec.Mounts {
		if specutils.IsGoferMount(m) {
			cfg := fsgofer.Config{
				ROMount:  isReadonlyMount(m.Options) || overlay2.SubMounts,
				HostUDS:  conf.GetHostUDS(),
				HostFifo: conf.HostFifo,
			}
			ap, err := fsgofer.NewAttachPoint(m.Destination, cfg)
			if err != nil {
				util.Fatalf("creating attach point: %v", err)
			}
			ats = append(ats, ap)

			if mountIdx >= len(g.ioFDs) {
				util.Fatalf("no FD found for mount. Did you forget --io-fd? mount: %d, %v", len(g.ioFDs), m)
			}
			log.Infof("Serving %q mapped on FD %d (ro: %t)", m.Destination, g.ioFDs[mountIdx], cfg.ROMount)
			mountIdx++
		}
	}
	if mountIdx != len(g.ioFDs) {
		util.Fatalf("too many FDs passed for mounts. mounts: %d, FDs: %d", mountIdx, len(g.ioFDs))
	}

	// Run the loops and wait for all to exit.
	var wg sync.WaitGroup
	for i, ioFD := range g.ioFDs {
		wg.Add(1)
		go func(ioFD int, at p9.Attacher) {
			socket, err := unet.NewSocket(ioFD)
			if err != nil {
				util.Fatalf("creating server on FD %d: %v", ioFD, err)
			}
			s := p9.NewServer(at)
			if err := s.Handle(socket); err != nil {
				util.Fatalf("P9 server returned error. Gofer is shutting down. FD: %d, err: %v", ioFD, err)
			}
			wg.Done()
		}(ioFD, ats[i])
	}
	wg.Wait()
	log.Infof("All 9P servers exited.")
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

func isReadonlyMount(opts []string) bool {
	for _, o := range opts {
		if o == "ro" {
			return true
		}
	}
	return false
}

func setupRootFS(spec *specs.Spec, conf *config.Config) error {
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
		if err := specutils.SafeMount("runsc-root", "/proc", "tmpfs", flags, "", procPath); err != nil {
			util.Fatalf("error mounting tmpfs: %v", err)
		}

		// Prepare tree structure for pivot_root(2).
		if err := os.Mkdir("/proc/proc", 0755); err != nil {
			util.Fatalf("error creating /proc/proc: %v", err)
		}
		if err := os.Mkdir("/proc/root", 0755); err != nil {
			util.Fatalf("error creating /proc/root: %v", err)
		}
		if err := os.Mkdir("/proc/etc", 0755); err != nil {
			util.Fatalf("error creating /proc/etc: %v", err)
		}
		// This cannot use SafeMount because there's no available procfs. But we
		// know that /proc is an empty tmpfs mount, so this is safe.
		if err := unix.Mount("runsc-proc", "/proc/proc", "proc", flags|unix.MS_RDONLY, ""); err != nil {
			util.Fatalf("error mounting proc: %v", err)
		}
		if err := copyFile("/proc/etc/localtime", "/etc/localtime"); err != nil {
			log.Warningf("Failed to copy /etc/localtime: %v. UTC timezone will be used.", err)
		}
		root = "/proc/root"
		procPath = "/proc/proc"
	}

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

	// Replace the current spec, with the clean spec with symlinks resolved.
	if err := setupMounts(conf, spec.Mounts, root, procPath); err != nil {
		util.Fatalf("error setting up FS: %v", err)
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
	if spec.Root.Readonly || conf.GetOverlay2().RootMount {
		// If root is a mount point but not read-only, we can change mount options
		// to make it read-only for extra safety.
		log.Infof("Remounting root as readonly: %q", root)
		flags := uintptr(unix.MS_BIND | unix.MS_REMOUNT | unix.MS_RDONLY | unix.MS_REC)
		if err := specutils.SafeMount(root, root, "bind", flags, "", procPath); err != nil {
			return fmt.Errorf("remounting root as read-only with source: %q, target: %q, flags: %#x, err: %v", root, root, flags, err)
		}
	}

	if !conf.TestOnlyAllowRunAsCurrentUserWithoutChroot {
		if err := pivotRoot("/proc"); err != nil {
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
func setupMounts(conf *config.Config, mounts []specs.Mount, root, procPath string) error {
	for _, m := range mounts {
		if !specutils.IsGoferMount(m) {
			continue
		}

		dst, err := resolveSymlinks(root, m.Destination)
		if err != nil {
			return fmt.Errorf("resolving symlinks to %q: %v", m.Destination, err)
		}

		flags := specutils.OptionsToFlags(m.Options) | unix.MS_BIND
		if conf.GetOverlay2().SubMounts {
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

// resolveMounts resolved relative paths and symlinks to mount points.
//
// Note: mount points must already be in place for resolution to work.
// Otherwise, it may follow symlinks to locations that would be overwritten
// with another mount point and return the wrong location. In short, make sure
// setupMounts() has been called before.
func resolveMounts(conf *config.Config, mounts []specs.Mount, root string) ([]specs.Mount, error) {
	cleanMounts := make([]specs.Mount, 0, len(mounts))
	for _, m := range mounts {
		if !specutils.IsGoferMount(m) {
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

// adjustMountOptions adds 'overlayfs_stale_read' if mounting over overlayfs.
func adjustMountOptions(conf *config.Config, path string, opts []string) ([]string, error) {
	rv := make([]string, len(opts))
	copy(rv, opts)

	statfs := unix.Statfs_t{}
	if err := unix.Statfs(path, &statfs); err != nil {
		return nil, err
	}
	if statfs.Type == unix.OVERLAYFS_SUPER_MAGIC {
		rv = append(rv, "overlayfs_stale_read")
	}
	return rv, nil
}

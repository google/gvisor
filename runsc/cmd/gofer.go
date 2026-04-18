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
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"

	"github.com/google/subcommands"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/lisafs"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/seccomp"
	"gvisor.dev/gvisor/pkg/unet"
	"gvisor.dev/gvisor/pkg/urpc"
	"gvisor.dev/gvisor/runsc/cmd/sandboxsetup"
	"gvisor.dev/gvisor/runsc/cmd/util"
	"gvisor.dev/gvisor/runsc/config"
	"gvisor.dev/gvisor/runsc/container"
	"gvisor.dev/gvisor/runsc/flag"
	"gvisor.dev/gvisor/runsc/fsgofer"
	"gvisor.dev/gvisor/runsc/fsgofer/filter"
	"gvisor.dev/gvisor/runsc/gofer/provider"
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

var udsOpenCaps = []string{
	"CAP_SETUID",
	"CAP_SETGID",
}

// goferCaps is the minimal set of capabilities needed by the Gofer to operate
// on files.
var goferCaps = &specs.LinuxCapabilities{
	Bounding:    caps,
	Effective:   caps,
	Permitted:   caps,
	Inheritable: caps,
	Ambient:     caps,
}

var goferUdsOpenCaps = &specs.LinuxCapabilities{
	Bounding:  udsOpenCaps,
	Effective: udsOpenCaps,
	Permitted: udsOpenCaps,
}

// goferSyncFDs contains file descriptors that are used for synchronization
// of the Gofer startup process against other processes.
type goferSyncFDs struct {
	// chrootFD is a file descriptor that is used to wait until container
	// filesystem related setup is done. This setup involves creating files and
	// mounts in the Gofer process's mount namespace and needs to be done before
	// the Gofer chroots.
	// If this is set, this FD is the first that the Gofer waits for.
	chrootFD int
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
	util.InternalSubCommand
	bundleDir  string
	ioFDs      sandboxsetup.IntFlags
	devIoFD    int
	applyCaps  bool
	setUpRoot  bool
	mountConfs specutils.GoferMountConfFlags

	// uid and gid are the user and group IDs to switch to after setting up the
	// user namespace.
	uid int
	gid int

	specFD           int
	mountsFD         int
	goferToHostRPCFD int
	profileFDs       profile.FDArgs
	syncFDs          goferSyncFDs
	stopProfiling    func()
}

// Name implements subcommands.Command.
func (*Gofer) Name() string {
	return "gofer"
}

// Synopsis implements subcommands.Command.
func (g *Gofer) Synopsis() string {
	return "launch a gofer process that proxies access to container files"
}

// Usage implements subcommands.Command.
func (*Gofer) Usage() string {
	return "gofer [flags]\n"
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
	f.IntVar(&g.goferToHostRPCFD, "rpc-fd", -1, "gofer-to-host RPC file descriptor.")

	// IDs to run gofer as.
	f.IntVar(&g.uid, "uid", 0, "User ID")
	f.IntVar(&g.gid, "gid", 0, "Group ID")

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

	g.syncFDs.syncChroot()
	g.syncFDs.syncUsernsForRootless(uint32(g.uid), uint32(g.gid))

	goferToHostRPCSock, err := unet.NewSocket(g.goferToHostRPCFD)
	if err != nil {
		util.Fatalf("creating rpc socket: %v", err)
	}

	goferToHostRPC := urpc.NewClient(goferToHostRPCSock)
	defer goferToHostRPC.Close()

	if g.setUpRoot {
		if err := sandboxsetup.SetupRootFS(spec, conf, g.mountConfs, g.devIoFD, makeRPCMountOpener(goferToHostRPC)); err != nil {
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
		args := sandboxsetup.PrepareArgs(g.Name(), f, overrides)
		capsToApply := goferCaps
		if conf.GetHostUDS().AllowOpen() {
			capsToApply = specutils.MergeCapabilities(capsToApply, goferUdsOpenCaps)
		}
		util.Fatalf("setCapsAndCallSelf(%v, %v): %v", args, capsToApply, sandboxsetup.SetCapsAndCallSelf(args, capsToApply))
		panic("unreachable")
	}

	// This can't happen until after setCapsAndCallSelf(), since otherwise the
	// re-executed gofer may reuse goferToHostRPCFD's file descriptor for an
	// unrelated file.
	goferToHostRPC.Close()

	// Start profiling. This will be a noop if no profiling arguments were passed.
	profileOpts := profile.MakeOpts(&g.profileFDs, conf.ProfileGCInterval)
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
	cleanMounts, err := sandboxsetup.ResolveMounts(conf, spec.Mounts, root, g.mountConfs)
	if err != nil {
		util.Fatalf("Failure to resolve mounts: %v", err)
	}
	spec.Mounts = cleanMounts
	go func() {
		if err := sandboxsetup.WriteMounts(g.mountsFD, cleanMounts); err != nil {
			panic(fmt.Sprintf("Failed to write mounts: %v", err))
		}
	}()

	specutils.LogSpecDebug(spec, conf.OCISeccomp)

	// fsgofer should run with a umask of 0, because we want to preserve file
	// modes exactly as sent by the sandbox, which will have applied its own umask.
	unix.Umask(0)

	procFDPath := sandboxsetup.ProcFDBindMount
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

	ruid := unix.Getuid()
	euid := unix.Geteuid()
	rgid := unix.Getgid()
	egid := unix.Getegid()
	log.Debugf("Process running as uid=%d euid=%d gid=%d egid=%d", ruid, euid, rgid, egid)

	// Initialize filters, merging any extra rules from registered providers.
	opts := filter.Options{
		UDSOpenEnabled:   conf.GetHostUDS().AllowOpen(),
		UDSCreateEnabled: conf.GetHostUDS().AllowCreate(),
		ProfileEnabled:   profileOpts.Enabled(),
		DirectFS:         conf.DirectFS,
		CgoEnabled:       config.CgoEnabled,
	}
	var extraRules *seccomp.SyscallRules
	for _, p := range provider.Registered() {
		if r := p.SeccompRules(); r.Size() > 0 {
			if extraRules == nil {
				copied := r.Copy()
				extraRules = &copied
			} else {
				extraRules.Merge(r)
			}
		}
	}
	if extraRules != nil {
		if err := filter.InstallWithExtra(opts, *extraRules); err != nil {
			util.Fatalf("installing seccomp filters: %v", err)
		}
	} else {
		if err := filter.Install(opts); err != nil {
			util.Fatalf("installing seccomp filters: %v", err)
		}
	}

	return g.serve(spec, conf, root, ruid, euid, rgid, egid)
}

func (g *Gofer) serve(spec *specs.Spec, conf *config.Config, root string, ruid int, euid int, rgid int, egid int) subcommands.ExitStatus {
	type connectionConfig struct {
		sock      *unet.Socket
		mountPath string
		readonly  bool
		mountConf specutils.GoferMountConf
	}
	cfgs := make([]connectionConfig, 0, len(spec.Mounts)+1)
	server := fsgofer.NewLisafsServer(fsgofer.Config{
		// These are global options. Ignore readonly configuration, that is set on
		// a per connection basis.
		HostUDS:            conf.GetHostUDS(),
		HostFifo:           conf.HostFifo,
		DonateMountPointFD: conf.DirectFS,
		RUID:               ruid,
		EUID:               euid,
		RGID:               rgid,
		EGID:               egid,
	})

	ioFDs := g.ioFDs
	rootfsConf := g.mountConfs[0]
	if rootfsConf.ShouldUseLisafs() {
		// Start with root mount, then add any other additional mount as needed.
		cfgs = append(cfgs, connectionConfig{
			sock:      sandboxsetup.NewSocket(ioFDs[0]),
			mountPath: "/", // fsgofer process is always chroot()ed. So serve root.
			readonly:  spec.Root.Readonly || rootfsConf.ShouldUseOverlayfs(),
			mountConf: rootfsConf,
		})
		log.Infof("Serving %q mapped to %q on FD %d (ro: %t)", "/", root, ioFDs[0], cfgs[0].readonly)
		ioFDs = ioFDs[1:]
	}

	mountIdx := 1 // first one is the root
	for _, m := range spec.Mounts {
		if !specutils.HasMountConfig(m) {
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
			sock:      sandboxsetup.NewSocket(ioFD),
			mountPath: m.Destination,
			readonly:  readonly,
			mountConf: mountConf,
		})
		log.Infof("Serving %q mapped on FD %d (ro: %t)", m.Destination, ioFD, readonly)
	}

	if len(ioFDs) > 0 {
		util.Fatalf("too many FDs passed for mounts. mounts: %d, FDs: %d", len(cfgs), len(g.ioFDs))
	}

	if g.devIoFD >= 0 {
		cfgs = append(cfgs, connectionConfig{
			sock:      sandboxsetup.NewSocket(g.devIoFD),
			mountPath: "/dev",
		})
		log.Infof("Serving /dev mapped on FD %d (ro: false)", g.devIoFD)
	}

	var providerServers []*lisafs.Server
	for _, cfg := range cfgs {
		var srv *lisafs.Server
		for _, p := range provider.Registered() {
			var err error
			srv, err = p.NewServer(spec, cfg.mountPath, cfg.mountConf, cfg.readonly)
			if err != nil {
				util.Fatalf("provider %s for %q: %v", p.Name(), cfg.mountPath, err)
			}
			if srv != nil {
				providerServers = append(providerServers, srv)
				log.Infof("Serving %q via provider %s on FD %d", cfg.mountPath, p.Name(), cfg.sock.FD())
				break
			}
		}
		if srv == nil {
			srv = &server.Server
		}
		conn, err := srv.CreateConnection(cfg.sock, cfg.mountPath, cfg.readonly)
		if err != nil {
			util.Fatalf("starting connection on FD %d for gofer mount failed: %v", cfg.sock.FD(), err)
		}
		srv.StartConnection(conn)
	}
	server.Wait()
	for _, ps := range providerServers {
		ps.Wait()
	}
	server.Destroy()
	for _, ps := range providerServers {
		ps.Destroy()
	}
	log.Infof("All lisafs servers exited.")
	if g.stopProfiling != nil {
		g.stopProfiling()
	}
	return subcommands.ExitSuccess
}

// makeRPCMountOpener returns a MountOpener that opens mount sources via the
// gofer-to-host RPC channel.
func makeRPCMountOpener(goferToHostRPC *urpc.Client) sandboxsetup.MountOpener {
	return func(m *specs.Mount) (*os.File, error) {
		var res container.OpenMountResult
		if err := goferToHostRPC.Call("goferToHostRPC.OpenMount", m, &res); err != nil {
			return nil, fmt.Errorf("opening %s: %w", m.Source, err)
		}
		return res.Files[0], nil
	}
}

// setFlags sets sync FD flags on the given FlagSet.
func (g *goferSyncFDs) setFlags(f *flag.FlagSet) {
	f.IntVar(&g.chrootFD, "sync-chroot-fd", -1, "file descriptor that the gofer waits on until container filesystem setup is done")
	f.IntVar(&g.usernsFD, "sync-userns-fd", -1, "file descriptor the gofer waits on until userns mappings are set up")
	f.IntVar(&g.procMountFD, "proc-mount-sync-fd", -1, "file descriptor that the gofer writes to when /proc isn't needed anymore and can be unmounted")
}

// flags returns the flags necessary to pass along the current sync FD values
// to a re-executed version of this process.
func (g *goferSyncFDs) flags() map[string]string {
	return map[string]string{
		"sync-chroot-fd":     fmt.Sprintf("%d", g.chrootFD),
		"sync-userns-fd":     fmt.Sprintf("%d", g.usernsFD),
		"proc-mount-sync-fd": fmt.Sprintf("%d", g.procMountFD),
	}
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
	cmd, w := sandboxsetup.ExecProcUmounter()
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
	sandboxsetup.UmountProc(g.procMountFD)
	g.procMountFD = -1
}

// syncUsernsForRootless waits on usernsFD to be closed and then sets
// UID/GID to uid/gid. Note that this function calls runtime.LockOSThread().
// This function is a no-op if usernsFD is -1.
//
// Postcondition: All callers must re-exec themselves after this returns,
// unless usernsFD was -1.
func (g *goferSyncFDs) syncUsernsForRootless(uid, gid uint32) {
	if g.usernsFD < 0 {
		return
	}
	syncUsernsForRootless(g.usernsFD, uid, gid)
	g.usernsFD = -1
}

// syncUsernsForRootless waits on usernsFD to be closed and then sets
// UID/GID to uid/gid. Note that this function calls runtime.LockOSThread().
//
// Postcondition: All callers must re-exec themselves after this returns.
func syncUsernsForRootless(fd int, uid uint32, gid uint32) {
	if err := sandboxsetup.WaitForFD(fd, "userns sync FD"); err != nil {
		util.Fatalf("failed to sync on userns FD: %v", err)
	}

	// SETUID changes UID on the current system thread, so we have
	// to re-execute current binary.
	runtime.LockOSThread()
	if _, _, errno := unix.RawSyscall(unix.SYS_SETUID, uintptr(uid), 0, 0); errno != 0 {
		util.Fatalf("failed to set UID: %v", errno)
	}
	if _, _, errno := unix.RawSyscall(unix.SYS_SETGID, uintptr(gid), 0, 0); errno != 0 {
		util.Fatalf("failed to set GID: %v", errno)
	}
}

// syncChroot waits on chrootFD to be closed.
// Used for synchronization during container filesystem setup which is done
// from the non-gofer process.
// This function is a no-op if chrootFD is -1.
func (g *goferSyncFDs) syncChroot() {
	if g.chrootFD < 0 {
		return
	}
	if err := sandboxsetup.WaitForFD(g.chrootFD, "chroot sync FD"); err != nil {
		util.Fatalf("failed to sync on chroot FD: %v", err)
	}
	g.chrootFD = -1
}

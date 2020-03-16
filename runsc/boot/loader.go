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

// Package boot loads the kernel and runs a container.
package boot

import (
	"errors"
	"fmt"
	mrand "math/rand"
	"os"
	"runtime"
	"sync/atomic"
	gtime "time"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/bpf"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/cpuid"
	"gvisor.dev/gvisor/pkg/fd"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/memutil"
	"gvisor.dev/gvisor/pkg/rand"
	"gvisor.dev/gvisor/pkg/refs"
	"gvisor.dev/gvisor/pkg/refsvfs2"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/control"
	"gvisor.dev/gvisor/pkg/sentry/fdimport"
	"gvisor.dev/gvisor/pkg/sentry/fs"
	"gvisor.dev/gvisor/pkg/sentry/fs/host"
	"gvisor.dev/gvisor/pkg/sentry/fs/user"
	hostvfs2 "gvisor.dev/gvisor/pkg/sentry/fsimpl/host"
	"gvisor.dev/gvisor/pkg/sentry/inet"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/loader"
	"gvisor.dev/gvisor/pkg/sentry/pgalloc"
	"gvisor.dev/gvisor/pkg/sentry/platform"
	"gvisor.dev/gvisor/pkg/sentry/sighandling"
	"gvisor.dev/gvisor/pkg/sentry/socket/netfilter"
	"gvisor.dev/gvisor/pkg/sentry/syscalls/linux/vfs2"
	"gvisor.dev/gvisor/pkg/sentry/time"
	"gvisor.dev/gvisor/pkg/sentry/usage"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/sentry/watchdog"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/link/loopback"
	"gvisor.dev/gvisor/pkg/tcpip/link/sniffer"
	"gvisor.dev/gvisor/pkg/tcpip/network/arp"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/raw"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/runsc/boot/filter"
	_ "gvisor.dev/gvisor/runsc/boot/platforms" // register all platforms.
	"gvisor.dev/gvisor/runsc/boot/pprof"
	"gvisor.dev/gvisor/runsc/config"
	"gvisor.dev/gvisor/runsc/specutils"
	"gvisor.dev/gvisor/runsc/specutils/seccomp"

	// Top-level inet providers.
	"gvisor.dev/gvisor/pkg/sentry/socket/hostinet"
	"gvisor.dev/gvisor/pkg/sentry/socket/netstack"

	// Include other supported socket providers.
	_ "gvisor.dev/gvisor/pkg/sentry/socket/netlink"
	_ "gvisor.dev/gvisor/pkg/sentry/socket/netlink/route"
	_ "gvisor.dev/gvisor/pkg/sentry/socket/netlink/uevent"
	_ "gvisor.dev/gvisor/pkg/sentry/socket/unix"
)

type containerInfo struct {
	conf *config.Config

	// spec is the base configuration for the root container.
	spec *specs.Spec

	// procArgs refers to the container's init task.
	procArgs kernel.CreateProcessArgs

	// stdioFDs contains stdin, stdout, and stderr.
	stdioFDs []*fd.FD

	// goferFDs are the FDs that attach the sandbox to the gofers.
	goferFDs []*fd.FD
}

// Loader keeps state needed to start the kernel and run the container..
type Loader struct {
	// k is the kernel.
	k *kernel.Kernel

	// ctrl is the control server.
	ctrl *controller

	// root contains information about the root container in the sandbox.
	root containerInfo

	watchdog *watchdog.Watchdog

	// stopSignalForwarding disables forwarding of signals to the sandboxed
	// container. It should be called when a sandbox is destroyed.
	stopSignalForwarding func()

	// restore is set to true if we are restoring a container.
	restore bool

	// sandboxID is the ID for the whole sandbox.
	sandboxID string

	// mu guards processes.
	mu sync.Mutex

	// processes maps containers init process and invocation of exec. Root
	// processes are keyed with container ID and pid=0, while exec invocations
	// have the corresponding pid set.
	//
	// processes is guardded by mu.
	processes map[execID]*execProcess

	// mountHints provides extra information about mounts for containers that
	// apply to the entire pod.
	mountHints *podMountHints
}

// execID uniquely identifies a sentry process that is executed in a container.
type execID struct {
	cid string
	pid kernel.ThreadID
}

// execProcess contains the thread group and host TTY of a sentry process.
type execProcess struct {
	// tg will be nil for containers that haven't started yet.
	tg *kernel.ThreadGroup

	// tty will be nil if the process is not attached to a terminal.
	tty *host.TTYFileOperations

	// tty will be nil if the process is not attached to a terminal.
	ttyVFS2 *hostvfs2.TTYFileDescription

	// pidnsPath is the pid namespace path in spec
	pidnsPath string

	// hostTTY is present when creating a sub-container with terminal enabled.
	// TTY file is passed during container create and must be saved until
	// container start.
	hostTTY *fd.FD
}

func init() {
	// Initialize the random number generator.
	mrand.Seed(gtime.Now().UnixNano())
}

// Args are the arguments for New().
type Args struct {
	// Id is the sandbox ID.
	ID string
	// Spec is the sandbox specification.
	Spec *specs.Spec
	// Conf is the system configuration.
	Conf *config.Config
	// ControllerFD is the FD to the URPC controller. The Loader takes ownership
	// of this FD and may close it at any time.
	ControllerFD int
	// Device is an optional argument that is passed to the platform. The Loader
	// takes ownership of this file and may close it at any time.
	Device *os.File
	// GoferFDs is an array of FDs used to connect with the Gofer. The Loader
	// takes ownership of these FDs and may close them at any time.
	GoferFDs []int
	// StdioFDs is the stdio for the application. The Loader takes ownership of
	// these FDs and may close them at any time.
	StdioFDs []int
	// NumCPU is the number of CPUs to create inside the sandbox.
	NumCPU int
	// TotalMem is the initial amount of total memory to report back to the
	// container.
	TotalMem uint64
	// UserLogFD is the file descriptor to write user logs to.
	UserLogFD int
}

// make sure stdioFDs are always the same on initial start and on restore
const startingStdioFD = 256

// New initializes a new kernel loader configured by spec.
// New also handles setting up a kernel for restoring a container.
func New(args Args) (*Loader, error) {
	// We initialize the rand package now to make sure /dev/urandom is pre-opened
	// on kernels that do not support getrandom(2).
	if err := rand.Init(); err != nil {
		return nil, fmt.Errorf("setting up rand: %v", err)
	}

	if err := usage.Init(); err != nil {
		return nil, fmt.Errorf("setting up memory usage: %v", err)
	}

	// Is this a VFSv2 kernel?
	if args.Conf.VFS2 {
		kernel.VFS2Enabled = true
		if args.Conf.FUSE {
			kernel.FUSEEnabled = true
		}

		vfs2.Override()
	}

	// Create kernel and platform.
	p, err := createPlatform(args.Conf, args.Device)
	if err != nil {
		return nil, fmt.Errorf("creating platform: %v", err)
	}
	k := &kernel.Kernel{
		Platform: p,
	}

	// Create memory file.
	mf, err := createMemoryFile()
	if err != nil {
		return nil, fmt.Errorf("creating memory file: %v", err)
	}
	k.SetMemoryFile(mf)

	// Create VDSO.
	//
	// Pass k as the platform since it is savable, unlike the actual platform.
	vdso, err := loader.PrepareVDSO(k)
	if err != nil {
		return nil, fmt.Errorf("creating vdso: %v", err)
	}

	// Create timekeeper.
	tk, err := kernel.NewTimekeeper(k, vdso.ParamPage.FileRange())
	if err != nil {
		return nil, fmt.Errorf("creating timekeeper: %v", err)
	}
	tk.SetClocks(time.NewCalibratedClocks())

	if err := enableStrace(args.Conf); err != nil {
		return nil, fmt.Errorf("enabling strace: %v", err)
	}

	// Create root network namespace/stack.
	netns, err := newRootNetworkNamespace(args.Conf, k, k)
	if err != nil {
		return nil, fmt.Errorf("creating network: %v", err)
	}

	// Create capabilities.
	caps, err := specutils.Capabilities(args.Conf.EnableRaw, args.Spec.Process.Capabilities)
	if err != nil {
		return nil, fmt.Errorf("converting capabilities: %v", err)
	}

	// Convert the spec's additional GIDs to KGIDs.
	extraKGIDs := make([]auth.KGID, 0, len(args.Spec.Process.User.AdditionalGids))
	for _, GID := range args.Spec.Process.User.AdditionalGids {
		extraKGIDs = append(extraKGIDs, auth.KGID(GID))
	}

	// Create credentials.
	creds := auth.NewUserCredentials(
		auth.KUID(args.Spec.Process.User.UID),
		auth.KGID(args.Spec.Process.User.GID),
		extraKGIDs,
		caps,
		auth.NewRootUserNamespace())

	if args.NumCPU == 0 {
		args.NumCPU = runtime.NumCPU()
	}
	log.Infof("CPUs: %d", args.NumCPU)
	runtime.GOMAXPROCS(args.NumCPU)

	if args.TotalMem > 0 {
		// Adjust the total memory returned by the Sentry so that applications that
		// use /proc/meminfo can make allocations based on this limit.
		usage.MaximumTotalMemoryBytes = args.TotalMem
		log.Infof("Setting total memory to %.2f GB", float64(args.TotalMem)/(1<<30))
	}

	// Initiate the Kernel object, which is required by the Context passed
	// to createVFS in order to mount (among other things) procfs.
	if err = k.Init(kernel.InitKernelArgs{
		FeatureSet:                  cpuid.HostFeatureSet(),
		Timekeeper:                  tk,
		RootUserNamespace:           creds.UserNamespace,
		RootNetworkNamespace:        netns,
		ApplicationCores:            uint(args.NumCPU),
		Vdso:                        vdso,
		RootUTSNamespace:            kernel.NewUTSNamespace(args.Spec.Hostname, args.Spec.Hostname, creds.UserNamespace),
		RootIPCNamespace:            kernel.NewIPCNamespace(creds.UserNamespace),
		RootAbstractSocketNamespace: kernel.NewAbstractSocketNamespace(),
		PIDNamespace:                kernel.NewRootPIDNamespace(creds.UserNamespace),
	}); err != nil {
		return nil, fmt.Errorf("initializing kernel: %v", err)
	}

	if kernel.VFS2Enabled {
		if err := registerFilesystems(k); err != nil {
			return nil, fmt.Errorf("registering filesystems: %w", err)
		}
	}

	if err := adjustDirentCache(k); err != nil {
		return nil, err
	}

	// Turn on packet logging if enabled.
	if args.Conf.LogPackets {
		log.Infof("Packet logging enabled")
		atomic.StoreUint32(&sniffer.LogPackets, 1)
	} else {
		log.Infof("Packet logging disabled")
		atomic.StoreUint32(&sniffer.LogPackets, 0)
	}

	// Create a watchdog.
	dogOpts := watchdog.DefaultOpts
	dogOpts.TaskTimeoutAction = args.Conf.WatchdogAction
	dog := watchdog.New(k, dogOpts)

	procArgs, err := createProcessArgs(args.ID, args.Spec, creds, k, k.RootPIDNamespace())
	if err != nil {
		return nil, fmt.Errorf("creating init process for root container: %v", err)
	}

	if err := initCompatLogs(args.UserLogFD); err != nil {
		return nil, fmt.Errorf("initializing compat logs: %v", err)
	}

	mountHints, err := newPodMountHints(args.Spec)
	if err != nil {
		return nil, fmt.Errorf("creating pod mount hints: %v", err)
	}

	if kernel.VFS2Enabled {
		// Set up host mount that will be used for imported fds.
		hostFilesystem, err := hostvfs2.NewFilesystem(k.VFS())
		if err != nil {
			return nil, fmt.Errorf("failed to create hostfs filesystem: %v", err)
		}
		defer hostFilesystem.DecRef(k.SupervisorContext())
		hostMount, err := k.VFS().NewDisconnectedMount(hostFilesystem, nil, &vfs.MountOptions{})
		if err != nil {
			return nil, fmt.Errorf("failed to create hostfs mount: %v", err)
		}
		k.SetHostMount(hostMount)
	}

	info := containerInfo{
		conf:     args.Conf,
		spec:     args.Spec,
		procArgs: procArgs,
	}

	// Make host FDs stable between invocations. Host FDs must map to the exact
	// same number when the sandbox is restored. Otherwise the wrong FD will be
	// used.
	newfd := startingStdioFD
	for _, stdioFD := range args.StdioFDs {
		// Check that newfd is unused to avoid clobbering over it.
		if _, err := unix.FcntlInt(uintptr(newfd), unix.F_GETFD, 0); !errors.Is(err, unix.EBADF) {
			if err != nil {
				return nil, fmt.Errorf("error checking for FD (%d) conflict: %w", newfd, err)
			}
			return nil, fmt.Errorf("unable to remap stdios, FD %d is already in use", newfd)
		}

		err := unix.Dup3(stdioFD, newfd, unix.O_CLOEXEC)
		if err != nil {
			return nil, fmt.Errorf("dup3 of stdios failed: %w", err)
		}
		info.stdioFDs = append(info.stdioFDs, fd.New(newfd))
		_ = unix.Close(stdioFD)
		newfd++
	}
	for _, goferFD := range args.GoferFDs {
		info.goferFDs = append(info.goferFDs, fd.New(goferFD))
	}

	eid := execID{cid: args.ID}
	l := &Loader{
		k:          k,
		watchdog:   dog,
		sandboxID:  args.ID,
		processes:  map[execID]*execProcess{eid: {}},
		mountHints: mountHints,
		root:       info,
		containers: map[string]int{args.ID: 0},
	}

	// We don't care about child signals; some platforms can generate a
	// tremendous number of useless ones (I'm looking at you, ptrace).
	if err := sighandling.IgnoreChildStop(); err != nil {
		return nil, fmt.Errorf("ignore child stop signals failed: %v", err)
	}

	// Create the control server using the provided FD.
	//
	// This must be done *after* we have initialized the kernel since the
	// controller is used to configure the kernel's network stack.
	ctrl, err := newController(args.ControllerFD, l)
	if err != nil {
		return nil, fmt.Errorf("creating control server: %v", err)
	}
	l.ctrl = ctrl

	// Only start serving after Loader is set to controller and controller is set
	// to Loader, because they are both used in the urpc methods.
	if err := ctrl.srv.StartServing(); err != nil {
		return nil, fmt.Errorf("starting control server: %v", err)
	}

	return l, nil
}

// createProcessArgs creates args that can be used with kernel.CreateProcess.
func createProcessArgs(id string, spec *specs.Spec, creds *auth.Credentials, k *kernel.Kernel, pidns *kernel.PIDNamespace) (kernel.CreateProcessArgs, error) {
	// Create initial limits.
	ls, err := createLimitSet(spec)
	if err != nil {
		return kernel.CreateProcessArgs{}, fmt.Errorf("creating limits: %v", err)
	}
	env, err := specutils.ResolveEnvs(spec.Process.Env)
	if err != nil {
		return kernel.CreateProcessArgs{}, fmt.Errorf("resolving env: %w", err)
	}

	wd := spec.Process.Cwd
	if wd == "" {
		wd = "/"
	}

	// Create the process arguments.
	procArgs := kernel.CreateProcessArgs{
		Argv:                    spec.Process.Args,
		Envv:                    env,
		WorkingDirectory:        wd,
		Credentials:             creds,
		Umask:                   0022,
		Limits:                  ls,
		MaxSymlinkTraversals:    linux.MaxSymlinkTraversals,
		UTSNamespace:            k.RootUTSNamespace(),
		IPCNamespace:            k.RootIPCNamespace(),
		AbstractSocketNamespace: k.RootAbstractSocketNamespace(),
		ContainerID:             id,
		PIDNamespace:            pidns,
	}

	return procArgs, nil
}

// Destroy cleans up all resources used by the loader.
//
// Note that this will block until all open control server connections have
// been closed. For that reason, this should NOT be called in a defer, because
// a panic in a control server rpc would then hang forever.
func (l *Loader) Destroy() {
	if l.ctrl != nil {
		l.ctrl.srv.Stop()
	}
	if l.stopSignalForwarding != nil {
		l.stopSignalForwarding()
	}
	l.watchdog.Stop()

	// Release all kernel resources. This is only safe after we can no longer
	// save/restore.
	l.k.Release()

	// All sentry-created resources should have been released at this point;
	// check for reference leaks.
	refsvfs2.DoLeakCheck()

	// In the success case, stdioFDs and goferFDs will only contain
	// released/closed FDs that ownership has been passed over to host FDs and
	// gofer sessions. Close them here in case of failure.
	for _, fd := range l.root.stdioFDs {
		_ = fd.Close()
	}
	for _, fd := range l.root.goferFDs {
		_ = fd.Close()
	}
}

func createPlatform(conf *config.Config, deviceFile *os.File) (platform.Platform, error) {
	p, err := platform.Lookup(conf.Platform)
	if err != nil {
		panic(fmt.Sprintf("invalid platform %v: %v", conf.Platform, err))
	}
	log.Infof("Platform: %s", conf.Platform)
	return p.New(deviceFile)
}

func createMemoryFile() (*pgalloc.MemoryFile, error) {
	const memfileName = "runsc-memory"
	memfd, err := memutil.CreateMemFD(memfileName, 0)
	if err != nil {
		return nil, fmt.Errorf("error creating memfd: %v", err)
	}
	memfile := os.NewFile(uintptr(memfd), memfileName)
	// We can't enable pgalloc.MemoryFileOpts.UseHostMemcgPressure even if
	// there are memory cgroups specified, because at this point we're already
	// in a mount namespace in which the relevant cgroupfs is not visible.
	mf, err := pgalloc.NewMemoryFile(memfile, pgalloc.MemoryFileOpts{})
	if err != nil {
		memfile.Close()
		return nil, fmt.Errorf("error creating pgalloc.MemoryFile: %v", err)
	}
	return mf, nil
}

// installSeccompFilters installs sandbox seccomp filters with the host.
func (l *Loader) installSeccompFilters() error {
	if l.root.conf.DisableSeccomp {
		filter.Report("syscall filter is DISABLED. Running in less secure mode.")
	} else {
		opts := filter.Options{
			Platform:      l.k.Platform,
			HostNetwork:   l.root.conf.Network == config.NetworkHost,
			ProfileEnable: l.root.conf.ProfileEnable,
			ControllerFD:  l.ctrl.srv.FD(),
		}
		if err := filter.Install(opts); err != nil {
			return fmt.Errorf("installing seccomp filters: %v", err)
		}
	}
	return nil
}

// Run runs the root container.
func (l *Loader) Run() error {
	err := l.run()
	l.ctrl.manager.startResultChan <- err
	if err != nil {
		// Give the controller some time to send the error to the
		// runtime. If we return too quickly here the process will exit
		// and the control connection will be closed before the error
		// is returned.
		gtime.Sleep(2 * gtime.Second)
		return err
	}
	return nil
}

func (l *Loader) run() error {
	if l.root.conf.Network == config.NetworkHost {
		// Delay host network configuration to this point because network namespace
		// is configured after the loader is created and before Run() is called.
		log.Debugf("Configuring host network")
		stack := l.k.RootNetworkNamespace().Stack().(*hostinet.Stack)
		if err := stack.Configure(); err != nil {
			return err
		}
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	eid := execID{cid: l.sandboxID}
	ep, ok := l.processes[eid]
	if !ok {
		return fmt.Errorf("trying to start deleted container %q", l.sandboxID)
	}

	// If we are restoring, we do not want to create a process.
	// l.restore is set by the container manager when a restore call is made.
	if !l.restore {
		if l.root.conf.ProfileEnable {
			pprof.Initialize()
		}

		// Finally done with all configuration. Setup filters before user code
		// is loaded.
		if err := l.installSeccompFilters(); err != nil {
			return err
		}

		// Create the root container init task. It will begin running
		// when the kernel is started.
		var err error
		_, ep.tty, ep.ttyVFS2, err = l.createContainerProcess(true, l.sandboxID, &l.root)
		if err != nil {
			return err
		}
	}

	ep.tg = l.k.GlobalInit()
	if ns, ok := specutils.GetNS(specs.PIDNamespace, l.root.spec); ok {
		ep.pidnsPath = ns.Path
	}

	// Handle signals by forwarding them to the root container process
	// (except for panic signal, which should cause a panic).
	l.stopSignalForwarding = sighandling.StartSignalForwarding(func(sig linux.Signal) {
		// Panic signal should cause a panic.
		if l.root.conf.PanicSignal != -1 && sig == linux.Signal(l.root.conf.PanicSignal) {
			panic("Signal-induced panic")
		}

		// Otherwise forward to root container.
		deliveryMode := DeliverToProcess
		if l.root.spec.Process.Terminal {
			// Since we are running with a console, we should forward the signal to
			// the foreground process group so that job control signals like ^C can
			// be handled properly.
			deliveryMode = DeliverToForegroundProcessGroup
		}
		log.Infof("Received external signal %d, mode: %v", sig, deliveryMode)
		if err := l.signal(l.sandboxID, 0, int32(sig), deliveryMode); err != nil {
			log.Warningf("error sending signal %v to container %q: %v", sig, l.sandboxID, err)
		}
	})

	log.Infof("Process should have started...")
	l.watchdog.Start()
	return l.k.Start()
}

// createContainer creates a new container inside the sandbox.
func (l *Loader) createContainer(cid string, tty *fd.FD) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	eid := execID{cid: cid}
	if _, ok := l.processes[eid]; ok {
		return fmt.Errorf("container %q already exists", cid)
	}
	l.processes[eid] = &execProcess{hostTTY: tty}
	return nil
}

// startContainer starts a child container. It returns the thread group ID of
// the newly created process. Used FDs are either closed or released. It's safe
// for the caller to close any remaining files upon return.
func (l *Loader) startContainer(spec *specs.Spec, conf *config.Config, cid string, stdioFDs, goferFDs []*fd.FD) error {
	// Create capabilities.
	caps, err := specutils.Capabilities(conf.EnableRaw, spec.Process.Capabilities)
	if err != nil {
		return fmt.Errorf("creating capabilities: %v", err)
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	ep := l.processes[execID{cid: cid}]
	if ep == nil {
		return fmt.Errorf("trying to start a deleted container %q", cid)
	}

	// Convert the spec's additional GIDs to KGIDs.
	extraKGIDs := make([]auth.KGID, 0, len(spec.Process.User.AdditionalGids))
	for _, GID := range spec.Process.User.AdditionalGids {
		extraKGIDs = append(extraKGIDs, auth.KGID(GID))
	}

	// Create credentials. We reuse the root user namespace because the
	// sentry currently supports only 1 mount namespace, which is tied to a
	// single user namespace. Thus we must run in the same user namespace
	// to access mounts.
	creds := auth.NewUserCredentials(
		auth.KUID(spec.Process.User.UID),
		auth.KGID(spec.Process.User.GID),
		extraKGIDs,
		caps,
		l.k.RootUserNamespace())

	var pidns *kernel.PIDNamespace
	if ns, ok := specutils.GetNS(specs.PIDNamespace, spec); ok {
		if ns.Path != "" {
			for _, p := range l.processes {
				if ns.Path == p.pidnsPath {
					pidns = p.tg.PIDNamespace()
					break
				}
			}
		}
		if pidns == nil {
			pidns = l.k.RootPIDNamespace().NewChild(l.k.RootUserNamespace())
		}
		ep.pidnsPath = ns.Path
	} else {
		pidns = l.k.RootPIDNamespace()
	}

	info := &containerInfo{
		conf:     conf,
		spec:     spec,
		goferFDs: goferFDs,
	}
	info.procArgs, err = createProcessArgs(cid, spec, creds, l.k, pidns)
	if err != nil {
		return fmt.Errorf("creating new process: %v", err)
	}

	// Use stdios or TTY depending on the spec configuration.
	if spec.Process.Terminal {
		if len(stdioFDs) > 0 {
			return fmt.Errorf("using TTY, stdios not expected: %v", stdioFDs)
		}
		if ep.hostTTY == nil {
			return fmt.Errorf("terminal enabled but no TTY provided. Did you set --console-socket on create?")
		}
		info.stdioFDs = []*fd.FD{ep.hostTTY, ep.hostTTY, ep.hostTTY}
		ep.hostTTY = nil
	} else {
		info.stdioFDs = stdioFDs
	}

	ep.tg, ep.tty, ep.ttyVFS2, err = l.createContainerProcess(false, cid, info)
	if err != nil {
		return err
	}
	l.k.StartProcess(ep.tg)
	return nil
}

func (l *Loader) createContainerProcess(root bool, cid string, info *containerInfo) (*kernel.ThreadGroup, *host.TTYFileOperations, *hostvfs2.TTYFileDescription, error) {
	// Create the FD map, which will set stdin, stdout, and stderr.
	ctx := info.procArgs.NewContext(l.k)
	fdTable, ttyFile, ttyFileVFS2, err := createFDTable(ctx, info.spec.Process.Terminal, info.stdioFDs)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("importing fds: %v", err)
	}
	// CreateProcess takes a reference on fdTable if successful. We won't need
	// ours either way.
	info.procArgs.FDTable = fdTable

	// Setup the child container file system.
	l.startGoferMonitor(cid, info.goferFDs)

	mntr := newContainerMounter(info.spec, info.goferFDs, l.k, l.mountHints)
	if root {
		if err := mntr.processHints(info.conf, info.procArgs.Credentials); err != nil {
			return nil, nil, nil, err
		}
	}
	if err := setupContainerFS(ctx, info.conf, mntr, &info.procArgs); err != nil {
		return nil, nil, nil, err
	}

	// Add the HOME environment variable if it is not already set.
	var envv []string
	if kernel.VFS2Enabled {
		envv, err = user.MaybeAddExecUserHomeVFS2(ctx, info.procArgs.MountNamespaceVFS2,
			info.procArgs.Credentials.RealKUID, info.procArgs.Envv)

	} else {
		envv, err = user.MaybeAddExecUserHome(ctx, info.procArgs.MountNamespace,
			info.procArgs.Credentials.RealKUID, info.procArgs.Envv)
	}
	if err != nil {
		return nil, nil, nil, err
	}
	info.procArgs.Envv = envv

	// Create and start the new process.
	tg, _, err := l.k.CreateProcess(info.procArgs)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("creating process: %v", err)
	}
	// CreateProcess takes a reference on FDTable if successful.
	info.procArgs.FDTable.DecRef(ctx)

	// Set the foreground process group on the TTY to the global init process
	// group, since that is what we are about to start running.
	switch {
	case ttyFileVFS2 != nil:
		ttyFileVFS2.InitForegroundProcessGroup(tg.ProcessGroup())
	case ttyFile != nil:
		ttyFile.InitForegroundProcessGroup(tg.ProcessGroup())
	}

	// Install seccomp filters with the new task if there are any.
	if info.conf.OCISeccomp {
		if info.spec.Linux != nil && info.spec.Linux.Seccomp != nil {
			program, err := seccomp.BuildProgram(info.spec.Linux.Seccomp)
			if err != nil {
				return nil, nil, nil, fmt.Errorf("building seccomp program: %v", err)
			}

			if log.IsLogging(log.Debug) {
				out, _ := bpf.DecodeProgram(program)
				log.Debugf("Installing OCI seccomp filters\nProgram:\n%s", out)
			}

			task := tg.Leader()
			// NOTE: It seems Flags are ignored by runc so we ignore them too.
			if err := task.AppendSyscallFilter(program, true); err != nil {
				return nil, nil, nil, fmt.Errorf("appending seccomp filters: %v", err)
			}
		}
	} else {
		if info.spec.Linux != nil && info.spec.Linux.Seccomp != nil {
			log.Warningf("Seccomp spec is being ignored")
		}
	}

	return tg, ttyFile, ttyFileVFS2, nil
}

// startGoferMonitor runs a goroutine to monitor gofer's health. It polls on
// the gofer FDs looking for disconnects, and kills the container processes if a
// disconnect occurs in any of the gofer FDs.
func (l *Loader) startGoferMonitor(cid string, goferFDs []*fd.FD) {
	go func() {
		log.Debugf("Monitoring gofer health for container %q", cid)
		var events []unix.PollFd
		for _, goferFD := range goferFDs {
			events = append(events, unix.PollFd{
				Fd:     int32(goferFD.FD()),
				Events: unix.POLLHUP | unix.POLLRDHUP,
			})
		}
		_, _, err := specutils.RetryEintr(func() (uintptr, uintptr, error) {
			// Use ppoll instead of poll because it's already whilelisted in seccomp.
			n, err := unix.Ppoll(events, nil, nil)
			return uintptr(n), 0, err
		})
		if err != nil {
			panic(fmt.Sprintf("Error monitoring gofer FDs: %v", err))
		}

		l.mu.Lock()
		defer l.mu.Unlock()

		// The gofer could have been stopped due to a normal container shutdown.
		// Check if the container has not stopped yet.
		if tg, _ := l.tryThreadGroupFromIDLocked(execID{cid: cid}); tg != nil {
			log.Infof("Gofer socket disconnected, killing container %q", cid)
			if err := l.signalAllProcesses(cid, int32(linux.SIGKILL)); err != nil {
				log.Warningf("Error killing container %q after gofer stopped: %v", cid, err)
			}
		}
	}()
}

// destroyContainer stops a container if it is still running and cleans up its
// filesystem.
func (l *Loader) destroyContainer(cid string) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	tg, err := l.tryThreadGroupFromIDLocked(execID{cid: cid})
	if err != nil {
		// Container doesn't exist.
		return err
	}

	// The container exists, but has it been started?
	if tg != nil {
		if err := l.signalAllProcesses(cid, int32(linux.SIGKILL)); err != nil {
			return fmt.Errorf("sending SIGKILL to all container processes: %v", err)
		}
		// Wait for all processes that belong to the container to exit (including
		// exec'd processes).
		for _, t := range l.k.TaskSet().Root.Tasks() {
			if t.ContainerID() == cid {
				t.ThreadGroup().WaitExited()
			}
		}

		// At this point, all processes inside of the container have exited,
		// releasing all references to the container's MountNamespace and
		// causing all submounts and overlays to be unmounted.
		//
		// Since the container's MountNamespace has been released,
		// MountNamespace.destroy() will have executed, but that function may
		// trigger async close operations. We must wait for those to complete
		// before returning, otherwise the caller may kill the gofer before
		// they complete, causing a cascade of failing RPCs.
		fs.AsyncBarrier()
	}

	// No more failure from this point on. Remove all container thread groups
	// from the map.
	for key := range l.processes {
		if key.cid == cid {
			delete(l.processes, key)
		}
	}

	log.Debugf("Container destroyed, cid: %s", cid)
	return nil
}

func (l *Loader) executeAsync(args *control.ExecArgs) (kernel.ThreadID, error) {
	// Hold the lock for the entire operation to ensure that exec'd process is
	// added to 'processes' in case it races with destroyContainer().
	l.mu.Lock()
	defer l.mu.Unlock()

	tg, err := l.tryThreadGroupFromIDLocked(execID{cid: args.ContainerID})
	if err != nil {
		return 0, err
	}
	if tg == nil {
		return 0, fmt.Errorf("container %q not started", args.ContainerID)
	}

	// Get the container MountNamespace from the Task. Try to acquire ref may fail
	// in case it raced with task exit.
	if kernel.VFS2Enabled {
		// task.MountNamespaceVFS2() does not take a ref, so we must do so ourselves.
		args.MountNamespaceVFS2 = tg.Leader().MountNamespaceVFS2()
		if !args.MountNamespaceVFS2.TryIncRef() {
			return 0, fmt.Errorf("container %q has stopped", args.ContainerID)
		}
	} else {
		var reffed bool
		tg.Leader().WithMuLocked(func(t *kernel.Task) {
			// task.MountNamespace() does not take a ref, so we must do so ourselves.
			args.MountNamespace = t.MountNamespace()
			reffed = args.MountNamespace.TryIncRef()
		})
		if !reffed {
			return 0, fmt.Errorf("container %q has stopped", args.ContainerID)
		}
	}

	args.Envv, err = specutils.ResolveEnvs(args.Envv)
	if err != nil {
		return 0, fmt.Errorf("resolving env: %w", err)
	}

	// Add the HOME environment variable if it is not already set.
	if kernel.VFS2Enabled {
		root := args.MountNamespaceVFS2.Root()
		ctx := vfs.WithRoot(l.k.SupervisorContext(), root)
		defer args.MountNamespaceVFS2.DecRef(ctx)
		envv, err := user.MaybeAddExecUserHomeVFS2(ctx, args.MountNamespaceVFS2, args.KUID, args.Envv)
		if err != nil {
			return 0, err
		}
		args.Envv = envv
	} else {
		root := args.MountNamespace.Root()
		ctx := fs.WithRoot(l.k.SupervisorContext(), root)
		defer args.MountNamespace.DecRef(ctx)
		defer root.DecRef(ctx)
		envv, err := user.MaybeAddExecUserHome(ctx, args.MountNamespace, args.KUID, args.Envv)
		if err != nil {
			return 0, err
		}
		args.Envv = envv
	}

	// Start the process.
	proc := control.Proc{Kernel: l.k}
	args.PIDNamespace = tg.PIDNamespace()
	newTG, tgid, ttyFile, ttyFileVFS2, err := control.ExecAsync(&proc, args)
	if err != nil {
		return 0, err
	}

	eid := execID{cid: args.ContainerID, pid: tgid}
	l.processes[eid] = &execProcess{
		tg:      newTG,
		tty:     ttyFile,
		ttyVFS2: ttyFileVFS2,
	}
	log.Debugf("updated processes: %v", l.processes)

	return tgid, nil
}

// waitContainer waits for the init process of a container to exit.
func (l *Loader) waitContainer(cid string, waitStatus *uint32) error {
	// Don't defer unlock, as doing so would make it impossible for
	// multiple clients to wait on the same container.
	tg, err := l.threadGroupFromID(execID{cid: cid})
	if err != nil {
		return fmt.Errorf("can't wait for container %q: %v", cid, err)
	}

	// If the thread either has already exited or exits during waiting,
	// consider the container exited.
	ws := l.wait(tg)
	*waitStatus = ws
	return nil
}

func (l *Loader) waitPID(tgid kernel.ThreadID, cid string, waitStatus *uint32) error {
	if tgid <= 0 {
		return fmt.Errorf("PID (%d) must be positive", tgid)
	}

	// Try to find a process that was exec'd
	eid := execID{cid: cid, pid: tgid}
	execTG, err := l.threadGroupFromID(eid)
	if err == nil {
		ws := l.wait(execTG)
		*waitStatus = ws

		l.mu.Lock()
		delete(l.processes, eid)
		log.Debugf("updated processes (removal): %v", l.processes)
		l.mu.Unlock()
		return nil
	}

	// The caller may be waiting on a process not started directly via exec.
	// In this case, find the process in the container's PID namespace.
	initTG, err := l.threadGroupFromID(execID{cid: cid})
	if err != nil {
		return fmt.Errorf("waiting for PID %d: %v", tgid, err)
	}
	tg := initTG.PIDNamespace().ThreadGroupWithID(tgid)
	if tg == nil {
		return fmt.Errorf("waiting for PID %d: no such process", tgid)
	}
	if tg.Leader().ContainerID() != cid {
		return fmt.Errorf("process %d is part of a different container: %q", tgid, tg.Leader().ContainerID())
	}
	ws := l.wait(tg)
	*waitStatus = ws
	return nil
}

// wait waits for the process with TGID 'tgid' in a container's PID namespace
// to exit.
func (l *Loader) wait(tg *kernel.ThreadGroup) uint32 {
	tg.WaitExited()
	return tg.ExitStatus().Status()
}

// WaitForStartSignal waits for a start signal from the control server.
func (l *Loader) WaitForStartSignal() {
	<-l.ctrl.manager.startChan
}

// WaitExit waits for the root container to exit, and returns its exit status.
func (l *Loader) WaitExit() kernel.ExitStatus {
	// Wait for container.
	l.k.WaitExited()

	// Stop the control server.
	l.ctrl.stop()

	// Check all references.
	refs.OnExit()

	return l.k.GlobalInit().ExitStatus()
}

func newRootNetworkNamespace(conf *config.Config, clock tcpip.Clock, uniqueID stack.UniqueID) (*inet.Namespace, error) {
	// Create an empty network stack because the network namespace may be empty at
	// this point. Netns is configured before Run() is called. Netstack is
	// configured using a control uRPC message. Host network is configured inside
	// Run().
	switch conf.Network {
	case config.NetworkHost:
		// No network namespacing support for hostinet yet, hence creator is nil.
		return inet.NewRootNamespace(hostinet.NewStack(), nil), nil

	case config.NetworkNone, config.NetworkSandbox:
		s, err := newEmptySandboxNetworkStack(clock, uniqueID)
		if err != nil {
			return nil, err
		}
		creator := &sandboxNetstackCreator{
			clock:    clock,
			uniqueID: uniqueID,
		}
		return inet.NewRootNamespace(s, creator), nil

	default:
		panic(fmt.Sprintf("invalid network configuration: %v", conf.Network))
	}

}

func newEmptySandboxNetworkStack(clock tcpip.Clock, uniqueID stack.UniqueID) (inet.Stack, error) {
	netProtos := []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol, arp.NewProtocol}
	transProtos := []stack.TransportProtocolFactory{
		tcp.NewProtocol,
		udp.NewProtocol,
		icmp.NewProtocol4,
		icmp.NewProtocol6,
	}
	s := netstack.Stack{stack.New(stack.Options{
		NetworkProtocols:   netProtos,
		TransportProtocols: transProtos,
		Clock:              clock,
		Stats:              netstack.Metrics,
		HandleLocal:        true,
		// Enable raw sockets for users with sufficient
		// privileges.
		RawFactory: raw.EndpointFactory{},
		UniqueID:   uniqueID,
		IPTables:   netfilter.DefaultLinuxTables(),
	})}

	// Enable SACK Recovery.
	{
		opt := tcpip.TCPSACKEnabled(true)
		if err := s.Stack.SetTransportProtocolOption(tcp.ProtocolNumber, &opt); err != nil {
			return nil, fmt.Errorf("SetTransportProtocolOption(%d, &%T(%t)): %s", tcp.ProtocolNumber, opt, opt, err)
		}
	}

	// Set default TTLs as required by socket/netstack.
	{
		opt := tcpip.DefaultTTLOption(netstack.DefaultTTL)
		if err := s.Stack.SetNetworkProtocolOption(ipv4.ProtocolNumber, &opt); err != nil {
			return nil, fmt.Errorf("SetNetworkProtocolOption(%d, &%T(%d)): %s", ipv4.ProtocolNumber, opt, opt, err)
		}
		if err := s.Stack.SetNetworkProtocolOption(ipv6.ProtocolNumber, &opt); err != nil {
			return nil, fmt.Errorf("SetNetworkProtocolOption(%d, &%T(%d)): %s", ipv6.ProtocolNumber, opt, opt, err)
		}
	}

	// Enable Receive Buffer Auto-Tuning.
	{
		opt := tcpip.TCPModerateReceiveBufferOption(true)
		if err := s.Stack.SetTransportProtocolOption(tcp.ProtocolNumber, &opt); err != nil {
			return nil, fmt.Errorf("SetTransportProtocolOption(%d, &%T(%t)): %s", tcp.ProtocolNumber, opt, opt, err)
		}
	}

	return &s, nil
}

// sandboxNetstackCreator implements kernel.NetworkStackCreator.
//
// +stateify savable
type sandboxNetstackCreator struct {
	clock    tcpip.Clock
	uniqueID stack.UniqueID
}

// CreateStack implements kernel.NetworkStackCreator.CreateStack.
func (f *sandboxNetstackCreator) CreateStack() (inet.Stack, error) {
	s, err := newEmptySandboxNetworkStack(f.clock, f.uniqueID)
	if err != nil {
		return nil, err
	}

	// Setup loopback.
	n := &Network{Stack: s.(*netstack.Stack).Stack}
	nicID := tcpip.NICID(f.uniqueID.UniqueID())
	link := DefaultLoopbackLink
	linkEP := loopback.New()
	if err := n.createNICWithAddrs(nicID, link.Name, linkEP, link.Addresses); err != nil {
		return nil, err
	}

	return s, nil
}

// signal sends a signal to one or more processes in a container. If PID is 0,
// then the container init process is used. Depending on the SignalDeliveryMode
// option, the signal may be sent directly to the indicated process, to all
// processes in the container, or to the foreground process group.
func (l *Loader) signal(cid string, pid, signo int32, mode SignalDeliveryMode) error {
	if pid < 0 {
		return fmt.Errorf("PID (%d) must be positive", pid)
	}

	switch mode {
	case DeliverToProcess:
		if err := l.signalProcess(cid, kernel.ThreadID(pid), signo); err != nil {
			return fmt.Errorf("signaling process in container %q PID %d: %v", cid, pid, err)
		}
		return nil

	case DeliverToForegroundProcessGroup:
		if err := l.signalForegrondProcessGroup(cid, kernel.ThreadID(pid), signo); err != nil {
			return fmt.Errorf("signaling foreground process group in container %q PID %d: %v", cid, pid, err)
		}
		return nil

	case DeliverToAllProcesses:
		if pid != 0 {
			return fmt.Errorf("PID (%d) cannot be set when signaling all processes", pid)
		}
		// Check that the container has actually started before signaling it.
		if _, err := l.threadGroupFromID(execID{cid: cid}); err != nil {
			return err
		}
		if err := l.signalAllProcesses(cid, signo); err != nil {
			return fmt.Errorf("signaling all processes in container %q: %v", cid, err)
		}
		return nil

	default:
		panic(fmt.Sprintf("unknown signal delivery mode %v", mode))
	}
}

func (l *Loader) signalProcess(cid string, tgid kernel.ThreadID, signo int32) error {
	execTG, err := l.threadGroupFromID(execID{cid: cid, pid: tgid})
	if err == nil {
		// Send signal directly to the identified process.
		return l.k.SendExternalSignalThreadGroup(execTG, &arch.SignalInfo{Signo: signo})
	}

	// The caller may be signaling a process not started directly via exec.
	// In this case, find the process in the container's PID namespace and
	// signal it.
	initTG, err := l.threadGroupFromID(execID{cid: cid})
	if err != nil {
		return fmt.Errorf("no thread group found: %v", err)
	}
	tg := initTG.PIDNamespace().ThreadGroupWithID(tgid)
	if tg == nil {
		return fmt.Errorf("no such process with PID %d", tgid)
	}
	if tg.Leader().ContainerID() != cid {
		return fmt.Errorf("process %d is part of a different container: %q", tgid, tg.Leader().ContainerID())
	}
	return l.k.SendExternalSignalThreadGroup(tg, &arch.SignalInfo{Signo: signo})
}

// signalForegrondProcessGroup looks up foreground process group from the TTY
// for the given "tgid" inside container "cid", and send the signal to it.
func (l *Loader) signalForegrondProcessGroup(cid string, tgid kernel.ThreadID, signo int32) error {
	l.mu.Lock()
	tg, err := l.tryThreadGroupFromIDLocked(execID{cid: cid, pid: tgid})
	if err != nil {
		l.mu.Unlock()
		return fmt.Errorf("no thread group found: %v", err)
	}
	if tg == nil {
		l.mu.Unlock()
		return fmt.Errorf("container %q not started", cid)
	}

	tty, ttyVFS2, err := l.ttyFromIDLocked(execID{cid: cid, pid: tgid})
	l.mu.Unlock()
	if err != nil {
		return fmt.Errorf("no thread group found: %v", err)
	}

	var pg *kernel.ProcessGroup
	switch {
	case ttyVFS2 != nil:
		pg = ttyVFS2.ForegroundProcessGroup()
	case tty != nil:
		pg = tty.ForegroundProcessGroup()
	default:
		return fmt.Errorf("no TTY attached")
	}
	if pg == nil {
		// No foreground process group has been set. Signal the
		// original thread group.
		log.Warningf("No foreground process group for container %q and PID %d. Sending signal directly to PID %d.", cid, tgid, tgid)
		return l.k.SendExternalSignalThreadGroup(tg, &arch.SignalInfo{Signo: signo})
	}
	// Send the signal to all processes in the process group.
	var lastErr error
	for _, tg := range l.k.TaskSet().Root.ThreadGroups() {
		if tg.ProcessGroup() != pg {
			continue
		}
		if err := l.k.SendExternalSignalThreadGroup(tg, &arch.SignalInfo{Signo: signo}); err != nil {
			lastErr = err
		}
	}
	return lastErr
}

// signalAllProcesses that belong to specified container. It's a noop if the
// container hasn't started or has exited.
func (l *Loader) signalAllProcesses(cid string, signo int32) error {
	// Pause the kernel to prevent new processes from being created while
	// the signal is delivered. This prevents process leaks when SIGKILL is
	// sent to the entire container.
	l.k.Pause()
	defer l.k.Unpause()
	return l.k.SendContainerSignal(cid, &arch.SignalInfo{Signo: signo})
}

// threadGroupFromID is similar to tryThreadGroupFromIDLocked except that it
// acquires mutex before calling it and fails in case container hasn't started
// yet.
func (l *Loader) threadGroupFromID(key execID) (*kernel.ThreadGroup, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	tg, err := l.tryThreadGroupFromIDLocked(key)
	if err != nil {
		return nil, err
	}
	if tg == nil {
		return nil, fmt.Errorf("container %q not started", key.cid)
	}
	return tg, nil
}

// tryThreadGroupFromIDLocked returns the thread group for the given execution
// ID. It may return nil in case the container has not started yet. Returns
// error if execution ID is invalid or if the container cannot be found (maybe
// it has been deleted). Caller must hold 'mu'.
func (l *Loader) tryThreadGroupFromIDLocked(key execID) (*kernel.ThreadGroup, error) {
	ep := l.processes[key]
	if ep == nil {
		return nil, fmt.Errorf("container %q not found", key.cid)
	}
	return ep.tg, nil
}

// ttyFromIDLocked returns the TTY files for the given execution ID. It may
// return nil in case the container has not started yet. Returns error if
// execution ID is invalid or if the container cannot be found (maybe it has
// been deleted). Caller must hold 'mu'.
func (l *Loader) ttyFromIDLocked(key execID) (*host.TTYFileOperations, *hostvfs2.TTYFileDescription, error) {
	ep := l.processes[key]
	if ep == nil {
		return nil, nil, fmt.Errorf("container %q not found", key.cid)
	}
	return ep.tty, ep.ttyVFS2, nil
}

func createFDTable(ctx context.Context, console bool, stdioFDs []*fd.FD) (*kernel.FDTable, *host.TTYFileOperations, *hostvfs2.TTYFileDescription, error) {
	if len(stdioFDs) != 3 {
		return nil, nil, nil, fmt.Errorf("stdioFDs should contain exactly 3 FDs (stdin, stdout, and stderr), but %d FDs received", len(stdioFDs))
	}

	k := kernel.KernelFromContext(ctx)
	fdTable := k.NewFDTable()
	ttyFile, ttyFileVFS2, err := fdimport.Import(ctx, fdTable, console, stdioFDs)
	if err != nil {
		fdTable.DecRef(ctx)
		return nil, nil, nil, err
	}
	return fdTable, ttyFile, ttyFileVFS2, nil
}

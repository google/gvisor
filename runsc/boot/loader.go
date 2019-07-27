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
	"fmt"
	mrand "math/rand"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	gtime "time"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/cpuid"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/memutil"
	"gvisor.dev/gvisor/pkg/rand"
	"gvisor.dev/gvisor/pkg/refs"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/control"
	"gvisor.dev/gvisor/pkg/sentry/fs"
	"gvisor.dev/gvisor/pkg/sentry/fs/host"
	"gvisor.dev/gvisor/pkg/sentry/inet"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/loader"
	"gvisor.dev/gvisor/pkg/sentry/pgalloc"
	"gvisor.dev/gvisor/pkg/sentry/platform"
	"gvisor.dev/gvisor/pkg/sentry/sighandling"
	slinux "gvisor.dev/gvisor/pkg/sentry/syscalls/linux"
	"gvisor.dev/gvisor/pkg/sentry/time"
	"gvisor.dev/gvisor/pkg/sentry/usage"
	"gvisor.dev/gvisor/pkg/sentry/watchdog"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/link/sniffer"
	"gvisor.dev/gvisor/pkg/tcpip/network/arp"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/runsc/boot/filter"
	_ "gvisor.dev/gvisor/runsc/boot/platforms" // register all platforms.
	"gvisor.dev/gvisor/runsc/specutils"

	// Include supported socket providers.
	"gvisor.dev/gvisor/pkg/sentry/socket/epsocket"
	"gvisor.dev/gvisor/pkg/sentry/socket/hostinet"
	_ "gvisor.dev/gvisor/pkg/sentry/socket/netlink"
	_ "gvisor.dev/gvisor/pkg/sentry/socket/netlink/route"
	_ "gvisor.dev/gvisor/pkg/sentry/socket/unix"
)

// Loader keeps state needed to start the kernel and run the container..
type Loader struct {
	// k is the kernel.
	k *kernel.Kernel

	// ctrl is the control server.
	ctrl *controller

	conf *Config

	// console is set to true if terminal is enabled.
	console bool

	watchdog *watchdog.Watchdog

	// stdioFDs contains stdin, stdout, and stderr.
	stdioFDs []int

	// goferFDs are the FDs that attach the sandbox to the gofers.
	goferFDs []int

	// spec is the base configuration for the root container.
	spec *specs.Spec

	// startSignalForwarding enables forwarding of signals to the sandboxed
	// container. It should be called after the init process is loaded.
	startSignalForwarding func() func()

	// stopSignalForwarding disables forwarding of signals to the sandboxed
	// container. It should be called when a sandbox is destroyed.
	stopSignalForwarding func()

	// restore is set to true if we are restoring a container.
	restore bool

	// rootProcArgs refers to the root sandbox init task.
	rootProcArgs kernel.CreateProcessArgs

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

	// pidnsPath is the pid namespace path in spec
	pidnsPath string
}

func init() {
	// Initialize the random number generator.
	mrand.Seed(gtime.Now().UnixNano())

	// Register the global syscall table.
	kernel.RegisterSyscallTable(slinux.AMD64)
}

// Args are the arguments for New().
type Args struct {
	// Id is the sandbox ID.
	ID string
	// Spec is the sandbox specification.
	Spec *specs.Spec
	// Conf is the system configuration.
	Conf *Config
	// ControllerFD is the FD to the URPC controller.
	ControllerFD int
	// Device is an optional argument that is passed to the platform.
	Device *os.File
	// GoferFDs is an array of FDs used to connect with the Gofer.
	GoferFDs []int
	// StdioFDs is the stdio for the application.
	StdioFDs []int
	// Console is set to true if using TTY.
	Console bool
	// NumCPU is the number of CPUs to create inside the sandbox.
	NumCPU int
	// TotalMem is the initial amount of total memory to report back to the
	// container.
	TotalMem uint64
	// UserLogFD is the file descriptor to write user logs to.
	UserLogFD int
}

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

	// Initialize watchdog.
	watchdog.AdvanceWatchdog(args.Conf.AdvanceWatchdog)

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
	//
	// FIXME(b/109889800): Use non-nil context.
	vdso, err := loader.PrepareVDSO(nil, k)
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

	// Create an empty network stack because the network namespace may be empty at
	// this point. Netns is configured before Run() is called. Netstack is
	// configured using a control uRPC message. Host network is configured inside
	// Run().
	networkStack, err := newEmptyNetworkStack(args.Conf, k)
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

	if args.TotalMem > 0 {
		// Adjust the total memory returned by the Sentry so that applications that
		// use /proc/meminfo can make allocations based on this limit.
		usage.MinimumTotalMemoryBytes = args.TotalMem
		log.Infof("Setting total memory to %.2f GB", float64(args.TotalMem)/(1<<30))
	}

	// Initiate the Kernel object, which is required by the Context passed
	// to createVFS in order to mount (among other things) procfs.
	if err = k.Init(kernel.InitKernelArgs{
		FeatureSet:                  cpuid.HostFeatureSet(),
		Timekeeper:                  tk,
		RootUserNamespace:           creds.UserNamespace,
		NetworkStack:                networkStack,
		ApplicationCores:            uint(args.NumCPU),
		Vdso:                        vdso,
		RootUTSNamespace:            kernel.NewUTSNamespace(args.Spec.Hostname, args.Spec.Hostname, creds.UserNamespace),
		RootIPCNamespace:            kernel.NewIPCNamespace(creds.UserNamespace),
		RootAbstractSocketNamespace: kernel.NewAbstractSocketNamespace(),
		PIDNamespace:                kernel.NewRootPIDNamespace(creds.UserNamespace),
	}); err != nil {
		return nil, fmt.Errorf("initializing kernel: %v", err)
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
	dog := watchdog.New(k, watchdog.DefaultTimeout, args.Conf.WatchdogAction)

	procArgs, err := newProcess(args.ID, args.Spec, creds, k, k.RootPIDNamespace())
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

	eid := execID{cid: args.ID}
	l := &Loader{
		k:            k,
		conf:         args.Conf,
		console:      args.Console,
		watchdog:     dog,
		spec:         args.Spec,
		goferFDs:     args.GoferFDs,
		stdioFDs:     args.StdioFDs,
		rootProcArgs: procArgs,
		sandboxID:    args.ID,
		processes:    map[execID]*execProcess{eid: {}},
		mountHints:   mountHints,
	}

	// We don't care about child signals; some platforms can generate a
	// tremendous number of useless ones (I'm looking at you, ptrace).
	if err := sighandling.IgnoreChildStop(); err != nil {
		return nil, fmt.Errorf("ignore child stop signals failed: %v", err)
	}

	// Handle signals by forwarding them to the root container process
	// (except for panic signal, which should cause a panic).
	l.startSignalForwarding = sighandling.PrepareHandler(func(sig linux.Signal) {
		// Panic signal should cause a panic.
		if args.Conf.PanicSignal != -1 && sig == linux.Signal(args.Conf.PanicSignal) {
			panic("Signal-induced panic")
		}

		// Otherwise forward to root container.
		deliveryMode := DeliverToProcess
		if args.Console {
			// Since we are running with a console, we should
			// forward the signal to the foreground process group
			// so that job control signals like ^C can be handled
			// properly.
			deliveryMode = DeliverToForegroundProcessGroup
		}
		log.Infof("Received external signal %d, mode: %v", sig, deliveryMode)
		if err := l.signal(args.ID, 0, int32(sig), deliveryMode); err != nil {
			log.Warningf("error sending signal %v to container %q: %v", sig, args.ID, err)
		}
	})

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

// newProcess creates a process that can be run with kernel.CreateProcess.
func newProcess(id string, spec *specs.Spec, creds *auth.Credentials, k *kernel.Kernel, pidns *kernel.PIDNamespace) (kernel.CreateProcessArgs, error) {
	// Create initial limits.
	ls, err := createLimitSet(spec)
	if err != nil {
		return kernel.CreateProcessArgs{}, fmt.Errorf("creating limits: %v", err)
	}

	// Create the process arguments.
	procArgs := kernel.CreateProcessArgs{
		Argv:                    spec.Process.Args,
		Envv:                    spec.Process.Env,
		WorkingDirectory:        spec.Process.Cwd, // Defaults to '/' if empty.
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
}

func createPlatform(conf *Config, deviceFile *os.File) (platform.Platform, error) {
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

func (l *Loader) installSeccompFilters() error {
	if l.conf.DisableSeccomp {
		filter.Report("syscall filter is DISABLED. Running in less secure mode.")
	} else {
		opts := filter.Options{
			Platform:      l.k.Platform,
			HostNetwork:   l.conf.Network == NetworkHost,
			ProfileEnable: l.conf.ProfileEnable,
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
	if l.conf.Network == NetworkHost {
		// Delay host network configuration to this point because network namespace
		// is configured after the loader is created and before Run() is called.
		log.Debugf("Configuring host network")
		stack := l.k.NetworkStack().(*hostinet.Stack)
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
		if l.conf.ProfileEnable {
			initializePProf()
		}

		// Finally done with all configuration. Setup filters before user code
		// is loaded.
		if err := l.installSeccompFilters(); err != nil {
			return err
		}

		// Create the FD map, which will set stdin, stdout, and stderr.  If console
		// is true, then ioctl calls will be passed through to the host fd.
		ctx := l.rootProcArgs.NewContext(l.k)
		fdTable, err := createFDTable(ctx, l.console, l.stdioFDs)
		if err != nil {
			return fmt.Errorf("importing fds: %v", err)
		}
		// CreateProcess takes a reference on FDMap if successful. We won't need
		// ours either way.
		l.rootProcArgs.FDTable = fdTable

		// Setup the root container file system.
		l.startGoferMonitor(l.sandboxID, l.goferFDs)
		mntr := newContainerMounter(l.spec, l.goferFDs, l.k, l.mountHints)
		if err := mntr.setupRootContainer(ctx, ctx, l.conf, func(mns *fs.MountNamespace) {
			l.rootProcArgs.MountNamespace = mns
		}); err != nil {
			return err
		}

		if err := setExecutablePath(ctx, &l.rootProcArgs); err != nil {
			return err
		}

		// Read /etc/passwd for the user's HOME directory and set the HOME
		// environment variable as required by POSIX if it is not overridden by
		// the user.
		hasHomeEnvv := false
		for _, envv := range l.rootProcArgs.Envv {
			if strings.HasPrefix(envv, "HOME=") {
				hasHomeEnvv = true
			}
		}
		if !hasHomeEnvv {
			homeDir, err := getExecUserHome(ctx, l.rootProcArgs.MountNamespace, uint32(l.rootProcArgs.Credentials.RealKUID))
			if err != nil {
				return fmt.Errorf("error reading exec user: %v", err)
			}

			l.rootProcArgs.Envv = append(l.rootProcArgs.Envv, "HOME="+homeDir)
		}

		// Create the root container init task. It will begin running
		// when the kernel is started.
		if _, _, err := l.k.CreateProcess(l.rootProcArgs); err != nil {
			return fmt.Errorf("creating init process: %v", err)
		}

		// CreateProcess takes a reference on FDTable if successful.
		l.rootProcArgs.FDTable.DecRef()
	}

	ep.tg = l.k.GlobalInit()
	if ns, ok := specutils.GetNS(specs.PIDNamespace, l.spec); ok {
		ep.pidnsPath = ns.Path
	}
	if l.console {
		ttyFile, _ := l.rootProcArgs.FDTable.Get(0)
		defer ttyFile.DecRef()
		ep.tty = ttyFile.FileOperations.(*host.TTYFileOperations)

		// Set the foreground process group on the TTY to the global
		// init process group, since that is what we are about to
		// start running.
		ep.tty.InitForegroundProcessGroup(ep.tg.ProcessGroup())
	}

	// Start signal forwarding only after an init process is created.
	l.stopSignalForwarding = l.startSignalForwarding()

	log.Infof("Process should have started...")
	l.watchdog.Start()
	return l.k.Start()
}

// createContainer creates a new container inside the sandbox.
func (l *Loader) createContainer(cid string) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	eid := execID{cid: cid}
	if _, ok := l.processes[eid]; ok {
		return fmt.Errorf("container %q already exists", cid)
	}
	l.processes[eid] = &execProcess{}
	return nil
}

// startContainer starts a child container. It returns the thread group ID of
// the newly created process. Caller owns 'files' and may close them after
// this method returns.
func (l *Loader) startContainer(spec *specs.Spec, conf *Config, cid string, files []*os.File) error {
	// Create capabilities.
	caps, err := specutils.Capabilities(conf.EnableRaw, spec.Process.Capabilities)
	if err != nil {
		return fmt.Errorf("creating capabilities: %v", err)
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	eid := execID{cid: cid}
	if _, ok := l.processes[eid]; !ok {
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
		l.processes[eid].pidnsPath = ns.Path
	} else {
		pidns = l.k.RootPIDNamespace()
	}
	procArgs, err := newProcess(cid, spec, creds, l.k, pidns)
	if err != nil {
		return fmt.Errorf("creating new process: %v", err)
	}

	// setupContainerFS() dups stdioFDs, so we don't need to dup them here.
	var stdioFDs []int
	for _, f := range files[:3] {
		stdioFDs = append(stdioFDs, int(f.Fd()))
	}

	// Create the FD map, which will set stdin, stdout, and stderr.
	ctx := procArgs.NewContext(l.k)
	fdTable, err := createFDTable(ctx, false, stdioFDs)
	if err != nil {
		return fmt.Errorf("importing fds: %v", err)
	}
	// CreateProcess takes a reference on fdTable if successful. We won't
	// need ours either way.
	procArgs.FDTable = fdTable

	// Can't take ownership away from os.File. dup them to get a new FDs.
	var goferFDs []int
	for _, f := range files[3:] {
		fd, err := syscall.Dup(int(f.Fd()))
		if err != nil {
			return fmt.Errorf("failed to dup file: %v", err)
		}
		goferFDs = append(goferFDs, fd)
	}

	// Setup the child container file system.
	l.startGoferMonitor(cid, goferFDs)
	mntr := newContainerMounter(spec, goferFDs, l.k, l.mountHints)
	if err := mntr.setupChildContainer(conf, &procArgs); err != nil {
		return fmt.Errorf("configuring container FS: %v", err)
	}

	if err := setExecutablePath(ctx, &procArgs); err != nil {
		return fmt.Errorf("setting executable path for %+v: %v", procArgs, err)
	}

	// Create and start the new process.
	tg, _, err := l.k.CreateProcess(procArgs)
	if err != nil {
		return fmt.Errorf("creating process: %v", err)
	}
	l.k.StartProcess(tg)

	// CreateProcess takes a reference on FDTable if successful.
	procArgs.FDTable.DecRef()

	l.processes[eid].tg = tg
	return nil
}

// startGoferMonitor runs a goroutine to monitor gofer's health. It polls on
// the gofer FDs looking for disconnects, and destroys the container if a
// disconnect occurs in any of the gofer FDs.
func (l *Loader) startGoferMonitor(cid string, goferFDs []int) {
	go func() {
		log.Debugf("Monitoring gofer health for container %q", cid)
		var events []unix.PollFd
		for _, fd := range goferFDs {
			events = append(events, unix.PollFd{
				Fd:     int32(fd),
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

		// Check if the gofer has stopped as part of normal container destruction.
		// This is done just to avoid sending an annoying error message to the log.
		// Note that there is a small race window in between mu.Unlock() and the
		// lock being reacquired in destroyContainer(), but it's harmless to call
		// destroyContainer() multiple times.
		l.mu.Lock()
		_, ok := l.processes[execID{cid: cid}]
		l.mu.Unlock()
		if ok {
			log.Infof("Gofer socket disconnected, destroying container %q", cid)
			if err := l.destroyContainer(cid); err != nil {
				log.Warningf("Error destroying container %q after gofer stopped: %v", cid, err)
			}
		}
	}()
}

// destroyContainer stops a container if it is still running and cleans up its
// filesystem.
func (l *Loader) destroyContainer(cid string) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	_, _, started, err := l.threadGroupFromIDLocked(execID{cid: cid})
	if err != nil {
		// Container doesn't exist.
		return err
	}

	// The container exists, has it been started?
	if started {
		if err := l.signalAllProcesses(cid, int32(linux.SIGKILL)); err != nil {
			return fmt.Errorf("sending SIGKILL to all container processes: %v", err)
		}
	}

	// Remove all container thread groups from the map.
	for key := range l.processes {
		if key.cid == cid {
			delete(l.processes, key)
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

	log.Debugf("Container destroyed %q", cid)
	return nil
}

func (l *Loader) executeAsync(args *control.ExecArgs) (kernel.ThreadID, error) {
	// Hold the lock for the entire operation to ensure that exec'd process is
	// added to 'processes' in case it races with destroyContainer().
	l.mu.Lock()
	defer l.mu.Unlock()

	tg, _, started, err := l.threadGroupFromIDLocked(execID{cid: args.ContainerID})
	if err != nil {
		return 0, err
	}
	if !started {
		return 0, fmt.Errorf("container %q not started", args.ContainerID)
	}

	// Get the container MountNamespace from the Task.
	tg.Leader().WithMuLocked(func(t *kernel.Task) {
		// task.MountNamespace() does not take a ref, so we must do so
		// ourselves.
		args.MountNamespace = t.MountNamespace()
		args.MountNamespace.IncRef()
	})
	defer args.MountNamespace.DecRef()

	// Start the process.
	proc := control.Proc{Kernel: l.k}
	args.PIDNamespace = tg.PIDNamespace()
	newTG, tgid, ttyFile, err := control.ExecAsync(&proc, args)
	if err != nil {
		return 0, err
	}

	eid := execID{cid: args.ContainerID, pid: tgid}
	l.processes[eid] = &execProcess{
		tg:  newTG,
		tty: ttyFile,
	}
	log.Debugf("updated processes: %v", l.processes)

	return tgid, nil
}

// waitContainer waits for the init process of a container to exit.
func (l *Loader) waitContainer(cid string, waitStatus *uint32) error {
	// Don't defer unlock, as doing so would make it impossible for
	// multiple clients to wait on the same container.
	tg, _, err := l.threadGroupFromID(execID{cid: cid})
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
	execTG, _, err := l.threadGroupFromID(eid)
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
	initTG, _, err := l.threadGroupFromID(execID{cid: cid})
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

	return l.k.GlobalInit().ExitStatus()
}

func newEmptyNetworkStack(conf *Config, clock tcpip.Clock) (inet.Stack, error) {
	switch conf.Network {
	case NetworkHost:
		return hostinet.NewStack(), nil

	case NetworkNone, NetworkSandbox:
		// NetworkNone sets up loopback using netstack.
		netProtos := []string{ipv4.ProtocolName, ipv6.ProtocolName, arp.ProtocolName}
		protoNames := []string{tcp.ProtocolName, udp.ProtocolName, icmp.ProtocolName4}
		s := epsocket.Stack{stack.New(netProtos, protoNames, stack.Options{
			Clock:       clock,
			Stats:       epsocket.Metrics,
			HandleLocal: true,
			// Enable raw sockets for users with sufficient
			// privileges.
			Raw: true,
		})}

		// Enable SACK Recovery.
		if err := s.Stack.SetTransportProtocolOption(tcp.ProtocolNumber, tcp.SACKEnabled(true)); err != nil {
			return nil, fmt.Errorf("failed to enable SACK: %v", err)
		}

		// Enable Receive Buffer Auto-Tuning.
		if err := s.Stack.SetTransportProtocolOption(tcp.ProtocolNumber, tcpip.ModerateReceiveBufferOption(true)); err != nil {
			return nil, fmt.Errorf("SetTransportProtocolOption failed: %v", err)
		}

		s.FillDefaultIPTables()

		return &s, nil

	default:
		panic(fmt.Sprintf("invalid network configuration: %v", conf.Network))
	}
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
		_, _, err := l.threadGroupFromID(execID{cid: cid})
		if err != nil {
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
	execTG, _, err := l.threadGroupFromID(execID{cid: cid, pid: tgid})
	if err == nil {
		// Send signal directly to the identified process.
		return execTG.SendSignal(&arch.SignalInfo{Signo: signo})
	}

	// The caller may be signaling a process not started directly via exec.
	// In this case, find the process in the container's PID namespace and
	// signal it.
	initTG, _, err := l.threadGroupFromID(execID{cid: cid})
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
	return tg.SendSignal(&arch.SignalInfo{Signo: signo})
}

func (l *Loader) signalForegrondProcessGroup(cid string, tgid kernel.ThreadID, signo int32) error {
	// Lookup foreground process group from the TTY for the given process,
	// and send the signal to it.
	tg, tty, err := l.threadGroupFromID(execID{cid: cid, pid: tgid})
	if err != nil {
		return fmt.Errorf("no thread group found: %v", err)
	}
	if tty == nil {
		return fmt.Errorf("no TTY attached")
	}
	pg := tty.ForegroundProcessGroup()
	if pg == nil {
		// No foreground process group has been set. Signal the
		// original thread group.
		log.Warningf("No foreground process group for container %q and PID %d. Sending signal directly to PID %d.", cid, tgid, tgid)
		return tg.SendSignal(&arch.SignalInfo{Signo: signo})
	}
	// Send the signal to all processes in the process group.
	var lastErr error
	for _, tg := range l.k.TaskSet().Root.ThreadGroups() {
		if tg.ProcessGroup() != pg {
			continue
		}
		if err := tg.SendSignal(&arch.SignalInfo{Signo: signo}); err != nil {
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
	if err := l.k.SendContainerSignal(cid, &arch.SignalInfo{Signo: signo}); err != nil {
		l.k.Unpause()
		return err
	}
	l.k.Unpause()

	// If SIGKILLing all processes, wait for them to exit.
	if linux.Signal(signo) == linux.SIGKILL {
		for _, t := range l.k.TaskSet().Root.Tasks() {
			if t.ContainerID() == cid {
				t.ThreadGroup().WaitExited()
			}
		}
	}
	return nil
}

// threadGroupFromID same as threadGroupFromIDLocked except that it acquires
// mutex before calling it.
func (l *Loader) threadGroupFromID(key execID) (*kernel.ThreadGroup, *host.TTYFileOperations, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	tg, tty, ok, err := l.threadGroupFromIDLocked(key)
	if err != nil {
		return nil, nil, err
	}
	if !ok {
		return nil, nil, fmt.Errorf("container %q not started", key.cid)
	}
	return tg, tty, nil
}

// threadGroupFromIDLocked returns the thread group and TTY for the given
// execution ID. TTY may be nil if the process is not attached to a terminal.
// Also returns a boolean indicating whether the container has already started.
// Returns error if execution ID is invalid or if the container cannot be
// found (maybe it has been deleted). Caller must hold 'mu'.
func (l *Loader) threadGroupFromIDLocked(key execID) (*kernel.ThreadGroup, *host.TTYFileOperations, bool, error) {
	ep := l.processes[key]
	if ep == nil {
		return nil, nil, false, fmt.Errorf("container %q not found", key.cid)
	}
	if ep.tg == nil {
		return nil, nil, false, nil
	}
	return ep.tg, ep.tty, true, nil
}

func init() {
	// TODO(gvisor.dev/issue/365): Make this configurable.
	refs.SetLeakMode(refs.NoLeakChecking)
}

// Copyright 2018 Google Inc.
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
	"math/rand"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	gtime "time"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"gvisor.googlesource.com/gvisor/pkg/abi/linux"
	"gvisor.googlesource.com/gvisor/pkg/cpuid"
	"gvisor.googlesource.com/gvisor/pkg/log"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs"
	"gvisor.googlesource.com/gvisor/pkg/sentry/inet"
	"gvisor.googlesource.com/gvisor/pkg/sentry/kernel"
	"gvisor.googlesource.com/gvisor/pkg/sentry/kernel/auth"
	"gvisor.googlesource.com/gvisor/pkg/sentry/loader"
	"gvisor.googlesource.com/gvisor/pkg/sentry/platform"
	"gvisor.googlesource.com/gvisor/pkg/sentry/platform/kvm"
	"gvisor.googlesource.com/gvisor/pkg/sentry/platform/ptrace"
	"gvisor.googlesource.com/gvisor/pkg/sentry/sighandling"
	"gvisor.googlesource.com/gvisor/pkg/sentry/state"
	slinux "gvisor.googlesource.com/gvisor/pkg/sentry/syscalls/linux"
	"gvisor.googlesource.com/gvisor/pkg/sentry/time"
	"gvisor.googlesource.com/gvisor/pkg/sentry/watchdog"
	"gvisor.googlesource.com/gvisor/pkg/tcpip"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/link/sniffer"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/network/arp"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/stack"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/transport/ping"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/transport/udp"
	"gvisor.googlesource.com/gvisor/runsc/boot/filter"
	"gvisor.googlesource.com/gvisor/runsc/specutils"

	// Include supported socket providers.
	"gvisor.googlesource.com/gvisor/pkg/sentry/socket/epsocket"
	"gvisor.googlesource.com/gvisor/pkg/sentry/socket/hostinet"
	_ "gvisor.googlesource.com/gvisor/pkg/sentry/socket/netlink"
	_ "gvisor.googlesource.com/gvisor/pkg/sentry/socket/netlink/route"
	_ "gvisor.googlesource.com/gvisor/pkg/sentry/socket/unix"
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

	// stopSignalForwarding disables forwarding of signals to the sandboxed
	// container. It should be called when a sandbox is destroyed.
	stopSignalForwarding func()

	// restore is set to true if we are restoring a container.
	restore bool

	// rootProcArgs refers to the root sandbox init task.
	rootProcArgs kernel.CreateProcessArgs

	// sandboxID is the ID for the whole sandbox.
	sandboxID string

	// mu guards containerRootTGIDs.
	mu sync.Mutex

	// containerRootTGIDs maps container IDs to their root processes. It
	// can be used to determine which process to manipulate when clients
	// call methods on particular containers.
	//
	// containerRootTGIDs is guarded by mu.
	containerRootTGIDs map[string]kernel.ThreadID
}

func init() {
	// Initialize the random number generator.
	rand.Seed(gtime.Now().UnixNano())

	// Register the global syscall table.
	kernel.RegisterSyscallTable(slinux.AMD64)
}

// New initializes a new kernel loader configured by spec.
// New also handles setting up a kernel for restoring a container.
func New(spec *specs.Spec, conf *Config, controllerFD, restoreFD int, ioFDs []int, console bool) (*Loader, error) {
	var (
		tk          *kernel.Timekeeper
		creds       *auth.Credentials
		vdso        *loader.VDSO
		utsns       *kernel.UTSNamespace
		ipcns       *kernel.IPCNamespace
		restoreFile *os.File
		procArgs    kernel.CreateProcessArgs
	)
	// Create kernel and platform.
	p, err := createPlatform(conf)
	if err != nil {
		return nil, fmt.Errorf("error creating platform: %v", err)
	}
	k := &kernel.Kernel{
		Platform: p,
	}

	if restoreFD == -1 {
		// Create VDSO.
		//
		// Pass k as the platform since it is savable, unlike the actual platform.
		vdso, err = loader.PrepareVDSO(k)
		if err != nil {
			return nil, fmt.Errorf("error creating vdso: %v", err)
		}

		// Create timekeeper.
		tk, err = kernel.NewTimekeeper(k, vdso.ParamPage.FileRange())
		if err != nil {
			return nil, fmt.Errorf("error creating timekeeper: %v", err)
		}
		tk.SetClocks(time.NewCalibratedClocks())

		// Create capabilities.
		caps, err := specutils.Capabilities(spec.Process.Capabilities)
		if err != nil {
			return nil, fmt.Errorf("error creating capabilities: %v", err)
		}

		// Convert the spec's additional GIDs to KGIDs.
		extraKGIDs := make([]auth.KGID, 0, len(spec.Process.User.AdditionalGids))
		for _, GID := range spec.Process.User.AdditionalGids {
			extraKGIDs = append(extraKGIDs, auth.KGID(GID))
		}

		// Create credentials.
		creds = auth.NewUserCredentials(
			auth.KUID(spec.Process.User.UID),
			auth.KGID(spec.Process.User.GID),
			extraKGIDs,
			caps,
			auth.NewRootUserNamespace())

		// Create user namespace.
		// TODO: Not clear what domain name should be here.  It is
		// not configurable from runtime spec.
		utsns = kernel.NewUTSNamespace(spec.Hostname, "", creds.UserNamespace)

		ipcns = kernel.NewIPCNamespace(creds.UserNamespace)
	} else {
		// Create and set RestoreEnvironment
		fds := &fdDispenser{fds: ioFDs}
		renv, err := createRestoreEnvironment(spec, conf, fds)
		if err != nil {
			return nil, fmt.Errorf("error creating RestoreEnvironment: %v", err)
		}
		fs.SetRestoreEnvironment(*renv)

		restoreFile = os.NewFile(uintptr(restoreFD), "restore_file")
		defer restoreFile.Close()
	}

	if err := enableStrace(conf); err != nil {
		return nil, fmt.Errorf("failed to enable strace: %v", err)
	}

	// Create an empty network stack because the network namespace may be empty at
	// this point. Netns is configured before Run() is called. Netstack is
	// configured using a control uRPC message. Host network is configured inside
	// Run().
	networkStack := newEmptyNetworkStack(conf, k)

	if restoreFile == nil {
		// Initiate the Kernel object, which is required by the Context passed
		// to createVFS in order to mount (among other things) procfs.
		if err = k.Init(kernel.InitKernelArgs{
			FeatureSet:        cpuid.HostFeatureSet(),
			Timekeeper:        tk,
			RootUserNamespace: creds.UserNamespace,
			NetworkStack:      networkStack,
			// TODO: use number of logical processors from cgroups.
			ApplicationCores: uint(runtime.NumCPU()),
			Vdso:             vdso,
			RootUTSNamespace: utsns,
			RootIPCNamespace: ipcns,
		}); err != nil {
			return nil, fmt.Errorf("error initializing kernel: %v", err)
		}
	} else {
		// Load the state.
		loadOpts := state.LoadOpts{
			Source: restoreFile,
		}
		if err := loadOpts.Load(k, p, networkStack); err != nil {
			return nil, err
		}

		// Set timekeeper.
		k.Timekeeper().SetClocks(time.NewCalibratedClocks())
	}

	// Turn on packet logging if enabled.
	if conf.LogPackets {
		log.Infof("Packet logging enabled")
		atomic.StoreUint32(&sniffer.LogPackets, 1)
	} else {
		log.Infof("Packet logging disabled")
		atomic.StoreUint32(&sniffer.LogPackets, 0)
	}

	// Create a watchdog.
	watchdog := watchdog.New(k, watchdog.DefaultTimeout, conf.WatchdogAction)

	// Create the control server using the provided FD.
	//
	// This must be done *after* we have initialized the kernel since the
	// controller is used to configure the kernel's network stack.
	//
	// This should also be *before* we create the process, since a
	// misconfigured process will cause an error, and we want the control
	// server up before that so that we don't time out trying to connect to
	// it.
	ctrl, err := newController(controllerFD, k, watchdog)
	if err != nil {
		return nil, fmt.Errorf("error creating control server: %v", err)
	}

	// We don't care about child signals; some platforms can generate a
	// tremendous number of useless ones (I'm looking at you, ptrace).
	if err := sighandling.IgnoreChildStop(); err != nil {
		return nil, fmt.Errorf("failed to ignore child stop signals: %v", err)
	}
	// Ensure that signals received are forwarded to the emulated kernel.
	stopSignalForwarding := sighandling.PrepareForwarding(k, false)()

	if restoreFile == nil {
		procArgs, err = newProcess(spec, conf, ioFDs, console, creds, utsns, ipcns, k)
		if err != nil {
			return nil, fmt.Errorf("failed to create root process: %v", err)
		}
	}

	l := &Loader{
		k:                    k,
		ctrl:                 ctrl,
		conf:                 conf,
		console:              console,
		watchdog:             watchdog,
		stopSignalForwarding: stopSignalForwarding,
		rootProcArgs:         procArgs,
		restore:              restoreFile != nil,
	}
	ctrl.manager.l = l
	return l, nil
}

// newProcess creates a process that can be run with kernel.CreateProcess.
func newProcess(spec *specs.Spec, conf *Config, ioFDs []int, console bool, creds *auth.Credentials, utsns *kernel.UTSNamespace, ipcns *kernel.IPCNamespace, k *kernel.Kernel) (kernel.CreateProcessArgs, error) {
	// Create initial limits.
	ls, err := createLimitSet(spec)
	if err != nil {
		return kernel.CreateProcessArgs{}, fmt.Errorf("error creating limits: %v", err)
	}

	// Get the executable path, which is a bit tricky because we have to
	// inspect the environment PATH which is relative to the root path.
	exec, err := specutils.GetExecutablePath(spec.Process.Args[0], spec.Root.Path, spec.Process.Env)
	if err != nil {
		return kernel.CreateProcessArgs{}, fmt.Errorf("error getting executable path: %v", err)
	}

	// Create the process arguments.
	procArgs := kernel.CreateProcessArgs{
		Filename:             exec,
		Argv:                 spec.Process.Args,
		Envv:                 spec.Process.Env,
		WorkingDirectory:     spec.Process.Cwd, // Defaults to '/' if empty.
		Credentials:          creds,
		Umask:                0022,
		Limits:               ls,
		MaxSymlinkTraversals: linux.MaxSymlinkTraversals,
		UTSNamespace:         utsns,
		IPCNamespace:         ipcns,
	}
	ctx := procArgs.NewContext(k)

	// Create the FD map, which will set stdin, stdout, and stderr.  If
	// console is true, then ioctl calls will be passed through to the host
	// fd.
	fdm, err := createFDMap(ctx, k, ls, console)
	if err != nil {
		return kernel.CreateProcessArgs{}, fmt.Errorf("error importing fds: %v", err)
	}

	// CreateProcess takes a reference on FDMap if successful. We
	// won't need ours either way.
	procArgs.FDMap = fdm

	// If this is the root container, we also need to setup the root mount
	// namespace.
	if k.RootMountNamespace() == nil {
		// Use root user to configure mounts. The current user might not have
		// permission to do so.
		rootProcArgs := kernel.CreateProcessArgs{
			WorkingDirectory:     "/",
			Credentials:          auth.NewRootCredentials(creds.UserNamespace),
			Umask:                0022,
			MaxSymlinkTraversals: linux.MaxSymlinkTraversals,
		}
		rootCtx := rootProcArgs.NewContext(k)

		// Create the virtual filesystem.
		mns, err := createMountNamespace(ctx, rootCtx, spec, conf, ioFDs)
		if err != nil {
			return kernel.CreateProcessArgs{}, fmt.Errorf("error creating mounts: %v", err)
		}

		k.SetRootMountNamespace(mns)
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
	l.stopSignalForwarding()
	l.watchdog.Stop()
}

func createPlatform(conf *Config) (platform.Platform, error) {
	switch conf.Platform {
	case PlatformPtrace:
		log.Infof("Platform: ptrace")
		return ptrace.New()
	case PlatformKVM:
		log.Infof("Platform: kvm")
		return kvm.New()
	default:
		return nil, fmt.Errorf("invalid platform %v", conf.Platform)
	}
}

// Run runs the root container..
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

	// Finally done with all configuration. Setup filters before user code
	// is loaded.
	if l.conf.DisableSeccomp {
		filter.Report("syscall filter is DISABLED. Running in less secure mode.")
	} else {
		whitelistFS := l.conf.FileAccess == FileAccessDirect
		hostNet := l.conf.Network == NetworkHost
		if err := filter.Install(l.k.Platform, whitelistFS, l.console, hostNet); err != nil {
			return fmt.Errorf("Failed to install seccomp filters: %v", err)
		}
	}

	// If we are restoring, we do not want to create a process.
	if !l.restore {
		// Create the root container init task.
		if _, err := l.k.CreateProcess(l.rootProcArgs); err != nil {
			return fmt.Errorf("failed to create init process: %v", err)
		}

		// CreateProcess takes a reference on FDMap if successful.
		l.rootProcArgs.FDMap.DecRef()
	}

	l.watchdog.Start()
	return l.k.Start()
}

// startContainer starts a child container. It returns the thread group ID of
// the newly created process.
func (l *Loader) startContainer(args *StartArgs, k *kernel.Kernel) (kernel.ThreadID, error) {
	spec := args.Spec
	// Create capabilities.
	caps, err := specutils.Capabilities(spec.Process.Capabilities)
	if err != nil {
		return 0, fmt.Errorf("error creating capabilities: %v", err)
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
	// TODO: Create a new mount namespace for the container.
	creds := auth.NewUserCredentials(
		auth.KUID(spec.Process.User.UID),
		auth.KGID(spec.Process.User.GID),
		extraKGIDs,
		caps,
		l.k.RootUserNamespace())

	// TODO New containers should be started in new PID namespaces
	// when indicated by the spec.

	procArgs, err := newProcess(
		args.Spec,
		args.Conf,
		nil,   // ioFDs
		false, // console
		creds,
		k.RootUTSNamespace(),
		k.RootIPCNamespace(),
		k)
	if err != nil {
		return 0, fmt.Errorf("failed to create new process: %v", err)
	}

	tg, err := l.k.CreateProcess(procArgs)
	if err != nil {
		return 0, fmt.Errorf("failed to create process in sentry: %v", err)
	}

	ts := k.TaskSet()
	tgid := ts.Root.IDOfThreadGroup(tg)
	if tgid == 0 {
		return 0, errors.New("failed to get thread group ID of new process")
	}

	// CreateProcess takes a reference on FDMap if successful.
	procArgs.FDMap.DecRef()

	l.mu.Lock()
	defer l.mu.Unlock()
	l.containerRootTGIDs[args.CID] = tgid

	return tgid, nil
}

// TODO: Per-container namespaces must be supported
// for -pid.

// waitContainer waits for the root process of a container to exit.
func (l *Loader) waitContainer(cid string, waitStatus *uint32) error {
	// Don't defer unlock, as doing so would make it impossible for
	// multiple clients to wait on the same container.
	l.mu.Lock()
	tgid, ok := l.containerRootTGIDs[cid]
	l.mu.Unlock()
	if !ok {
		return fmt.Errorf("can't find process for container %q in %v", cid, l.containerRootTGIDs)
	}
	// If the thread either has already exited or exits during waiting,
	// consider the container exited.
	defer func() {
		l.mu.Lock()
		defer l.mu.Unlock()
		// TODO: Containers don't map 1:1 with their root
		// processes. Container exits should be managed explicitly
		// rather than via PID.
		delete(l.containerRootTGIDs, cid)
	}()
	return l.wait(tgid, cid, waitStatus)
}

func (l *Loader) waitPID(tgid kernel.ThreadID, cid string, waitStatus *uint32) error {
	// TODO: Containers all currently share a PID namespace.
	// When per-container PID namespaces are supported, wait should use cid
	// to find the appropriate PID namespace.
	if cid != l.sandboxID {
		return errors.New("non-sandbox PID namespaces are not yet implemented")
	}
	return l.wait(tgid, cid, waitStatus)
}

// wait waits for the process with TGID 'tgid' in a container's PID namespace
// to exit.
func (l *Loader) wait(tgid kernel.ThreadID, cid string, waitStatus *uint32) error {
	tg := l.k.TaskSet().Root.ThreadGroupWithID(kernel.ThreadID(tgid))
	if tg == nil {
		return fmt.Errorf("no thread group with ID %d", tgid)
	}
	tg.WaitExited()
	*waitStatus = tg.ExitStatus().Status()
	return nil
}

func (l *Loader) setRootContainerID(cid string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	// The root container has PID 1.
	l.containerRootTGIDs = map[string]kernel.ThreadID{cid: 1}
	l.sandboxID = cid
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

func newEmptyNetworkStack(conf *Config, clock tcpip.Clock) inet.Stack {
	switch conf.Network {
	case NetworkHost:
		return hostinet.NewStack()

	case NetworkNone, NetworkSandbox:
		// NetworkNone sets up loopback using netstack.
		netProtos := []string{ipv4.ProtocolName, ipv6.ProtocolName, arp.ProtocolName}
		protoNames := []string{tcp.ProtocolName, udp.ProtocolName, ping.ProtocolName4}
		return &epsocket.Stack{stack.New(clock, netProtos, protoNames)}

	default:
		panic(fmt.Sprintf("invalid network configuration: %v", conf.Network))
	}
}

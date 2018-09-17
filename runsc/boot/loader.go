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
	"fmt"
	"math/rand"
	"os"
	"os/signal"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	gtime "time"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"gvisor.googlesource.com/gvisor/pkg/abi/linux"
	"gvisor.googlesource.com/gvisor/pkg/cpuid"
	"gvisor.googlesource.com/gvisor/pkg/log"
	"gvisor.googlesource.com/gvisor/pkg/sentry/arch"
	"gvisor.googlesource.com/gvisor/pkg/sentry/inet"
	"gvisor.googlesource.com/gvisor/pkg/sentry/kernel"
	"gvisor.googlesource.com/gvisor/pkg/sentry/kernel/auth"
	"gvisor.googlesource.com/gvisor/pkg/sentry/loader"
	"gvisor.googlesource.com/gvisor/pkg/sentry/platform"
	"gvisor.googlesource.com/gvisor/pkg/sentry/platform/kvm"
	"gvisor.googlesource.com/gvisor/pkg/sentry/platform/ptrace"
	"gvisor.googlesource.com/gvisor/pkg/sentry/sighandling"
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

	// mu guards containerRootTGs.
	mu sync.Mutex

	// containerRootTGs maps container IDs to their root processes. It
	// can be used to determine which process to manipulate when clients
	// call methods on particular containers.
	//
	// containerRootTGs is guarded by mu.
	containerRootTGs map[string]*kernel.ThreadGroup
}

func init() {
	// Initialize the random number generator.
	rand.Seed(gtime.Now().UnixNano())

	// Register the global syscall table.
	kernel.RegisterSyscallTable(slinux.AMD64)
}

// New initializes a new kernel loader configured by spec.
// New also handles setting up a kernel for restoring a container.
func New(spec *specs.Spec, conf *Config, controllerFD, deviceFD int, goferFDs []int, console bool) (*Loader, error) {
	// Create kernel and platform.
	p, err := createPlatform(conf, deviceFD)
	if err != nil {
		return nil, fmt.Errorf("error creating platform: %v", err)
	}
	k := &kernel.Kernel{
		Platform: p,
	}

	// Create VDSO.
	//
	// Pass k as the platform since it is savable, unlike the actual platform.
	vdso, err := loader.PrepareVDSO(k)
	if err != nil {
		return nil, fmt.Errorf("error creating vdso: %v", err)
	}

	// Create timekeeper.
	tk, err := kernel.NewTimekeeper(k, vdso.ParamPage.FileRange())
	if err != nil {
		return nil, fmt.Errorf("error creating timekeeper: %v", err)
	}
	tk.SetClocks(time.NewCalibratedClocks())

	if err := enableStrace(conf); err != nil {
		return nil, fmt.Errorf("failed to enable strace: %v", err)
	}

	// Create an empty network stack because the network namespace may be empty at
	// this point. Netns is configured before Run() is called. Netstack is
	// configured using a control uRPC message. Host network is configured inside
	// Run().
	networkStack, err := newEmptyNetworkStack(conf, k)
	if err != nil {
		return nil, fmt.Errorf("failed to create network: %v", err)
	}

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
	creds := auth.NewUserCredentials(
		auth.KUID(spec.Process.User.UID),
		auth.KGID(spec.Process.User.GID),
		extraKGIDs,
		caps,
		auth.NewRootUserNamespace())

	// Initiate the Kernel object, which is required by the Context passed
	// to createVFS in order to mount (among other things) procfs.
	if err = k.Init(kernel.InitKernelArgs{
		FeatureSet:        cpuid.HostFeatureSet(),
		Timekeeper:        tk,
		RootUserNamespace: creds.UserNamespace,
		NetworkStack:      networkStack,
		// TODO: use number of logical processors from cgroups.
		ApplicationCores:            uint(runtime.NumCPU()),
		Vdso:                        vdso,
		RootUTSNamespace:            kernel.NewUTSNamespace(spec.Hostname, "", creds.UserNamespace),
		RootIPCNamespace:            kernel.NewIPCNamespace(creds.UserNamespace),
		RootAbstractSocketNamespace: kernel.NewAbstractSocketNamespace(),
	}); err != nil {
		return nil, fmt.Errorf("error initializing kernel: %v", err)
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
	ps := syscall.Signal(conf.PanicSignal)
	startSignalForwarding := sighandling.PrepareForwarding(k, ps)
	if conf.PanicSignal != -1 {
		// Panics if the sentry receives 'conf.PanicSignal'.
		panicChan := make(chan os.Signal, 1)
		signal.Notify(panicChan, ps)
		go func() { // S/R-SAFE: causes sentry panic.
			<-panicChan
			panic("Signal-induced panic")
		}()
		log.Infof("Panic signal set to %v(%d)", ps, conf.PanicSignal)
	}

	procArgs, err := newProcess(spec, creds, k)
	if err != nil {
		return nil, fmt.Errorf("failed to create root process: %v", err)
	}

	l := &Loader{
		k:                     k,
		ctrl:                  ctrl,
		conf:                  conf,
		console:               console,
		watchdog:              watchdog,
		stdioFDs:              []int{syscall.Stdin, syscall.Stdout, syscall.Stderr},
		goferFDs:              goferFDs,
		spec:                  spec,
		startSignalForwarding: startSignalForwarding,
		rootProcArgs:          procArgs,
	}
	ctrl.manager.l = l
	return l, nil
}

// newProcess creates a process that can be run with kernel.CreateProcess.
func newProcess(spec *specs.Spec, creds *auth.Credentials, k *kernel.Kernel) (kernel.CreateProcessArgs, error) {
	// Create initial limits.
	ls, err := createLimitSet(spec)
	if err != nil {
		return kernel.CreateProcessArgs{}, fmt.Errorf("error creating limits: %v", err)
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

func createPlatform(conf *Config, deviceFD int) (platform.Platform, error) {
	switch conf.Platform {
	case PlatformPtrace:
		log.Infof("Platform: ptrace")
		return ptrace.New()
	case PlatformKVM:
		log.Infof("Platform: kvm")
		if deviceFD < 0 {
			return nil, fmt.Errorf("kvm device fd must be provided")
		}
		return kvm.New(os.NewFile(uintptr(deviceFD), "kvm device"))
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
		opts := filter.Options{
			Platform:     l.k.Platform,
			HostNetwork:  l.conf.Network == NetworkHost,
			ControllerFD: l.ctrl.srv.FD(),
		}
		if err := filter.Install(opts); err != nil {
			return fmt.Errorf("Failed to install seccomp filters: %v", err)
		}
	}

	// If we are restoring, we do not want to create a process.
	// l.restore is set by the container manager when a restore call is made.
	if !l.restore {
		if err := setFileSystemForProcess(
			&l.rootProcArgs,
			l.spec,
			l.conf,
			l.stdioFDs,
			l.goferFDs,
			l.console,
			l.rootProcArgs.Credentials,
			l.rootProcArgs.Limits,
			l.k,
			"" /* CID, which isn't needed for the root container */); err != nil {
			return err
		}

		rootCtx := l.rootProcArgs.NewContext(l.k)
		rootMns := l.k.RootMountNamespace()
		if err := setExecutablePath(rootCtx, rootMns, &l.rootProcArgs); err != nil {
			return fmt.Errorf("error setting executable path for %+v: %v", l.rootProcArgs, err)
		}

		// Create the root container init task.
		if _, err := l.k.CreateProcess(l.rootProcArgs); err != nil {
			return fmt.Errorf("failed to create init process: %v", err)
		}

		// CreateProcess takes a reference on FDMap if successful.
		l.rootProcArgs.FDMap.DecRef()
	}

	// Start signal forwarding only after an init process is created.
	l.stopSignalForwarding = l.startSignalForwarding()

	log.Infof("Process should have started...")
	l.watchdog.Start()
	return l.k.Start()
}

// startContainer starts a child container. It returns the thread group ID of
// the newly created process.
func (l *Loader) startContainer(k *kernel.Kernel, spec *specs.Spec, conf *Config, cid string, files []*os.File) error {
	// Create capabilities.
	caps, err := specutils.Capabilities(spec.Process.Capabilities)
	if err != nil {
		return fmt.Errorf("error creating capabilities: %v", err)
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

	procArgs, err := newProcess(spec, creds, l.k)
	if err != nil {
		return fmt.Errorf("failed to create new process: %v", err)
	}

	// Can't take ownership away from os.File. dup them to get a new FDs.
	var ioFDs []int
	for _, f := range files {
		fd, err := syscall.Dup(int(f.Fd()))
		if err != nil {
			return fmt.Errorf("failed to dup file: %v", err)
		}
		f.Close()
		ioFDs = append(ioFDs, fd)
	}

	if err := setFileSystemForProcess(
		&procArgs,
		spec,
		conf,
		ioFDs[:3], // stdioFDs
		ioFDs[3:], // goferFDs
		false,
		creds,
		procArgs.Limits,
		k,
		cid); err != nil {
		return fmt.Errorf("failed to create new process: %v", err)
	}

	ctx := procArgs.NewContext(l.k)
	mns := k.RootMountNamespace()
	if err := setExecutablePath(ctx, mns, &procArgs); err != nil {
		return fmt.Errorf("error setting executable path for %+v: %v", procArgs, err)
	}

	tg, err := l.k.CreateProcess(procArgs)
	if err != nil {
		return fmt.Errorf("failed to create process in sentry: %v", err)
	}

	// CreateProcess takes a reference on FDMap if successful.
	procArgs.FDMap.DecRef()

	l.mu.Lock()
	defer l.mu.Unlock()
	l.containerRootTGs[cid] = tg

	return nil
}

// TODO: Per-container namespaces must be supported for -pid.

// waitContainer waits for the root process of a container to exit.
func (l *Loader) waitContainer(cid string, waitStatus *uint32) error {
	// Don't defer unlock, as doing so would make it impossible for
	// multiple clients to wait on the same container.
	l.mu.Lock()
	tg, ok := l.containerRootTGs[cid]
	if !ok {
		defer l.mu.Unlock()
		return fmt.Errorf("can't find process for container %q in %v", cid, l.containerRootTGs)
	}
	l.mu.Unlock()

	// If the thread either has already exited or exits during waiting,
	// consider the container exited.
	// TODO: Multiple calls to waitContainer() should return
	// the same exit status.
	defer func() {
		l.mu.Lock()
		defer l.mu.Unlock()
		// TODO: Containers don't map 1:1 with their root
		// processes. Container exits should be managed explicitly
		// rather than via PID.
		delete(l.containerRootTGs, cid)
	}()
	l.wait(tg, waitStatus)
	return nil
}

func (l *Loader) waitPID(tgid kernel.ThreadID, cid string, waitStatus *uint32) error {
	// TODO: Containers all currently share a PID namespace.
	// When per-container PID namespaces are supported, wait should use cid
	// to find the appropriate PID namespace.
	/*if cid != l.sandboxID {
		return errors.New("non-sandbox PID namespaces are not yet implemented")
	}*/
	// TODO: This won't work if the exec process already exited.
	tg := l.k.TaskSet().Root.ThreadGroupWithID(kernel.ThreadID(tgid))
	if tg == nil {
		return fmt.Errorf("no thread group with ID %d", tgid)
	}
	l.wait(tg, waitStatus)
	return nil
}

// wait waits for the process with TGID 'tgid' in a container's PID namespace
// to exit.
func (l *Loader) wait(tg *kernel.ThreadGroup, waitStatus *uint32) {
	tg.WaitExited()
	*waitStatus = tg.ExitStatus().Status()
}

func (l *Loader) setRootContainerID(cid string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.containerRootTGs = map[string]*kernel.ThreadGroup{cid: l.k.GlobalInit()}
	l.sandboxID = cid
}

// WaitForStartSignal waits for a start signal from the control server.
func (l *Loader) WaitForStartSignal() {
	<-l.ctrl.manager.startChan
}

// NotifyLoaderCreated sends a signal to the container manager that this
// loader has been created.
func (l *Loader) NotifyLoaderCreated() {
	l.ctrl.manager.loaderCreatedChan <- struct{}{}
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
		protoNames := []string{tcp.ProtocolName, udp.ProtocolName, ping.ProtocolName4}
		s := &epsocket.Stack{stack.New(netProtos, protoNames, stack.Options{Clock: clock})}
		if err := s.Stack.SetTransportProtocolOption(tcp.ProtocolNumber, tcp.SACKEnabled(true)); err != nil {
			return nil, fmt.Errorf("failed to enable SACK: %v", err)
		}
		return s, nil

	default:
		panic(fmt.Sprintf("invalid network configuration: %v", conf.Network))
	}
}

// TODO: Support sending signal to all.
func (l *Loader) signal(cid string, signo int32) error {
	l.mu.Lock()
	tg, ok := l.containerRootTGs[cid]
	l.mu.Unlock()
	if !ok {
		return fmt.Errorf("failed to signal container %q: no such container", cid)
	}

	si := arch.SignalInfo{Signo: signo}
	return tg.Leader().SendSignal(&si)
}

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

// Package sandbox creates and manipulates sandboxes.
package sandbox

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"syscall"
	"time"

	"github.com/cenkalti/backoff"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/syndtr/gocapability/capability"
	"gvisor.googlesource.com/gvisor/pkg/control/client"
	"gvisor.googlesource.com/gvisor/pkg/control/server"
	"gvisor.googlesource.com/gvisor/pkg/log"
	"gvisor.googlesource.com/gvisor/pkg/sentry/control"
	"gvisor.googlesource.com/gvisor/pkg/sentry/platform/kvm"
	"gvisor.googlesource.com/gvisor/pkg/urpc"
	"gvisor.googlesource.com/gvisor/runsc/boot"
	"gvisor.googlesource.com/gvisor/runsc/cgroup"
	"gvisor.googlesource.com/gvisor/runsc/console"
	"gvisor.googlesource.com/gvisor/runsc/specutils"
)

// Sandbox wraps a sandbox process.
//
// It is used to start/stop sandbox process (and associated processes like
// gofers), as well as for running and manipulating containers inside a running
// sandbox.
//
// Note: Sandbox must be immutable because a copy of it is saved for each
// container and changes would not be synchronized to all of them.
type Sandbox struct {
	// ID is the id of the sandbox (immutable). By convention, this is the same
	// ID as the first container run in the sandbox.
	ID string `json:"id"`

	// Pid is the pid of the running sandbox (immutable). May be 0 is the sandbox
	// is not running.
	Pid int `json:"pid"`

	// Chroot is the path to the chroot directory that the sandbox process
	// is running in.
	Chroot string `json:"chroot"`

	// Ccroup has the cgroup configuration for the sandbox.
	Cgroup *cgroup.Cgroup `json:"cgroup"`
}

// Create creates the sandbox process. The caller must call Destroy() on the
// sandbox.
func Create(id string, spec *specs.Spec, conf *boot.Config, bundleDir, consoleSocket, userLog string, ioFiles []*os.File) (*Sandbox, error) {
	s := &Sandbox{ID: id}
	c := specutils.MakeCleanup(func() { s.destroy() })
	defer c.Clean()

	if cg, ok := cgroup.New(spec); ok {
		s.Cgroup = cg

		// If there is cgroup config, install it before creating sandbox process.
		if err := s.Cgroup.Install(spec.Linux.Resources); err != nil {
			return nil, fmt.Errorf("error configuring cgroup: %v", err)
		}
	}

	// Create the sandbox process.
	if err := s.createSandboxProcess(spec, conf, bundleDir, consoleSocket, userLog, ioFiles); err != nil {
		return nil, err
	}

	// Wait for the control server to come up (or timeout).
	if err := s.waitForCreated(10 * time.Second); err != nil {
		return nil, err
	}

	if s.Cgroup != nil {
		if err := s.Cgroup.Add(s.Pid); err != nil {
			return nil, fmt.Errorf("error adding sandbox to cgroup: %v", err)
		}
	}

	c.Release()
	return s, nil
}

// StartRoot starts running the root container process inside the sandbox.
func (s *Sandbox) StartRoot(spec *specs.Spec, conf *boot.Config) error {
	log.Debugf("Start root sandbox %q, PID: %d", s.ID, s.Pid)
	conn, err := s.sandboxConnect()
	if err != nil {
		return err
	}
	defer conn.Close()

	// Configure the network.
	if err := setupNetwork(conn, s.Pid, spec, conf); err != nil {
		return fmt.Errorf("error setting up network: %v", err)
	}

	// Send a message to the sandbox control server to start the root
	// container.
	if err := conn.Call(boot.RootContainerStart, &s.ID, nil); err != nil {
		return fmt.Errorf("error starting root container %v: %v", spec.Process.Args, err)
	}

	return nil
}

// Start starts running a non-root container inside the sandbox.
func (s *Sandbox) Start(spec *specs.Spec, conf *boot.Config, cid string, goferFiles []*os.File) error {
	for _, f := range goferFiles {
		defer f.Close()
	}

	log.Debugf("Start non-root container sandbox %q, PID: %d", s.ID, s.Pid)
	sandboxConn, err := s.sandboxConnect()
	if err != nil {
		return fmt.Errorf("couldn't connect to sandbox: %v", err)
	}
	defer sandboxConn.Close()

	// The payload must container stdin/stdout/stderr followed by gofer
	// files.
	files := append([]*os.File{os.Stdin, os.Stdout, os.Stderr}, goferFiles...)
	// Start running the container.
	args := boot.StartArgs{
		Spec:        spec,
		Conf:        conf,
		CID:         cid,
		FilePayload: urpc.FilePayload{Files: files},
	}
	if err := sandboxConn.Call(boot.ContainerStart, &args, nil); err != nil {
		return fmt.Errorf("error starting non-root container %v: %v", spec.Process.Args, err)
	}
	return nil
}

// Restore sends the restore call for a container in the sandbox.
func (s *Sandbox) Restore(cid string, spec *specs.Spec, conf *boot.Config, f string) error {
	log.Debugf("Restore sandbox %q", s.ID)

	rf, err := os.Open(f)
	if err != nil {
		return fmt.Errorf("os.Open(%q) failed: %v", f, err)
	}
	defer rf.Close()

	opt := boot.RestoreOpts{
		FilePayload: urpc.FilePayload{
			Files: []*os.File{rf},
		},
		SandboxID: s.ID,
	}

	// If the platform needs a device FD we must pass it in.
	if deviceFile, err := deviceFileForPlatform(conf.Platform); err != nil {
		return err
	} else if deviceFile != nil {
		defer deviceFile.Close()
		opt.FilePayload.Files = append(opt.FilePayload.Files, deviceFile)
	}

	conn, err := s.sandboxConnect()
	if err != nil {
		return err
	}
	defer conn.Close()

	// Configure the network.
	if err := setupNetwork(conn, s.Pid, spec, conf); err != nil {
		return fmt.Errorf("error setting up network: %v", err)
	}

	// Restore the container and start the root container.
	if err := conn.Call(boot.ContainerRestore, &opt, nil); err != nil {
		return fmt.Errorf("error restoring container %q: %v", cid, err)
	}

	return nil
}

// Processes retrieves the list of processes and associated metadata for a
// given container in this sandbox.
func (s *Sandbox) Processes(cid string) ([]*control.Process, error) {
	log.Debugf("Getting processes for container %q in sandbox %q", cid, s.ID)
	conn, err := s.sandboxConnect()
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	args := boot.ProcessesArgs{CID: cid}
	var pl []*control.Process
	if err := conn.Call(boot.ContainerProcesses, &args, &pl); err != nil {
		return nil, fmt.Errorf("error retrieving process data from sandbox: %v", err)
	}
	return pl, nil
}

// Execute runs the specified command in the container. It returns the PID of
// the newly created process.
func (s *Sandbox) Execute(args *control.ExecArgs) (int32, error) {
	log.Debugf("Executing new process in container %q in sandbox %q", args.ContainerID, s.ID)
	conn, err := s.sandboxConnect()
	if err != nil {
		return 0, s.connError(err)
	}
	defer conn.Close()

	// Send a message to the sandbox control server to start the container.
	var pid int32
	if err := conn.Call(boot.ContainerExecuteAsync, args, &pid); err != nil {
		return 0, fmt.Errorf("error executing in sandbox: %v", err)
	}
	return pid, nil
}

// Event retrieves stats about the sandbox such as memory and CPU utilization.
func (s *Sandbox) Event(cid string) (*boot.Event, error) {
	log.Debugf("Getting events for container %q in sandbox %q", cid, s.ID)
	conn, err := s.sandboxConnect()
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	var e boot.Event
	// TODO: Pass in the container id (cid) here. The sandbox
	// should return events only for that container.
	if err := conn.Call(boot.ContainerEvent, nil, &e); err != nil {
		return nil, fmt.Errorf("error retrieving event data from sandbox: %v", err)
	}
	e.ID = cid
	return &e, nil
}

func (s *Sandbox) sandboxConnect() (*urpc.Client, error) {
	log.Debugf("Connecting to sandbox %q", s.ID)
	conn, err := client.ConnectTo(boot.ControlSocketAddr(s.ID))
	if err != nil {
		return nil, s.connError(err)
	}
	return conn, nil
}

func (s *Sandbox) connError(err error) error {
	return fmt.Errorf("error connecting to control server at PID %d: %v", s.Pid, err)
}

// createSandboxProcess starts the sandbox as a subprocess by running the "boot"
// command, passing in the bundle dir.
func (s *Sandbox) createSandboxProcess(spec *specs.Spec, conf *boot.Config, bundleDir, consoleSocket, userLog string, ioFiles []*os.File) error {
	// nextFD is used to get unused FDs that we can pass to the sandbox.  It
	// starts at 3 because 0, 1, and 2 are taken by stdin/out/err.
	nextFD := 3

	binPath, err := specutils.BinPath()
	if err != nil {
		return err
	}
	cmd := exec.Command(binPath, conf.ToFlags()...)
	cmd.SysProcAttr = &syscall.SysProcAttr{}

	// Open the log files to pass to the sandbox as FDs.
	//
	// These flags must come BEFORE the "boot" command in cmd.Args.
	if conf.LogFilename != "" {
		logFile, err := os.OpenFile(conf.LogFilename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return fmt.Errorf("error opening log file %q: %v", conf.LogFilename, err)
		}
		defer logFile.Close()
		cmd.ExtraFiles = append(cmd.ExtraFiles, logFile)
		cmd.Args = append(cmd.Args, "--log-fd="+strconv.Itoa(nextFD))
		nextFD++
	}
	if conf.DebugLog != "" {
		debugLogFile, err := specutils.DebugLogFile(conf.DebugLog, "boot")
		if err != nil {
			return fmt.Errorf("error opening debug log file in %q: %v", conf.DebugLog, err)
		}
		defer debugLogFile.Close()
		cmd.ExtraFiles = append(cmd.ExtraFiles, debugLogFile)
		cmd.Args = append(cmd.Args, "--debug-log-fd="+strconv.Itoa(nextFD))
		nextFD++
	}

	// Add the "boot" command to the args.
	//
	// All flags after this must be for the boot command
	cmd.Args = append(cmd.Args, "boot", "--bundle="+bundleDir)

	// Create a socket for the control server and donate it to the sandbox.
	addr := boot.ControlSocketAddr(s.ID)
	sockFD, err := server.CreateSocket(addr)
	log.Infof("Creating sandbox process with addr: %s", addr[1:]) // skip "\00".
	if err != nil {
		return fmt.Errorf("error creating control server socket for sandbox %q: %v", s.ID, err)
	}
	controllerFile := os.NewFile(uintptr(sockFD), "control_server_socket")
	defer controllerFile.Close()
	cmd.ExtraFiles = append(cmd.ExtraFiles, controllerFile)
	cmd.Args = append(cmd.Args, "--controller-fd="+strconv.Itoa(nextFD))
	nextFD++

	// Open the spec file to donate to the sandbox.
	if conf.SpecFile == "" {
		return fmt.Errorf("conf.SpecFile must be set")
	}
	specFile, err := os.Open(conf.SpecFile)
	if err != nil {
		return fmt.Errorf("error opening spec file %q: %v", conf.SpecFile, err)
	}
	defer specFile.Close()
	cmd.ExtraFiles = append(cmd.ExtraFiles, specFile)
	cmd.Args = append(cmd.Args, "--spec-fd="+strconv.Itoa(nextFD))
	nextFD++

	// If there is a gofer, sends all socket ends to the sandbox.
	for _, f := range ioFiles {
		defer f.Close()
		cmd.ExtraFiles = append(cmd.ExtraFiles, f)
		cmd.Args = append(cmd.Args, "--io-fds="+strconv.Itoa(nextFD))
		nextFD++
	}

	// If the platform needs a device FD we must pass it in.
	if deviceFile, err := deviceFileForPlatform(conf.Platform); err != nil {
		return err
	} else if deviceFile != nil {
		defer deviceFile.Close()
		cmd.ExtraFiles = append(cmd.ExtraFiles, deviceFile)
		cmd.Args = append(cmd.Args, "--device-fd="+strconv.Itoa(nextFD))
		nextFD++
	}

	// The current process' stdio must be passed to the application via the
	// --stdio-fds flag. The stdio of the sandbox process itself must not
	// be connected to the same FDs, otherwise we risk leaking sandbox
	// errors to the application, so we set the sandbox stdio to nil,
	// causing them to read/write from the null device.
	cmd.Stdin = nil
	cmd.Stdout = nil
	cmd.Stderr = nil

	// If the console control socket file is provided, then create a new
	// pty master/slave pair and set the TTY on the sandbox process.
	if consoleSocket != "" {
		cmd.Args = append(cmd.Args, "--console=true")

		// console.NewWithSocket will send the master on the given
		// socket, and return the slave.
		tty, err := console.NewWithSocket(consoleSocket)
		if err != nil {
			return fmt.Errorf("error setting up console with socket %q: %v", consoleSocket, err)
		}
		defer tty.Close()

		// Set the TTY as a controlling TTY on the sandbox process.
		// Note that the Ctty field must be the FD of the TTY in the
		// *new* process, not this process. Since we are about to
		// assign the TTY to nextFD, we can use that value here.
		// stdin, we can use FD 0 here.
		cmd.SysProcAttr.Setctty = true
		cmd.SysProcAttr.Ctty = nextFD

		// Pass the tty as all stdio fds to sandbox.
		for i := 0; i < 3; i++ {
			cmd.ExtraFiles = append(cmd.ExtraFiles, tty)
			cmd.Args = append(cmd.Args, "--stdio-fds="+strconv.Itoa(nextFD))
			nextFD++
		}

		if conf.Debug {
			// If debugging, send the boot process stdio to the
			// TTY, so that it is easier to find.
			cmd.Stdin = tty
			cmd.Stdout = tty
			cmd.Stderr = tty
		}
	} else {
		// If not using a console, pass our current stdio as the
		// container stdio via flags.
		for _, f := range []*os.File{os.Stdin, os.Stdout, os.Stderr} {
			cmd.ExtraFiles = append(cmd.ExtraFiles, f)
			cmd.Args = append(cmd.Args, "--stdio-fds="+strconv.Itoa(nextFD))
			nextFD++
		}

		if conf.Debug {
			// If debugging, send the boot process stdio to the
			// this process' stdio, so that is is easier to find.
			cmd.Stdin = os.Stdin
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
		}
	}

	// Detach from this session, otherwise cmd will get SIGHUP and SIGCONT
	// when re-parented.
	cmd.SysProcAttr.Setsid = true

	// nss is the set of namespaces to join or create before starting the sandbox
	// process. Mount, IPC and UTS namespaces from the host are not used as they
	// are virtualized inside the sandbox. Be paranoid and run inside an empty
	// namespace for these. Don't unshare cgroup because sandbox is added to a
	// cgroup in the caller's namespace.
	log.Infof("Sandbox will be started in new mount, IPC and UTS namespaces")
	nss := []specs.LinuxNamespace{
		{Type: specs.IPCNamespace},
		{Type: specs.MountNamespace},
		{Type: specs.UTSNamespace},
	}

	if conf.Platform == boot.PlatformPtrace {
		// TODO: Also set a new PID namespace so that we limit
		// access to other host processes.
		log.Infof("Sandbox will be started in the current PID namespace")
	} else {
		log.Infof("Sandbox will be started in a new PID namespace")
		nss = append(nss, specs.LinuxNamespace{Type: specs.PIDNamespace})
	}

	// Joins the network namespace if network is enabled. the sandbox talks
	// directly to the host network, which may have been configured in the
	// namespace.
	if ns, ok := specutils.GetNS(specs.NetworkNamespace, spec); ok && conf.Network != boot.NetworkNone {
		log.Infof("Sandbox will be started in the container's network namespace: %+v", ns)
		nss = append(nss, ns)
	} else {
		log.Infof("Sandbox will be started in new network namespace")
		nss = append(nss, specs.LinuxNamespace{Type: specs.NetworkNamespace})
	}

	// User namespace depends on the network type. Host network requires to run
	// inside the user namespace specified in the spec or the current namespace
	// if none is configured.
	if conf.Network == boot.NetworkHost {
		if userns, ok := specutils.GetNS(specs.UserNamespace, spec); ok {
			log.Infof("Sandbox will be started in container's user namespace: %+v", userns)
			nss = append(nss, userns)
			specutils.SetUIDGIDMappings(cmd, spec)
		} else {
			log.Infof("Sandbox will be started in the current user namespace")
		}
		// When running in the caller's defined user namespace, apply the same
		// capabilities to the sandbox process to ensure it abides to the same
		// rules.
		cmd.Args = append(cmd.Args, "--apply-caps=true")

	} else {
		log.Infof("Sandbox will be started in new user namespace")
		nss = append(nss, specs.LinuxNamespace{Type: specs.UserNamespace})

		// If we have CAP_SETUID and CAP_SETGID, then we can also run
		// as user nobody.
		if conf.TestOnlyAllowRunAsCurrentUserWithoutChroot {
			log.Warningf("Running sandbox in test mode as current user (uid=%d gid=%d). This is only safe in tests!", os.Getuid(), os.Getgid())
		} else if specutils.HasCapabilities(capability.CAP_SETUID, capability.CAP_SETGID) {
			// Map nobody in the new namespace to nobody in the parent namespace.
			const nobody = 65534
			cmd.SysProcAttr.UidMappings = []syscall.SysProcIDMap{{
				ContainerID: int(nobody),
				HostID:      int(nobody),
				Size:        int(1),
			}}
			cmd.SysProcAttr.GidMappings = []syscall.SysProcIDMap{{
				ContainerID: int(nobody),
				HostID:      int(nobody),
				Size:        int(1),
			}}

			// Set credentials to run as user and group nobody.
			cmd.SysProcAttr.Credential = &syscall.Credential{
				Uid: nobody,
				Gid: nobody,
			}
		} else {
			return fmt.Errorf("can't run sandbox process as user nobody since we don't have CAP_SETUID or CAP_SETGID")
		}

		// If we have CAP_SYS_ADMIN, we can create an empty chroot and
		// bind-mount the executable inside it.
		if conf.TestOnlyAllowRunAsCurrentUserWithoutChroot {
			log.Warningf("Running sandbox in test mode without chroot. This is only safe in tests!")
		} else if specutils.HasCapabilities(capability.CAP_SYS_ADMIN, capability.CAP_SYS_CHROOT) {
			log.Infof("Sandbox will be started in minimal chroot")
			chroot, err := setUpChroot()
			if err != nil {
				return fmt.Errorf("error setting up chroot: %v", err)
			}
			s.Chroot = chroot // Remember path so it can cleaned up.
			cmd.SysProcAttr.Chroot = chroot
			cmd.Dir = "/"
			cmd.Args[0] = "/runsc"
			cmd.Path = "/runsc"
		} else {
			return fmt.Errorf("can't run sandbox process in minimal chroot since we don't have CAP_SYS_ADMIN and CAP_SYS_CHROOT")
		}
	}

	if s.Cgroup != nil {
		cpuNum, err := s.Cgroup.NumCPU()
		if err != nil {
			return fmt.Errorf("error getting cpu count from cgroups: %v", err)
		}
		cmd.Args = append(cmd.Args, "--cpu-num", strconv.Itoa(cpuNum))

		mem, err := s.Cgroup.MemoryLimit()
		if err != nil {
			return fmt.Errorf("error getting memory limit from cgroups: %v", err)
		}
		// When memory limit is unset, a "large" number is returned. In that case,
		// just stick with the default.
		if mem < 0x7ffffffffffff000 {
			cmd.Args = append(cmd.Args, "--total-memory", strconv.FormatUint(mem, 10))
		}
	}

	if userLog != "" {
		f, err := os.OpenFile(userLog, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0664)
		if err != nil {
			return fmt.Errorf("opening compat log file: %v", err)
		}
		defer f.Close()

		cmd.ExtraFiles = append(cmd.ExtraFiles, f)
		cmd.Args = append(cmd.Args, "--user-log-fd", strconv.Itoa(nextFD))
		nextFD++
	}

	// Add container as the last argument.
	cmd.Args = append(cmd.Args, s.ID)

	// Log the FDs we are donating to the sandbox process.
	for i, f := range cmd.ExtraFiles {
		log.Debugf("Donating FD %d: %q", i+3, f.Name())
	}

	log.Debugf("Starting sandbox: %s %v", binPath, cmd.Args)
	log.Debugf("SysProcAttr: %+v", cmd.SysProcAttr)
	if err := specutils.StartInNS(cmd, nss); err != nil {
		return err
	}
	s.Pid = cmd.Process.Pid
	log.Infof("Sandbox started, PID: %d", s.Pid)

	return nil
}

// waitForCreated waits for the sandbox subprocess control server to be
// running and for the loader to have been created, at which point the sandbox
// is in Created state.
func (s *Sandbox) waitForCreated(timeout time.Duration) error {
	log.Debugf("Waiting for sandbox %q creation", s.ID)

	ready := func() (bool, error) {
		c, err := client.ConnectTo(boot.ControlSocketAddr(s.ID))
		if err != nil {
			return false, nil
		}
		// It's alive!
		c.Close()
		return true, nil
	}
	if err := specutils.WaitForReady(s.Pid, timeout, ready); err != nil {
		return fmt.Errorf("unexpected error waiting for sandbox %q, err: %v", s.ID, err)
	}
	conn, err := s.sandboxConnect()
	if err != nil {
		return err
	}
	defer conn.Close()

	if err := conn.Call(boot.ContainerWaitForLoader, nil, nil); err != nil {
		return fmt.Errorf("err waiting on loader on sandbox %q, err: %v", s.ID, err)
	}
	return nil
}

// Wait waits for the containerized process to exit, and returns its WaitStatus.
func (s *Sandbox) Wait(cid string) (syscall.WaitStatus, error) {
	log.Debugf("Waiting for container %q in sandbox %q", cid, s.ID)
	var ws syscall.WaitStatus
	conn, err := s.sandboxConnect()
	if err != nil {
		return ws, err
	}
	defer conn.Close()

	// First try the Wait RPC to the sandbox.
	if err := conn.Call(boot.ContainerWait, &cid, &ws); err == nil {
		return ws, nil
	}
	log.Warningf("Wait RPC to container %q failed: %v. Will try waiting on the sandbox process instead.", cid, err)

	// The sandbox may have already exited, or exited while handling the
	// Wait RPC. The best we can do is ask Linux what the sandbox exit
	// status was, since in most cases that will be the same as the
	// container exit status.
	p, err := os.FindProcess(s.Pid)
	if err != nil {
		// "On Unix systems, FindProcess always succeeds and returns a
		// Process for the given pid, regardless of whether the process
		// exists."
		return ws, fmt.Errorf("FindProcess(%d) failed: %v", s.Pid, err)
	}
	ps, err := p.Wait()
	if err != nil {
		return ws, fmt.Errorf("sandbox no longer running, tried to get exit status, but Wait failed: %v", err)
	}
	return ps.Sys().(syscall.WaitStatus), nil
}

// WaitPID waits for process 'pid' in the container's sandbox and returns its
// WaitStatus.
func (s *Sandbox) WaitPID(cid string, pid int32, clearStatus bool) (syscall.WaitStatus, error) {
	log.Debugf("Waiting for PID %d in sandbox %q", pid, s.ID)
	var ws syscall.WaitStatus
	conn, err := s.sandboxConnect()
	if err != nil {
		return ws, err
	}
	defer conn.Close()

	args := &boot.WaitPIDArgs{
		PID:         pid,
		CID:         cid,
		ClearStatus: clearStatus,
	}
	if err := conn.Call(boot.ContainerWaitPID, args, &ws); err != nil {
		return ws, fmt.Errorf("error waiting on PID %d in sandbox %q: %v", pid, s.ID, err)
	}
	return ws, nil
}

// IsRootContainer returns true if the specified container ID belongs to the
// root container.
func (s *Sandbox) IsRootContainer(cid string) bool {
	return s.ID == cid
}

// Destroy frees all resources associated with the sandbox. It fails fast and
// is idempotent.
func (s *Sandbox) destroy() error {
	log.Debugf("Destroy sandbox %q", s.ID)
	if s.Pid != 0 {
		log.Debugf("Killing sandbox %q", s.ID)
		if err := syscall.Kill(s.Pid, syscall.SIGKILL); err != nil && err != syscall.ESRCH {
			return fmt.Errorf("error killing sandbox %q PID %q: %v", s.ID, s.Pid, err)
		}
		if err := s.waitForStopped(); err != nil {
			return fmt.Errorf("error waiting sandbox %q stop: %v", s.ID, err)
		}
	}

	if s.Cgroup != nil {
		if err := s.Cgroup.Uninstall(); err != nil {
			return err
		}
	}
	if s.Chroot != "" {
		if err := tearDownChroot(s.Chroot); err != nil {
			return err
		}
	}

	return nil
}

// SignalContainer sends the signal to a container in the sandbox. If all is
// true and signal is SIGKILL, then waits for all processes to exit before
// returning.
func (s *Sandbox) SignalContainer(cid string, sig syscall.Signal, all bool) error {
	log.Debugf("Signal sandbox %q", s.ID)
	conn, err := s.sandboxConnect()
	if err != nil {
		return err
	}
	defer conn.Close()

	args := boot.SignalArgs{
		CID:   cid,
		Signo: int32(sig),
		All:   all,
	}
	if err := conn.Call(boot.ContainerSignal, &args, nil); err != nil {
		return fmt.Errorf("err signaling container %q: %v", cid, err)
	}
	return nil
}

// SignalProcess sends the signal to a particular process in the container. If
// fgProcess is true, then the signal is sent to the foreground process group
// in the same session that PID belongs to. This is only valid if the process
// is attached to a host TTY.
func (s *Sandbox) SignalProcess(cid string, pid int32, sig syscall.Signal, fgProcess bool) error {
	log.Debugf("Signal sandbox %q", s.ID)
	conn, err := s.sandboxConnect()
	if err != nil {
		return err
	}
	defer conn.Close()

	args := boot.SignalProcessArgs{
		CID:                     cid,
		Signo:                   int32(sig),
		PID:                     pid,
		SendToForegroundProcess: fgProcess,
	}
	if err := conn.Call(boot.ContainerSignalProcess, &args, nil); err != nil {
		return fmt.Errorf("err signaling container %q PID %d: %v", cid, pid, err)
	}
	return nil
}

// Checkpoint sends the checkpoint call for a container in the sandbox.
// The statefile will be written to f.
func (s *Sandbox) Checkpoint(cid string, f *os.File) error {
	log.Debugf("Checkpoint sandbox %q", s.ID)
	conn, err := s.sandboxConnect()
	if err != nil {
		return err
	}
	defer conn.Close()

	opt := control.SaveOpts{
		FilePayload: urpc.FilePayload{
			Files: []*os.File{f},
		},
	}

	if err := conn.Call(boot.ContainerCheckpoint, &opt, nil); err != nil {
		return fmt.Errorf("err checkpointing container %q: %v", cid, err)
	}
	return nil
}

// Pause sends the pause call for a container in the sandbox.
func (s *Sandbox) Pause(cid string) error {
	log.Debugf("Pause sandbox %q", s.ID)
	conn, err := s.sandboxConnect()
	if err != nil {
		return err
	}
	defer conn.Close()

	if err := conn.Call(boot.ContainerPause, nil, nil); err != nil {
		return fmt.Errorf("err pausing container %q: %v", cid, err)
	}
	return nil
}

// Resume sends the resume call for a container in the sandbox.
func (s *Sandbox) Resume(cid string) error {
	log.Debugf("Resume sandbox %q", s.ID)
	conn, err := s.sandboxConnect()
	if err != nil {
		return err
	}
	defer conn.Close()

	if err := conn.Call(boot.ContainerResume, nil, nil); err != nil {
		return fmt.Errorf("err resuming container %q: %v", cid, err)
	}
	return nil
}

// IsRunning returns true if the sandbox or gofer process is running.
func (s *Sandbox) IsRunning() bool {
	if s.Pid != 0 {
		// Send a signal 0 to the sandbox process.
		if err := syscall.Kill(s.Pid, 0); err == nil {
			// Succeeded, process is running.
			return true
		}
	}
	return false
}

// Stacks collects and returns all stacks for the sandbox.
func (s *Sandbox) Stacks() (string, error) {
	log.Debugf("Stacks sandbox %q", s.ID)
	conn, err := s.sandboxConnect()
	if err != nil {
		return "", err
	}
	defer conn.Close()

	var stacks string
	if err := conn.Call(boot.SandboxStacks, nil, &stacks); err != nil {
		return "", fmt.Errorf("err getting sandbox %q stacks: %v", s.ID, err)
	}
	return stacks, nil
}

// DestroyContainer destroys the given container. If it is the root container,
// then the entire sandbox is destroyed.
func (s *Sandbox) DestroyContainer(cid string) error {
	if s.IsRootContainer(cid) {
		log.Debugf("Destroying root container %q by destroying sandbox", cid)
		return s.destroy()
	}

	if !s.IsRunning() {
		// Sandbox isn't running anymore, container is already destroyed.
		return nil
	}

	log.Debugf("Destroying container %q in sandbox %q", cid, s.ID)
	conn, err := s.sandboxConnect()
	if err != nil {
		return err
	}
	defer conn.Close()
	if err := conn.Call(boot.ContainerDestroy, &cid, nil); err != nil {
		return fmt.Errorf("error destroying container %q: %v", cid, err)
	}
	return nil
}

func (s *Sandbox) waitForStopped() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	b := backoff.WithContext(backoff.NewConstantBackOff(100*time.Millisecond), ctx)
	op := func() error {
		if s.IsRunning() {
			return fmt.Errorf("sandbox is still running")
		}
		return nil
	}
	return backoff.Retry(op, b)
}

// AddGoferToCgroup adds the gofer process to the sandbox's cgroup.
func (s *Sandbox) AddGoferToCgroup(pid int) error {
	if s.Cgroup != nil {
		return s.Cgroup.Add(pid)
	}
	return nil
}

// deviceFileForPlatform opens the device file for the given platform. If the
// platform does not need a device file, then nil is returned.
func deviceFileForPlatform(p boot.PlatformType) (*os.File, error) {
	var (
		f   *os.File
		err error
	)
	switch p {
	case boot.PlatformKVM:
		f, err = kvm.OpenDevice()
	default:
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("error opening device file for platform %q: %v", p, err)
	}
	return f, err
}

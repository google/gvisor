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
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"syscall"
	"time"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"
	"gvisor.googlesource.com/gvisor/pkg/control/client"
	"gvisor.googlesource.com/gvisor/pkg/control/server"
	"gvisor.googlesource.com/gvisor/pkg/log"
	"gvisor.googlesource.com/gvisor/pkg/sentry/control"
	"gvisor.googlesource.com/gvisor/pkg/urpc"
	"gvisor.googlesource.com/gvisor/runsc/boot"
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
}

// Create creates the sandbox process.
func Create(id string, spec *specs.Spec, conf *boot.Config, bundleDir, consoleSocket string, ioFiles []*os.File) (*Sandbox, error) {
	s := &Sandbox{ID: id}

	// Create the sandbox process.
	if err := s.createSandboxProcess(spec, conf, bundleDir, consoleSocket, ioFiles); err != nil {
		return nil, err
	}

	// Wait for the control server to come up (or timeout).
	if err := s.waitForCreated(10 * time.Second); err != nil {
		return nil, err
	}

	return s, nil
}

// StartRoot starts running the root container process inside the sandbox.
func (s *Sandbox) StartRoot(spec *specs.Spec, conf *boot.Config) error {
	log.Debugf("Start root sandbox %q, pid: %d", s.ID, s.Pid)
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
func (s *Sandbox) Start(spec *specs.Spec, conf *boot.Config, cid string, ioFiles []*os.File) error {
	for _, f := range ioFiles {
		defer f.Close()
	}

	log.Debugf("Start non-root container sandbox %q, pid: %d", s.ID, s.Pid)
	sandboxConn, err := s.sandboxConnect()
	if err != nil {
		return fmt.Errorf("couldn't connect to sandbox: %v", err)
	}
	defer sandboxConn.Close()

	// Start running the container.
	args := boot.StartArgs{
		Spec:        spec,
		Conf:        conf,
		CID:         cid,
		FilePayload: urpc.FilePayload{Files: ioFiles},
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

	var pl []*control.Process
	// TODO: Pass in the container id (cid) here. The sandbox
	// should return process info for only that container.
	if err := conn.Call(boot.ContainerProcesses, nil, &pl); err != nil {
		return nil, fmt.Errorf("error retrieving process data from sandbox: %v", err)
	}
	return pl, nil
}

// Execute runs the specified command in the container.
func (s *Sandbox) Execute(cid string, e *control.ExecArgs) (syscall.WaitStatus, error) {
	log.Debugf("Executing new process in container %q in sandbox %q", cid, s.ID)
	conn, err := s.sandboxConnect()
	if err != nil {
		return 0, s.connError(err)
	}
	defer conn.Close()

	// Send a message to the sandbox control server to start the container.
	var waitStatus uint32
	// TODO: Pass in the container id (cid) here. The sandbox
	// should execute in the context of that container.
	if err := conn.Call(boot.ContainerExecute, e, &waitStatus); err != nil {
		return 0, fmt.Errorf("error executing in sandbox: %v", err)
	}

	return syscall.WaitStatus(waitStatus), nil
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
	return fmt.Errorf("error connecting to control server at pid %d: %v", s.Pid, err)
}

// createSandboxProcess starts the sandbox as a subprocess by running the "boot"
// command, passing in the bundle dir.
func (s *Sandbox) createSandboxProcess(spec *specs.Spec, conf *boot.Config, bundleDir, consoleSocket string, ioFiles []*os.File) error {
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
	if conf.DebugLogDir != "" {
		debugLogFile, err := specutils.DebugLogFile(conf.DebugLogDir, "boot")
		if err != nil {
			return fmt.Errorf("error opening debug log file in %q: %v", conf.DebugLogDir, err)
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

	consoleEnabled := consoleSocket != ""
	cmd.Args = append(cmd.Args, "--console="+strconv.FormatBool(consoleEnabled))

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

	// Sandbox stdio defaults to current process stdio.
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	// If the console control socket file is provided, then create a new
	// pty master/slave pair and set the tty on the sandbox process.
	if consoleEnabled {
		// console.NewWithSocket will send the master on the socket,
		// and return the slave.
		tty, err := console.NewWithSocket(consoleSocket)
		if err != nil {
			return fmt.Errorf("error setting up console with socket %q: %v", consoleSocket, err)
		}
		defer tty.Close()

		cmd.Stdin = tty
		cmd.Stdout = tty
		cmd.Stderr = tty
		cmd.SysProcAttr.Setctty = true
		cmd.SysProcAttr.Ctty = int(tty.Fd())
	}

	// Detach from this session, otherwise cmd will get SIGHUP and SIGCONT
	// when re-parented.
	cmd.SysProcAttr.Setsid = true

	// nss is the set of namespaces to join or create before starting the sandbox
	// process. IPC and UTS namespaces from the host are not used as they
	// are virtualized inside the sandbox. Be paranoid and run inside an empty
	// namespace for these.
	log.Infof("Sandbox will be started in new IPC and UTS namespaces")
	nss := []specs.LinuxNamespace{
		{Type: specs.IPCNamespace},
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

	if conf.FileAccess == boot.FileAccessDirect {
		log.Infof("Sandbox will be started in the current mount namespace")
	} else {
		log.Infof("Sandbox will be started in new mount namespace")
		nss = append(nss, specs.LinuxNamespace{Type: specs.MountNamespace})
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

	// User namespace depends on the following options:
	//   - Host network/filesystem: requires to run inside the user namespace
	//       specified in the spec or the current namespace if none is configured.
	//   - Gofer: when using a Gofer, the sandbox process can run isolated in an
	//       empty namespace.
	if conf.Network == boot.NetworkHost || conf.FileAccess == boot.FileAccessDirect {
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
	}

	// Log the fds we are donating to the sandbox process.
	for i, f := range cmd.ExtraFiles {
		log.Debugf("Donating FD %d: %q", i+3, f.Name())
	}

	log.Debugf("Starting sandbox: %s %v", binPath, cmd.Args)
	if err := specutils.StartInNS(cmd, nss); err != nil {
		return err
	}
	s.Pid = cmd.Process.Pid
	log.Infof("Sandbox started, pid: %d", s.Pid)

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

	if err := conn.Call(boot.ContainerWait, &cid, &ws); err != nil {
		return ws, fmt.Errorf("error waiting on container %q: %v", cid, err)
	}
	return ws, nil
}

// WaitPID waits for process 'pid' in the container's sandbox and returns its
// WaitStatus.
func (s *Sandbox) WaitPID(pid int32, cid string) (syscall.WaitStatus, error) {
	log.Debugf("Waiting for PID %d in sandbox %q", pid, s.ID)
	var ws syscall.WaitStatus
	conn, err := s.sandboxConnect()
	if err != nil {
		return ws, err
	}
	defer conn.Close()

	args := &boot.WaitPIDArgs{
		PID: pid,
		CID: cid,
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

// Stop stops the container in the sandbox.
func (s *Sandbox) Stop(cid string) error {
	// TODO: This should stop the container with the given ID
	// in the sandbox.
	return nil
}

// Destroy frees all resources associated with the sandbox.
func (s *Sandbox) Destroy() error {
	log.Debugf("Destroy sandbox %q", s.ID)
	if s.Pid != 0 {
		// TODO: Too harsh?
		log.Debugf("Killing sandbox %q", s.ID)
		signalProcess(s.Pid, unix.SIGKILL)
	}
	return nil
}

// Signal sends the signal to a container in the sandbox.
func (s *Sandbox) Signal(cid string, sig syscall.Signal) error {
	log.Debugf("Signal sandbox %q", s.ID)
	conn, err := s.sandboxConnect()
	if err != nil {
		return err
	}
	defer conn.Close()

	args := boot.SignalArgs{
		CID:   cid,
		Signo: int32(sig),
	}
	if err := conn.Call(boot.ContainerSignal, &args, nil); err != nil {
		return fmt.Errorf("err signaling container %q: %v", cid, err)
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
		if err := signalProcess(s.Pid, 0); err == nil {
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

// signalProcess sends a signal to the host process (i.e. a sandbox or gofer
// process). Sandbox.Signal should be used to send a signal to a process
// running inside the sandbox.
func signalProcess(pid int, sig syscall.Signal) error {
	if err := syscall.Kill(pid, sig); err != nil {
		return fmt.Errorf("error sending signal %d to pid %d: %v", sig, pid, err)
	}
	return nil
}

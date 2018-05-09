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
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
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
	"gvisor.googlesource.com/gvisor/runsc/specutils"
)

// metadataFilename is the name of the metadata file relative to sandboxRoot
// that holds sandbox metadata.
const metadataFilename = "meta.json"

// See libcontainer/factory_linux.go
var idRegex = regexp.MustCompile(`^[\w+-\.]+$`)

// validateID validates the sandbox id.
func validateID(id string) error {
	if !idRegex.MatchString(id) {
		return fmt.Errorf("invalid sandbox id: %v", id)
	}
	return nil
}

func validateSpec(spec *specs.Spec) error {
	if spec.Process.SelinuxLabel != "" {
		return fmt.Errorf("SELinux is not supported: %s", spec.Process.SelinuxLabel)
	}

	// Docker uses AppArmor by default, so just log that it's being ignored.
	if spec.Process.ApparmorProfile != "" {
		log.Warningf("AppArmor profile %q is being ignored", spec.Process.ApparmorProfile)
	}
	// TODO: Apply seccomp to application inside sandbox.
	if spec.Linux != nil && spec.Linux.Seccomp != nil {
		log.Warningf("Seccomp spec is being ignored")
	}
	return nil
}

// Sandbox wraps a child sandbox process, and is responsible for saving and
// loading sandbox metadata to disk.
//
// Within a root directory, we maintain subdirectories for each sandbox named
// with the sandbox id.  The sandbox metadata is is stored as json within the
// sandbox directory in a file named "meta.json".  This metadata format is
// defined by us, and is not part of the OCI spec.
//
// Sandboxes must write this metadata file after any change to their internal
// state.  The entire sandbox directory is deleted when the sandbox is
// destroyed.
//
// TODO: Protect against concurrent changes to the sandbox metadata
// file.
type Sandbox struct {
	// ID is the sandbox ID.
	ID string `json:"id"`

	// Spec is the OCI runtime spec that configures this sandbox.
	Spec *specs.Spec `json:"spec"`

	// BundleDir is the directory containing the sandbox bundle.
	BundleDir string `json:"bundleDir"`

	// SandboxRoot is the directory containing the sandbox metadata file.
	SandboxRoot string `json:"sandboxRoot"`

	// CreatedAt is the time the sandbox was created.
	CreatedAt time.Time `json:"createdAt"`

	// Owner is the sandbox owner.
	Owner string `json:"owner"`

	// ConsoleSocket is the path to a unix domain socket that will receive
	// the console FD.  It is only used during create, so we don't need to
	// store it in the metadata.
	ConsoleSocket string `json:"-"`

	// Pid is the pid of the running sandbox.  Only valid if Status is
	// Created or Running.
	Pid int `json:"pid"`

	// GoferPid is the pid of the gofer running along side the sandbox. May be 0
	// if the gofer has been killed or it's not being used.
	GoferPid int `json:"goferPid"`

	// Status is the current sandbox Status.
	Status Status `json:"status"`
}

// Create creates the sandbox subprocess and writes the metadata file.  Args
// are additional arguments that will be passed to the sandbox process.
func Create(id string, spec *specs.Spec, conf *boot.Config, bundleDir, consoleSocket, pidFile string, args []string) (*Sandbox, error) {
	log.Debugf("Create sandbox %q in root dir: %s", id, conf.RootDir)
	if err := validateID(id); err != nil {
		return nil, err
	}
	if err := validateSpec(spec); err != nil {
		return nil, err
	}

	sandboxRoot := filepath.Join(conf.RootDir, id)
	if exists(sandboxRoot) {
		return nil, fmt.Errorf("sandbox with id %q already exists: %q ", id, sandboxRoot)
	}

	s := &Sandbox{
		ID:            id,
		Spec:          spec,
		ConsoleSocket: consoleSocket,
		BundleDir:     bundleDir,
		SandboxRoot:   sandboxRoot,
		Status:        Creating,
		Owner:         os.Getenv("USER"),
	}

	// Create sandbox process. If anything errors between now and the end of this
	// function, we MUST clean up all sandbox resources.
	if err := s.createProcesses(conf, args); err != nil {
		s.Destroy()
		return nil, err
	}

	// Wait for the control server to come up (or timeout).  The sandbox is
	// not "created" until that happens.
	if err := s.waitForCreated(10 * time.Second); err != nil {
		s.Destroy()
		return nil, err
	}

	s.Status = Created
	s.CreatedAt = time.Now()

	// Save the metadata file.
	if err := s.save(); err != nil {
		s.Destroy()
		return nil, err
	}

	// Write the pid file.  Containerd consideres the create complete after
	// this file is created, so it must be the last thing we do.
	if pidFile != "" {
		if err := ioutil.WriteFile(pidFile, []byte(strconv.Itoa(s.Pid)), 0644); err != nil {
			s.Destroy()
			return nil, fmt.Errorf("error writing pid file: %v", err)
		}
	}

	return s, nil
}

// Run is a helper that calls Create + Start + Wait.
func Run(id string, spec *specs.Spec, conf *boot.Config, bundleDir, consoleSocket, pidFile string, args []string) (syscall.WaitStatus, error) {
	s, err := Create(id, spec, conf, bundleDir, consoleSocket, pidFile, args)
	if err != nil {
		return 0, fmt.Errorf("error creating sandbox: %v", err)
	}
	if err := s.Start(conf); err != nil {
		return 0, fmt.Errorf("error starting sandbox: %v", err)
	}
	return s.Wait()
}

// Load loads a sandbox from with the given id from a metadata file.
func Load(rootDir, id string) (*Sandbox, error) {
	log.Debugf("Load sandbox %q %q", rootDir, id)
	if err := validateID(id); err != nil {
		return nil, err
	}
	sandboxRoot := filepath.Join(rootDir, id)
	if !exists(sandboxRoot) {
		return nil, fmt.Errorf("sandbox with id %q does not exist", id)
	}
	metaFile := filepath.Join(sandboxRoot, metadataFilename)
	if !exists(metaFile) {
		return nil, fmt.Errorf("sandbox with id %q does not have metadata file %q", id, metaFile)
	}
	metaBytes, err := ioutil.ReadFile(metaFile)
	if err != nil {
		return nil, fmt.Errorf("error reading sandbox metadata file %q: %v", metaFile, err)
	}
	var s Sandbox
	if err := json.Unmarshal(metaBytes, &s); err != nil {
		return nil, fmt.Errorf("error unmarshaling sandbox metadata from %q: %v", metaFile, err)
	}

	// If the status is "Running" or "Created", check that the process
	// still exists, and set it to Stopped if it does not.
	//
	// This is inherently racey.
	if s.Status == Running || s.Status == Created {
		// Send signal 0 to check if process exists.
		if err := s.Signal(0); err != nil {
			// Process no longer exists.
			s.Status = Stopped
			s.Pid = 0
		}
	}

	return &s, nil
}

// List returns all sandbox ids in the given root directory.
func List(rootDir string) ([]string, error) {
	log.Debugf("List sandboxes %q", rootDir)
	fs, err := ioutil.ReadDir(rootDir)
	if err != nil {
		return nil, fmt.Errorf("ReadDir(%s) failed: %v", rootDir, err)
	}
	var out []string
	for _, f := range fs {
		out = append(out, f.Name())
	}
	return out, nil
}

// State returns the metadata of the sandbox.
func (s *Sandbox) State() specs.State {
	return specs.State{
		Version: specs.Version,
		ID:      s.ID,
		Status:  s.Status.String(),
		Pid:     s.Pid,
		Bundle:  s.BundleDir,
	}
}

// Start starts running the containerized process inside the sandbox.
func (s *Sandbox) Start(conf *boot.Config) error {
	log.Debugf("Start sandbox %q, pid: %d", s.ID, s.Pid)
	if s.Status != Created {
		return fmt.Errorf("cannot start container in state %s", s.Status)
	}

	// "If any prestart hook fails, the runtime MUST generate an error,
	// stop and destroy the container".
	if s.Spec.Hooks != nil {
		if err := executeHooks(s.Spec.Hooks.Prestart, s.State()); err != nil {
			s.Destroy()
			return err
		}
	}

	c, err := s.connect()
	if err != nil {
		s.Destroy()
		return err
	}
	defer c.Close()

	// Configure the network.
	if err := setupNetwork(c, s.Pid, s.Spec, conf); err != nil {
		s.Destroy()
		return fmt.Errorf("error setting up network: %v", err)
	}

	// Send a message to the sandbox control server to start the
	// application.
	if err := c.Call(boot.ApplicationStart, nil, nil); err != nil {
		s.Destroy()
		return fmt.Errorf("error starting application %v: %v", s.Spec.Process.Args, err)
	}

	// "If any poststart hook fails, the runtime MUST log a warning, but
	// the remaining hooks and lifecycle continue as if the hook had
	// succeeded".
	if s.Spec.Hooks != nil {
		executeHooksBestEffort(s.Spec.Hooks.Poststart, s.State())
	}

	s.Status = Running
	return s.save()
}

// Processes retrieves the list of processes and associated metadata inside a
// sandbox.
func (s *Sandbox) Processes() ([]*control.Process, error) {
	if s.Status != Running {
		return nil, fmt.Errorf("cannot get processes of container %q because it isn't running. It is in state %v", s.ID, s.Status)
	}

	c, err := s.connect()
	if err != nil {
		return nil, err
	}
	defer c.Close()

	var pl []*control.Process
	if err := c.Call(boot.ApplicationProcesses, nil, &pl); err != nil {
		return nil, fmt.Errorf("error retrieving process data from sandbox: %v", err)
	}
	return pl, nil
}

// Execute runs the specified command in the sandbox.
func (s *Sandbox) Execute(e *control.ExecArgs) (syscall.WaitStatus, error) {
	log.Debugf("Execute in sandbox %q, pid: %d, args: %+v", s.ID, s.Pid, e)
	if s.Status != Created && s.Status != Running {
		return 0, fmt.Errorf("cannot exec in container in state %s", s.Status)
	}

	log.Debugf("Connecting to sandbox...")
	c, err := s.connect()
	if err != nil {
		return 0, fmt.Errorf("error connecting to control server at pid %d: %v", s.Pid, err)
	}
	defer c.Close()

	// Send a message to the sandbox control server to start the application.
	var waitStatus uint32
	if err := c.Call(boot.ApplicationExecute, e, &waitStatus); err != nil {
		return 0, fmt.Errorf("error executing in sandbox: %v", err)
	}

	return syscall.WaitStatus(waitStatus), nil
}

// Event retrieves stats about the sandbox such as memory and CPU utilization.
func (s *Sandbox) Event() (*boot.Event, error) {
	if s.Status != Running && s.Status != Created {
		return nil, fmt.Errorf("cannot get events for container in state: %s", s.Status)
	}

	c, err := s.connect()
	if err != nil {
		return nil, err
	}
	defer c.Close()

	var e boot.Event
	if err := c.Call(boot.ApplicationEvent, nil, &e); err != nil {
		return nil, fmt.Errorf("error retrieving event data from sandbox: %v", err)
	}
	e.ID = s.ID
	return &e, nil
}

func (s *Sandbox) connect() (*urpc.Client, error) {
	log.Debugf("Connecting to sandbox...")
	c, err := client.ConnectTo(boot.ControlSocketAddr(s.ID))
	if err != nil {
		return nil, fmt.Errorf("error connecting to control server at pid %d: %v", s.Pid, err)
	}
	return c, nil
}

func (s *Sandbox) createProcesses(conf *boot.Config, args []string) error {
	binPath, err := specutils.BinPath()
	if err != nil {
		return err
	}

	ioFiles, err := s.createGoferProcess(conf, binPath, args)
	if err != nil {
		return err
	}
	return s.createSandboxProcess(conf, binPath, args, ioFiles)
}

func (s *Sandbox) createGoferProcess(conf *boot.Config, binPath string, commonArgs []string) ([]*os.File, error) {
	if conf.FileAccess != boot.FileAccessProxy {
		// Don't start a gofer. The sandbox will access host FS directly.
		return nil, nil
	}

	var args []string
	args = append(args, commonArgs...)
	args = append(args, "gofer", "--bundle", s.BundleDir)

	// Start with root mount and then add any other additional mount.
	mountCount := 1
	for _, m := range s.Spec.Mounts {
		if specutils.Is9PMount(m) {
			mountCount++
		}
	}

	sandEnds := make([]*os.File, 0, mountCount)
	goferEnds := make([]*os.File, 0, mountCount)
	for i := 0; i < mountCount; i++ {
		// Create socket that connects the sandbox and gofer.
		fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
		if err != nil {
			return nil, err
		}
		sandEnds = append(sandEnds, os.NewFile(uintptr(fds[0]), "sandbox io fd"))

		goferEnd := os.NewFile(uintptr(fds[1]), "gofer io fd")
		defer goferEnd.Close()
		goferEnds = append(goferEnds, goferEnd)

		args = append(args, fmt.Sprintf("--io-fds=%d", 3+i))
	}

	cmd := exec.Command(binPath, args...)
	cmd.ExtraFiles = goferEnds

	// Setup any uid/gid mappings, and create or join the configured user
	// namespace so the gofer's view of the filesystem aligns with the
	// users in the sandbox.
	setUIDGIDMappings(cmd, s.Spec)
	nss := filterNS([]specs.LinuxNamespaceType{specs.UserNamespace}, s.Spec)

	// Start the gofer in the given namespace.
	log.Debugf("Starting gofer: %s %v", binPath, args)
	if err := startInNS(cmd, nss); err != nil {
		return nil, err
	}
	s.GoferPid = cmd.Process.Pid
	log.Infof("Gofer started, pid: %d", cmd.Process.Pid)
	return sandEnds, nil
}

// createSandboxProcess starts the sandbox as a subprocess by running the "boot"
// command, passing in the bundle dir.
func (s *Sandbox) createSandboxProcess(conf *boot.Config, binPath string, commonArgs []string, ioFiles []*os.File) error {
	// nextFD is used to get unused FDs that we can pass to the sandbox.  It
	// starts at 3 because 0, 1, and 2 are taken by stdin/out/err.
	nextFD := 3

	// Create control server socket here and donate FD to child process because
	// it may be in a different network namespace and won't be reachable from
	// outside.
	fd, err := server.CreateSocket(boot.ControlSocketAddr(s.ID))
	if err != nil {
		return fmt.Errorf("error creating control server socket for sandbox %q: %v", s.ID, err)
	}

	consoleEnabled := s.ConsoleSocket != ""

	cmd := exec.Command(binPath, commonArgs...)
	cmd.SysProcAttr = &syscall.SysProcAttr{}
	cmd.Args = append(cmd.Args,
		"boot",
		"--bundle", s.BundleDir,
		"--controller-fd="+strconv.Itoa(nextFD),
		fmt.Sprintf("--console=%t", consoleEnabled))
	nextFD++

	controllerFile := os.NewFile(uintptr(fd), "control_server_socket")
	defer controllerFile.Close()
	cmd.ExtraFiles = append(cmd.ExtraFiles, controllerFile)

	// If there is a gofer, sends all socket ends to the sandbox.
	for _, f := range ioFiles {
		defer f.Close()
		cmd.ExtraFiles = append(cmd.ExtraFiles, f)
		cmd.Args = append(cmd.Args, "--io-fds="+strconv.Itoa(nextFD))
		nextFD++
	}

	// If the console control socket file is provided, then create a new
	// pty master/slave pair and set the tty on the sandox process.
	if consoleEnabled {
		// setupConsole will send the master on the socket, and return
		// the slave.
		tty, err := setupConsole(s.ConsoleSocket)
		if err != nil {
			return fmt.Errorf("error setting up control socket %q: %v", s.ConsoleSocket, err)
		}
		defer tty.Close()

		cmd.Stdin = tty
		cmd.Stdout = tty
		cmd.Stderr = tty
		cmd.SysProcAttr.Setctty = true
		cmd.SysProcAttr.Ctty = int(tty.Fd())
	} else {
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
	}

	// Detach from this session, otherwise cmd will get SIGHUP and SIGCONT
	// when re-parented.
	cmd.SysProcAttr.Setsid = true

	// nss is the set of namespaces to join or create before starting the sandbox
	// process. IPC and UTS namespaces from the host are not used as they
	// are virtualized inside the sandbox. Be paranoid and run inside an empty
	// namespace for these.
	log.Infof("Sandbox will be started in empty IPC and UTS namespaces")
	nss := []specs.LinuxNamespace{
		{Type: specs.IPCNamespace},
		{Type: specs.UTSNamespace},
	}

	if conf.Platform == boot.PlatformPtrace {
		// TODO: Also set an empty PID namespace so that we limit
		// access to other host processes.
		log.Infof("Sandbox will be started in the current PID namespace")
	} else {
		log.Infof("Sandbox will be started in empty PID namespace")
		nss = append(nss, specs.LinuxNamespace{Type: specs.PIDNamespace})
	}

	if conf.FileAccess == boot.FileAccessProxy {
		log.Infof("Sandbox will be started in empty mount namespace")
		nss = append(nss, specs.LinuxNamespace{Type: specs.MountNamespace})
	} else {
		log.Infof("Sandbox will be started in the current mount namespace")
	}

	// Joins the network namespace if network is enabled. the sandbox talks
	// directly to the host network, which may have been configured in the
	// namespace.
	if ns, ok := getNS(specs.NetworkNamespace, s.Spec); ok && conf.Network != boot.NetworkNone {
		log.Infof("Sandbox will be started in the container's network namespace: %+v", ns)
		nss = append(nss, ns)
	} else {
		log.Infof("Sandbox will be started in empty network namespace")
		nss = append(nss, specs.LinuxNamespace{Type: specs.NetworkNamespace})
	}

	// User namespace depends on the following options:
	//   - Host network/filesystem: requires to run inside the user namespace
	//       specified in the spec or the current namespace if none is configured.
	//   - Gofer: when using a Gofer, the sandbox process can run isolated in an
	//       empty namespace.
	if conf.Network == boot.NetworkHost || conf.FileAccess == boot.FileAccessDirect {
		if userns, ok := getNS(specs.UserNamespace, s.Spec); ok {
			log.Infof("Sandbox will be started in container's user namespace: %+v", userns)
			nss = append(nss, userns)
			setUIDGIDMappings(cmd, s.Spec)
		} else {
			log.Infof("Sandbox will be started in the current user namespace")
		}
		// When running in the caller's defined user namespace, apply the same
		// capabilities to the sandbox process to ensure it abides to the same
		// rules.
		cmd.Args = append(cmd.Args, "--apply-caps=true")

	} else {
		log.Infof("Sandbox will be started in empty user namespace")
		nss = append(nss, specs.LinuxNamespace{Type: specs.UserNamespace})
	}

	log.Debugf("Starting sandbox: %s %v", binPath, cmd.Args)
	if err := startInNS(cmd, nss); err != nil {
		return err
	}
	s.Pid = cmd.Process.Pid
	log.Infof("Sandbox started, pid: %d", s.Pid)
	return nil
}

// waitForCreated waits for the sandbox subprocess control server to be
// running, at which point the sandbox is in Created state.
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
	return nil
}

// Wait waits for the containerized process to exit, and returns its WaitStatus.
func (s *Sandbox) Wait() (syscall.WaitStatus, error) {
	log.Debugf("Wait on sandbox %q with pid %d", s.ID, s.Pid)
	p, err := os.FindProcess(s.Pid)
	if err != nil {
		// "On Unix systems, FindProcess always succeeds and returns a
		// Process for the given pid."
		panic(err)
	}
	ps, err := p.Wait()
	if err != nil {
		return 0, err
	}
	return ps.Sys().(syscall.WaitStatus), nil
}

// Destroy frees all resources associated with the sandbox.
func (s *Sandbox) Destroy() error {
	log.Debugf("Destroy sandbox %q", s.ID)
	if s.Pid != 0 {
		// TODO: Too harsh?
		log.Debugf("Killing sandbox %q", s.ID)
		sendSignal(s.Pid, unix.SIGKILL)
		s.Pid = 0
	}
	if s.GoferPid != 0 {
		log.Debugf("Killing gofer for sandbox %q", s.ID)
		sendSignal(s.GoferPid, unix.SIGKILL)
		s.GoferPid = 0
	}
	if err := os.RemoveAll(s.SandboxRoot); err != nil {
		log.Warningf("Failed to delete sandbox root directory %q, err: %v", s.SandboxRoot, err)
	}

	// "If any poststop hook fails, the runtime MUST log a warning, but the
	// remaining hooks and lifecycle continue as if the hook had succeeded".
	if s.Spec.Hooks != nil && (s.Status == Created || s.Status == Running) {
		executeHooksBestEffort(s.Spec.Hooks.Poststop, s.State())
	}

	s.Status = Stopped
	return nil
}

// Signal sends the signal to the sandbox.
func (s *Sandbox) Signal(sig syscall.Signal) error {
	log.Debugf("Signal sandbox %q", s.ID)
	if s.Status == Stopped {
		log.Warningf("sandbox %q not running, not sending signal %v to pid %d", s.ID, sig, s.Pid)
		return nil
	}
	return sendSignal(s.Pid, sig)
}

func sendSignal(pid int, sig syscall.Signal) error {
	if err := syscall.Kill(pid, sig); err != nil {
		return fmt.Errorf("error sending signal %d to pid %d: %v", sig, pid, err)
	}
	return nil
}

// save saves the sandbox metadata to a file.
func (s *Sandbox) save() error {
	log.Debugf("Save sandbox %q", s.ID)
	if err := os.MkdirAll(s.SandboxRoot, 0711); err != nil {
		return fmt.Errorf("error creating sandbox root directory %q: %v", s.SandboxRoot, err)
	}
	meta, err := json.Marshal(s)
	if err != nil {
		return fmt.Errorf("error marshaling sandbox metadata: %v", err)
	}
	metaFile := filepath.Join(s.SandboxRoot, metadataFilename)
	if err := ioutil.WriteFile(metaFile, meta, 0640); err != nil {
		return fmt.Errorf("error writing sandbox metadata: %v", err)
	}
	return nil
}

// exists returns true if the given file exists.
func exists(f string) bool {
	if _, err := os.Stat(f); err == nil {
		return true
	} else if !os.IsNotExist(err) {
		log.Warningf("error checking for file %q: %v", f, err)
	}
	return false
}

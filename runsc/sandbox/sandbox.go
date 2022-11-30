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

// Package sandbox creates and manipulates sandboxes.
package sandbox

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/cenkalti/backoff"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/syndtr/gocapability/capability"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/atomicbitops"
	"gvisor.dev/gvisor/pkg/cleanup"
	"gvisor.dev/gvisor/pkg/control/client"
	"gvisor.dev/gvisor/pkg/control/server"
	"gvisor.dev/gvisor/pkg/coverage"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/control"
	"gvisor.dev/gvisor/pkg/sentry/platform"
	"gvisor.dev/gvisor/pkg/sentry/seccheck"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/urpc"
	"gvisor.dev/gvisor/runsc/boot"
	"gvisor.dev/gvisor/runsc/boot/procfs"
	"gvisor.dev/gvisor/runsc/cgroup"
	"gvisor.dev/gvisor/runsc/config"
	"gvisor.dev/gvisor/runsc/console"
	"gvisor.dev/gvisor/runsc/donation"
	"gvisor.dev/gvisor/runsc/specutils"
)

// pid is an atomic type that implements JSON marshal/unmarshal interfaces.
type pid struct {
	val atomicbitops.Int64
}

func (p *pid) store(pid int) {
	p.val.Store(int64(pid))
}

func (p *pid) load() int {
	return int(p.val.Load())
}

// UnmarshalJSON implements json.Unmarshaler.UnmarshalJSON.
func (p *pid) UnmarshalJSON(b []byte) error {
	var pid int

	if err := json.Unmarshal(b, &pid); err != nil {
		return err
	}
	p.store(pid)
	return nil
}

// MarshalJSON implements json.Marshaler.MarshalJSON
func (p *pid) MarshalJSON() ([]byte, error) {
	return json.Marshal(p.load())
}

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

	// Pid is the pid of the running sandbox. May be 0 if the sandbox
	// is not running.
	Pid pid `json:"pid"`

	// UID is the user ID in the parent namespace that the sandbox is running as.
	UID int `json:"uid"`
	// GID is the group ID in the parent namespace that the sandbox is running as.
	GID int `json:"gid"`

	// CgroupJSON contains the cgroup configuration that the sandbox is part of
	// and allow serialization of the configuration into json
	CgroupJSON cgroup.CgroupJSON `json:"cgroup"`

	// OriginalOOMScoreAdj stores the value of oom_score_adj when the sandbox
	// started, before it may be modified.
	OriginalOOMScoreAdj int `json:"originalOomScoreAdj"`

	// child is set if a sandbox process is a child of the current process.
	//
	// This field isn't saved to json, because only a creator of sandbox
	// will have it as a child process.
	child bool

	// statusMu protects status.
	statusMu sync.Mutex

	// status is the exit status of a sandbox process. It's only set if the
	// child==true and the sandbox was waited on. This field allows for multiple
	// threads to wait on sandbox and get the exit code, since Linux will return
	// WaitStatus to one of the waiters only.
	status unix.WaitStatus
}

// Getpid returns the process ID of the sandbox process.
func (s *Sandbox) Getpid() int {
	return s.Pid.load()
}

// Args is used to configure a new sandbox.
type Args struct {
	// ID is the sandbox unique identifier.
	ID string

	// Spec is the OCI spec that describes the container.
	Spec *specs.Spec

	// BundleDir is the directory containing the container bundle.
	BundleDir string

	// ConsoleSocket is the path to a unix domain socket that will receive
	// the console FD. It may be empty.
	ConsoleSocket string

	// UserLog is the filename to send user-visible logs to. It may be empty.
	UserLog string

	// IOFiles is the list of files that connect to a gofer endpoint for the
	// mounts points using Gofers. They must be in the same order as mounts
	// appear in the spec.
	IOFiles []*os.File

	// OverlayFilestoreFile is the regular file that will back the tmpfs upper
	// mount in the overlay mounts.
	OverlayFilestoreFile *os.File

	// MountsFile is a file container mount information from the spec. It's
	// equivalent to the mounts from the spec, except that all paths have been
	// resolved to their final absolute location.
	MountsFile *os.File

	// Gcgroup is the cgroup that the sandbox is part of.
	Cgroup cgroup.Cgroup

	// Attached indicates that the sandbox lifecycle is attached with the caller.
	// If the caller exits, the sandbox should exit too.
	Attached bool

	// SinkFiles is the an ordered array of files to be used by seccheck sinks
	// configured from the --pod-init-config file.
	SinkFiles []*os.File
}

// New creates the sandbox process. The caller must call Destroy() on the
// sandbox.
func New(conf *config.Config, args *Args) (*Sandbox, error) {
	s := &Sandbox{
		ID: args.ID,
		CgroupJSON: cgroup.CgroupJSON{
			Cgroup: args.Cgroup,
		},
		UID: -1, // prevent usage before it's set.
		GID: -1, // prevent usage before it's set.
	}
	// The Cleanup object cleans up partially created sandboxes when an error
	// occurs. Any errors occurring during cleanup itself are ignored.
	c := cleanup.Make(func() {
		if err := s.destroy(); err != nil {
			log.Warningf("error destroying sandbox: %v", err)
		}
	})
	defer c.Clean()

	if len(conf.PodInitConfig) > 0 {
		initConf, err := boot.LoadInitConfig(conf.PodInitConfig)
		if err != nil {
			return nil, fmt.Errorf("loading init config file: %w", err)
		}
		args.SinkFiles, err = initConf.Setup()
		if err != nil {
			return nil, fmt.Errorf("cannot init config: %w", err)
		}
	}

	// Create pipe to synchronize when sandbox process has been booted.
	clientSyncFile, sandboxSyncFile, err := os.Pipe()
	if err != nil {
		return nil, fmt.Errorf("creating pipe for sandbox %q: %v", s.ID, err)
	}
	defer clientSyncFile.Close()

	// Create the sandbox process.
	err = s.createSandboxProcess(conf, args, sandboxSyncFile)
	// sandboxSyncFile has to be closed to be able to detect when the sandbox
	// process exits unexpectedly.
	sandboxSyncFile.Close()
	if err != nil {
		return nil, fmt.Errorf("cannot create sandbox process: %w", err)
	}

	// Wait until the sandbox has booted.
	b := make([]byte, 1)
	if l, err := clientSyncFile.Read(b); err != nil || l != 1 {
		err := fmt.Errorf("waiting for sandbox to start: %v", err)
		// If the sandbox failed to start, it may be because the binary
		// permissions were incorrect. Check the bits and return a more helpful
		// error message.
		//
		// NOTE: The error message is checked because error types are lost over
		// rpc calls.
		if strings.Contains(err.Error(), io.EOF.Error()) {
			if permsErr := checkBinaryPermissions(conf); permsErr != nil {
				return nil, fmt.Errorf("%v: %v", err, permsErr)
			}
		}
		return nil, fmt.Errorf("cannot read client sync file: %w", err)
	}

	c.Release()
	return s, nil
}

// CreateSubcontainer creates a container inside the sandbox.
func (s *Sandbox) CreateSubcontainer(conf *config.Config, cid string, tty *os.File) error {
	log.Debugf("Create sub-container %q in sandbox %q, PID: %d", cid, s.ID, s.Pid.load())

	var files []*os.File
	if tty != nil {
		files = []*os.File{tty}
	}
	if err := s.configureStdios(conf, files); err != nil {
		return err
	}

	sandboxConn, err := s.sandboxConnect()
	if err != nil {
		return fmt.Errorf("couldn't connect to sandbox: %v", err)
	}
	defer sandboxConn.Close()

	args := boot.CreateArgs{
		CID:         cid,
		FilePayload: urpc.FilePayload{Files: files},
	}
	if err := sandboxConn.Call(boot.ContMgrCreateSubcontainer, &args, nil); err != nil {
		return fmt.Errorf("creating sub-container %q: %v", cid, err)
	}
	return nil
}

// StartRoot starts running the root container process inside the sandbox.
func (s *Sandbox) StartRoot(spec *specs.Spec, conf *config.Config) error {
	pid := s.Pid.load()
	log.Debugf("Start root sandbox %q, PID: %d", s.ID, pid)
	conn, err := s.sandboxConnect()
	if err != nil {
		return err
	}
	defer conn.Close()

	// Configure the network.
	if err := setupNetwork(conn, pid, conf); err != nil {
		return fmt.Errorf("setting up network: %v", err)
	}

	// Send a message to the sandbox control server to start the root
	// container.
	if err := conn.Call(boot.ContMgrRootContainerStart, &s.ID, nil); err != nil {
		return fmt.Errorf("starting root container: %v", err)
	}

	return nil
}

// StartSubcontainer starts running a sub-container inside the sandbox.
func (s *Sandbox) StartSubcontainer(spec *specs.Spec, conf *config.Config, cid string, stdios, goferFiles []*os.File) error {
	log.Debugf("Start sub-container %q in sandbox %q, PID: %d", cid, s.ID, s.Pid.load())

	if err := s.configureStdios(conf, stdios); err != nil {
		return err
	}

	sandboxConn, err := s.sandboxConnect()
	if err != nil {
		return fmt.Errorf("couldn't connect to sandbox: %v", err)
	}
	defer sandboxConn.Close()

	// The payload must contain stdin/stdout/stderr (which may be empty if using
	// TTY) followed by gofer files.
	payload := urpc.FilePayload{}
	payload.Files = append(payload.Files, stdios...)
	payload.Files = append(payload.Files, goferFiles...)

	// Start running the container.
	args := boot.StartArgs{
		Spec:        spec,
		Conf:        conf,
		CID:         cid,
		FilePayload: payload,
	}
	if err := sandboxConn.Call(boot.ContMgrStartSubcontainer, &args, nil); err != nil {
		return fmt.Errorf("starting sub-container %v: %v", spec.Process.Args, err)
	}
	return nil
}

// Restore sends the restore call for a container in the sandbox.
func (s *Sandbox) Restore(cid string, spec *specs.Spec, conf *config.Config, filename string) error {
	log.Debugf("Restore sandbox %q", s.ID)

	rf, err := os.Open(filename)
	if err != nil {
		return fmt.Errorf("opening restore file %q failed: %v", filename, err)
	}
	defer rf.Close()

	opt := boot.RestoreOpts{
		FilePayload: urpc.FilePayload{
			Files: []*os.File{rf},
		},
		SandboxID: s.ID,
	}

	// If the platform needs a device FD we must pass it in.
	if deviceFile, err := deviceFileForPlatform(conf.Platform, conf.PlatformDevicePath); err != nil {
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
	if err := setupNetwork(conn, s.Pid.load(), conf); err != nil {
		return fmt.Errorf("setting up network: %v", err)
	}

	// Restore the container and start the root container.
	if err := conn.Call(boot.ContMgrRestore, &opt, nil); err != nil {
		return fmt.Errorf("restoring container %q: %v", cid, err)
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
	if err := conn.Call(boot.ContMgrProcesses, &cid, &pl); err != nil {
		return nil, fmt.Errorf("retrieving process data from sandbox: %v", err)
	}
	return pl, nil
}

// CreateTraceSession creates a new trace session.
func (s *Sandbox) CreateTraceSession(config *seccheck.SessionConfig, force bool) error {
	log.Debugf("Creating trace session in sandbox %q", s.ID)

	sinkFiles, err := seccheck.SetupSinks(config.Sinks)
	if err != nil {
		return err
	}
	defer func() {
		for _, f := range sinkFiles {
			_ = f.Close()
		}
	}()

	conn, err := s.sandboxConnect()
	if err != nil {
		return err
	}
	defer conn.Close()

	arg := boot.CreateTraceSessionArgs{
		Config: *config,
		Force:  force,
		FilePayload: urpc.FilePayload{
			Files: sinkFiles,
		},
	}
	if err := conn.Call(boot.ContMgrCreateTraceSession, &arg, nil); err != nil {
		return fmt.Errorf("creating trace session: %w", err)
	}
	return nil
}

// DeleteTraceSession deletes an existing trace session.
func (s *Sandbox) DeleteTraceSession(name string) error {
	log.Debugf("Deleting trace session %q in sandbox %q", name, s.ID)
	conn, err := s.sandboxConnect()
	if err != nil {
		return err
	}
	defer conn.Close()

	if err := conn.Call(boot.ContMgrDeleteTraceSession, name, nil); err != nil {
		return fmt.Errorf("deleting trace session: %w", err)
	}
	return nil
}

// ListTraceSessions lists all trace sessions.
func (s *Sandbox) ListTraceSessions() ([]seccheck.SessionConfig, error) {
	log.Debugf("Listing trace sessions in sandbox %q", s.ID)
	conn, err := s.sandboxConnect()
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	var sessions []seccheck.SessionConfig
	if err := conn.Call(boot.ContMgrListTraceSessions, nil, &sessions); err != nil {
		return nil, fmt.Errorf("listing trace session: %w", err)
	}
	return sessions, nil
}

// ProcfsDump collects and returns a procfs dump for the sandbox.
func (s *Sandbox) ProcfsDump() ([]procfs.ProcessProcfsDump, error) {
	log.Debugf("Procfs dump %q", s.ID)
	conn, err := s.sandboxConnect()
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	var procfsDump []procfs.ProcessProcfsDump
	if err := conn.Call(boot.ContMgrProcfsDump, nil, &procfsDump); err != nil {
		return nil, fmt.Errorf("getting sandbox %q stacks: %v", s.ID, err)
	}
	return procfsDump, nil
}

// NewCGroup returns the sandbox's Cgroup, or an error if it does not have one.
func (s *Sandbox) NewCGroup() (cgroup.Cgroup, error) {
	return cgroup.NewFromPid(s.Pid.load(), false /* useSystemd */)
}

// Execute runs the specified command in the container. It returns the PID of
// the newly created process.
func (s *Sandbox) Execute(conf *config.Config, args *control.ExecArgs) (int32, error) {
	log.Debugf("Executing new process in container %q in sandbox %q", args.ContainerID, s.ID)

	if err := s.configureStdios(conf, args.Files); err != nil {
		return 0, err
	}

	conn, err := s.sandboxConnect()
	if err != nil {
		return 0, s.connError(err)
	}
	defer conn.Close()

	// Send a message to the sandbox control server to start the container.
	var pid int32
	if err := conn.Call(boot.ContMgrExecuteAsync, args, &pid); err != nil {
		return 0, fmt.Errorf("executing command %q in sandbox: %v", args, err)
	}
	return pid, nil
}

// Event retrieves stats about the sandbox such as memory and CPU utilization.
func (s *Sandbox) Event(cid string) (*boot.EventOut, error) {
	log.Debugf("Getting events for container %q in sandbox %q", cid, s.ID)
	conn, err := s.sandboxConnect()
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	var e boot.EventOut
	// TODO(b/129292330): Pass in the container id (cid) here. The sandbox
	// should return events only for that container.
	if err := conn.Call(boot.ContMgrEvent, nil, &e); err != nil {
		return nil, fmt.Errorf("retrieving event data from sandbox: %v", err)
	}
	e.Event.ID = cid
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
	return fmt.Errorf("connecting to control server at PID %d: %v", s.Pid.load(), err)
}

// createSandboxProcess starts the sandbox as a subprocess by running the "boot"
// command, passing in the bundle dir.
func (s *Sandbox) createSandboxProcess(conf *config.Config, args *Args, startSyncFile *os.File) error {
	donations := donation.Agency{}
	defer donations.Close()

	//
	// These flags must come BEFORE the "boot" command in cmd.Args.
	//

	// Open the log files to pass to the sandbox as FDs.
	if err := donations.OpenAndDonate("log-fd", conf.LogFilename, os.O_CREATE|os.O_WRONLY|os.O_APPEND); err != nil {
		return err
	}

	test := ""
	if len(conf.TestOnlyTestNameEnv) != 0 {
		// Fetch test name if one is provided and the test only flag was set.
		if t, ok := specutils.EnvVar(args.Spec.Process.Env, conf.TestOnlyTestNameEnv); ok {
			test = t
		}
	}
	if specutils.IsDebugCommand(conf, "boot") {
		if err := donations.DonateDebugLogFile("debug-log-fd", conf.DebugLog, "boot", test); err != nil {
			return err
		}
	}
	if err := donations.DonateDebugLogFile("panic-log-fd", conf.PanicLog, "panic", test); err != nil {
		return err
	}
	covFilename := conf.CoverageReport
	if covFilename == "" {
		covFilename = os.Getenv("GO_COVERAGE_FILE")
	}
	if covFilename != "" && coverage.Available() {
		if err := donations.DonateDebugLogFile("coverage-fd", covFilename, "cov", test); err != nil {
			return err
		}
	}

	// Relay all the config flags to the sandbox process.
	cmd := exec.Command(specutils.ExePath, conf.ToFlags()...)
	cmd.SysProcAttr = &unix.SysProcAttr{
		// Detach from this session, otherwise cmd will get SIGHUP and SIGCONT
		// when re-parented.
		Setsid: true,
	}

	// Set Args[0] to make easier to spot the sandbox process. Otherwise it's
	// shown as `exe`.
	cmd.Args[0] = "runsc-sandbox"

	// Tranfer FDs that need to be present before the "boot" command.
	// Start at 3 because 0, 1, and 2 are taken by stdin/out/err.
	nextFD := donations.Transfer(cmd, 3)

	// Add the "boot" command to the args.
	//
	// All flags after this must be for the boot command
	cmd.Args = append(cmd.Args, "boot", "--bundle="+args.BundleDir)

	// If there is a gofer, sends all socket ends to the sandbox.
	donations.DonateAndClose("io-fds", args.IOFiles...)
	donations.DonateAndClose("overlay-filestore-fd", args.OverlayFilestoreFile)
	donations.DonateAndClose("mounts-fd", args.MountsFile)
	donations.Donate("start-sync-fd", startSyncFile)
	if err := donations.OpenAndDonate("user-log-fd", args.UserLog, os.O_CREATE|os.O_WRONLY|os.O_APPEND); err != nil {
		return err
	}
	const profFlags = os.O_CREATE | os.O_WRONLY | os.O_TRUNC
	if err := donations.OpenAndDonate("profile-block-fd", conf.ProfileBlock, profFlags); err != nil {
		return err
	}
	if err := donations.OpenAndDonate("profile-cpu-fd", conf.ProfileCPU, profFlags); err != nil {
		return err
	}
	if err := donations.OpenAndDonate("profile-heap-fd", conf.ProfileHeap, profFlags); err != nil {
		return err
	}
	if err := donations.OpenAndDonate("profile-mutex-fd", conf.ProfileMutex, profFlags); err != nil {
		return err
	}
	if err := donations.OpenAndDonate("trace-fd", conf.TraceFile, profFlags); err != nil {
		return err
	}

	// Create a socket for the control server and donate it to the sandbox.
	addr := boot.ControlSocketAddr(s.ID)
	sockFD, err := server.CreateSocket(addr)
	log.Infof("Creating sandbox process with addr: %s", addr[1:]) // skip "\00".
	if err != nil {
		return fmt.Errorf("creating control server socket for sandbox %q: %v", s.ID, err)
	}
	donations.DonateAndClose("controller-fd", os.NewFile(uintptr(sockFD), "control_server_socket"))

	specFile, err := specutils.OpenSpec(args.BundleDir)
	if err != nil {
		return fmt.Errorf("cannot open spec file in bundle dir %v: %w", args.BundleDir, err)
	}
	donations.DonateAndClose("spec-fd", specFile)

	if err := donations.OpenAndDonate("pod-init-config-fd", conf.PodInitConfig, os.O_RDONLY); err != nil {
		return err
	}
	donations.DonateAndClose("sink-fds", args.SinkFiles...)

	gPlatform, err := platform.Lookup(conf.Platform)
	if err != nil {
		return fmt.Errorf("cannot look up platform: %w", err)
	}
	if deviceFile, err := gPlatform.OpenDevice(conf.PlatformDevicePath); err != nil {
		return fmt.Errorf("opening device file for platform %q: %v", conf.Platform, err)
	} else if deviceFile != nil {
		donations.DonateAndClose("device-fd", deviceFile)
	}

	// TODO(b/151157106): syscall tests fail by timeout if asyncpreemptoff
	// isn't set.
	if conf.Platform == "kvm" {
		cmd.Env = append(cmd.Env, "GODEBUG=asyncpreemptoff=1")
	}

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

	if gPlatform.Requirements().RequiresCurrentPIDNS {
		// TODO(b/75837838): Also set a new PID namespace so that we limit
		// access to other host processes.
		log.Infof("Sandbox will be started in the current PID namespace")
	} else {
		log.Infof("Sandbox will be started in a new PID namespace")
		nss = append(nss, specs.LinuxNamespace{Type: specs.PIDNamespace})
		cmd.Args = append(cmd.Args, "--pidns=true")
	}

	// Joins the network namespace if network is enabled. the sandbox talks
	// directly to the host network, which may have been configured in the
	// namespace.
	if ns, ok := specutils.GetNS(specs.NetworkNamespace, args.Spec); ok && conf.Network != config.NetworkNone {
		log.Infof("Sandbox will be started in the container's network namespace: %+v", ns)
		nss = append(nss, ns)
	} else if conf.Network == config.NetworkHost {
		log.Infof("Sandbox will be started in the host network namespace")
	} else {
		log.Infof("Sandbox will be started in new network namespace")
		nss = append(nss, specs.LinuxNamespace{Type: specs.NetworkNamespace})
	}

	// These are set to the uid/gid that the sandbox process will use. May be
	// overriden below.
	s.UID = os.Getuid()
	s.GID = os.Getgid()

	// User namespace depends on the network type. Host network requires to run
	// inside the user namespace specified in the spec or the current namespace
	// if none is configured.
	if conf.Network == config.NetworkHost {
		if userns, ok := specutils.GetNS(specs.UserNamespace, args.Spec); ok {
			log.Infof("Sandbox will be started in container's user namespace: %+v", userns)
			nss = append(nss, userns)
			specutils.SetUIDGIDMappings(cmd, args.Spec)
		} else {
			log.Infof("Sandbox will be started in the current user namespace")
		}
		// When running in the caller's defined user namespace, apply the same
		// capabilities to the sandbox process to ensure it abides to the same
		// rules.
		cmd.Args = append(cmd.Args, "--apply-caps=true")

		// If we have CAP_SYS_ADMIN, we can create an empty chroot and
		// bind-mount the executable inside it.
		if conf.TestOnlyAllowRunAsCurrentUserWithoutChroot {
			log.Warningf("Running sandbox in test mode without chroot. This is only safe in tests!")

		} else if specutils.HasCapabilities(capability.CAP_SYS_ADMIN) {
			log.Infof("Sandbox will be started in minimal chroot")
			cmd.Args = append(cmd.Args, "--setup-root")
		} else {
			return fmt.Errorf("can't run sandbox process in minimal chroot since we don't have CAP_SYS_ADMIN")
		}
	} else {
		rootlessEUID := unix.Getuid() != 0
		// If we have CAP_SETUID and CAP_SETGID, then we can also run
		// as user nobody.
		if conf.TestOnlyAllowRunAsCurrentUserWithoutChroot {
			log.Warningf("Running sandbox in test mode as current user (uid=%d gid=%d). This is only safe in tests!", os.Getuid(), os.Getgid())
			log.Warningf("Running sandbox in test mode without chroot. This is only safe in tests!")
		} else if rootlessEUID || specutils.HasCapabilities(capability.CAP_SETUID, capability.CAP_SETGID) {
			log.Infof("Sandbox will be started in new user namespace")
			nss = append(nss, specs.LinuxNamespace{Type: specs.UserNamespace})
			cmd.Args = append(cmd.Args, "--setup-root")

			const nobody = 65534
			if rootlessEUID || conf.Rootless {
				log.Infof("Rootless mode: sandbox will run as nobody inside user namespace, mapped to the current user, uid: %d, gid: %d", os.Getuid(), os.Getgid())
			} else {
				// Map nobody in the new namespace to nobody in the parent namespace.
				s.UID = nobody
				s.GID = nobody
			}

			// Set credentials to run as user and group nobody.
			cmd.SysProcAttr.Credential = &syscall.Credential{Uid: nobody, Gid: nobody}
			cmd.SysProcAttr.UidMappings = []syscall.SysProcIDMap{
				{
					ContainerID: nobody,
					HostID:      s.UID,
					Size:        1,
				},
			}
			cmd.SysProcAttr.GidMappings = []syscall.SysProcIDMap{
				{
					ContainerID: nobody,
					HostID:      s.GID,
					Size:        1,
				},
			}

			// A sandbox process will construct an empty root for itself, so it has
			// to have CAP_SYS_ADMIN and CAP_SYS_CHROOT capabilities.
			cmd.SysProcAttr.AmbientCaps = append(cmd.SysProcAttr.AmbientCaps, uintptr(capability.CAP_SYS_ADMIN), uintptr(capability.CAP_SYS_CHROOT))

		} else {
			return fmt.Errorf("can't run sandbox process as user nobody since we don't have CAP_SETUID or CAP_SETGID")
		}
	}

	// The current process' stdio must be passed to the application via the
	// --stdio-fds flag. The stdio of the sandbox process itself must not
	// be connected to the same FDs, otherwise we risk leaking sandbox
	// errors to the application, so we set the sandbox stdio to nil,
	// causing them to read/write from the null device.
	cmd.Stdin = nil
	cmd.Stdout = nil
	cmd.Stderr = nil
	var stdios [3]*os.File

	// If the console control socket file is provided, then create a new
	// pty master/replica pair and set the TTY on the sandbox process.
	if args.Spec.Process.Terminal && args.ConsoleSocket != "" {
		// console.NewWithSocket will send the master on the given
		// socket, and return the replica.
		tty, err := console.NewWithSocket(args.ConsoleSocket)
		if err != nil {
			return fmt.Errorf("setting up console with socket %q: %v", args.ConsoleSocket, err)
		}
		defer tty.Close()

		// Set the TTY as a controlling TTY on the sandbox process.
		cmd.SysProcAttr.Setctty = true

		// Inconveniently, the Ctty must be the FD in the *child* process's FD
		// table. So transfer all files we have so far and make sure the next file
		// added to donations is stdin.
		//
		// See https://github.com/golang/go/issues/29458.
		nextFD = donations.Transfer(cmd, nextFD)
		cmd.SysProcAttr.Ctty = nextFD

		// Pass the tty as all stdio fds to sandbox.
		stdios[0] = tty
		stdios[1] = tty
		stdios[2] = tty

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
		stdios[0] = os.Stdin
		stdios[1] = os.Stdout
		stdios[2] = os.Stderr

		if conf.Debug {
			// If debugging, send the boot process stdio to the
			// this process' stdio, so that is is easier to find.
			cmd.Stdin = os.Stdin
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
		}
	}
	if err := s.configureStdios(conf, stdios[:]); err != nil {
		return fmt.Errorf("configuring stdios: %w", err)
	}
	// Note: this must be done right after "cmd.SysProcAttr.Ctty" is set above
	// because it relies on stdin being the next FD donated.
	donations.Donate("stdio-fds", stdios[:]...)

	mem, err := totalSystemMemory()
	if err != nil {
		return err
	}

	if s.CgroupJSON.Cgroup != nil {
		cpuNum, err := s.CgroupJSON.Cgroup.NumCPU()
		if err != nil {
			return fmt.Errorf("getting cpu count from cgroups: %v", err)
		}
		if conf.CPUNumFromQuota {
			// Dropping below 2 CPUs can trigger application to disable
			// locks that can lead do hard to debug errors, so just
			// leaving two cores as reasonable default.
			const minCPUs = 2

			quota, err := s.CgroupJSON.Cgroup.CPUQuota()
			if err != nil {
				return fmt.Errorf("getting cpu quota from cgroups: %v", err)
			}
			if n := int(math.Ceil(quota)); n > 0 {
				if n < minCPUs {
					n = minCPUs
				}
				if n < cpuNum {
					// Only lower the cpu number.
					cpuNum = n
				}
			}
		}
		cmd.Args = append(cmd.Args, "--cpu-num", strconv.Itoa(cpuNum))

		memLimit, err := s.CgroupJSON.Cgroup.MemoryLimit()
		if err != nil {
			return fmt.Errorf("getting memory limit from cgroups: %v", err)
		}
		if memLimit < mem {
			mem = memLimit
		}
	}
	cmd.Args = append(cmd.Args, "--total-memory", strconv.FormatUint(mem, 10))

	if args.Attached {
		// Kill sandbox if parent process exits in attached mode.
		cmd.SysProcAttr.Pdeathsig = unix.SIGKILL
		// Tells boot that any process it creates must have pdeathsig set.
		cmd.Args = append(cmd.Args, "--attached")
	}

	// nextFD must not be used beyond this point.
	_ = donations.Transfer(cmd, nextFD)

	// Add container ID as the last argument.
	cmd.Args = append(cmd.Args, s.ID)

	donation.LogDonations(cmd)
	log.Debugf("Starting sandbox: %s %v", cmd.Path, cmd.Args)
	log.Debugf("SysProcAttr: %+v", cmd.SysProcAttr)
	if err := specutils.StartInNS(cmd, nss); err != nil {
		err := fmt.Errorf("starting sandbox: %v", err)
		// If the sandbox failed to start, it may be because the binary
		// permissions were incorrect. Check the bits and return a more helpful
		// error message.
		//
		// NOTE: The error message is checked because error types are lost over
		// rpc calls.
		if strings.Contains(err.Error(), unix.EACCES.Error()) {
			if permsErr := checkBinaryPermissions(conf); permsErr != nil {
				return fmt.Errorf("%v: %v", err, permsErr)
			}
		}
		return err
	}
	s.OriginalOOMScoreAdj, err = specutils.GetOOMScoreAdj(cmd.Process.Pid)
	if err != nil {
		return err
	}

	s.child = true
	s.Pid.store(cmd.Process.Pid)
	log.Infof("Sandbox started, PID: %d", cmd.Process.Pid)

	return nil
}

// Wait waits for the containerized process to exit, and returns its WaitStatus.
func (s *Sandbox) Wait(cid string) (unix.WaitStatus, error) {
	log.Debugf("Waiting for container %q in sandbox %q", cid, s.ID)

	if conn, err := s.sandboxConnect(); err != nil {
		// The sandbox may have exited while before we had a chance to wait on it.
		// There is nothing we can do for subcontainers. For the init container, we
		// can try to get the sandbox exit code.
		if !s.IsRootContainer(cid) {
			return unix.WaitStatus(0), err
		}
		log.Warningf("Wait on container %q failed: %v. Will try waiting on the sandbox process instead.", cid, err)
	} else {
		defer conn.Close()

		// Try the Wait RPC to the sandbox.
		var ws unix.WaitStatus
		err = conn.Call(boot.ContMgrWait, &cid, &ws)
		conn.Close()
		if err == nil {
			if s.IsRootContainer(cid) {
				if err := s.waitForStopped(); err != nil {
					return unix.WaitStatus(0), err
				}
			}
			// It worked!
			return ws, nil
		}
		// See comment above.
		if !s.IsRootContainer(cid) {
			return unix.WaitStatus(0), err
		}

		// The sandbox may have exited after we connected, but before
		// or during the Wait RPC.
		log.Warningf("Wait RPC to container %q failed: %v. Will try waiting on the sandbox process instead.", cid, err)
	}

	// The sandbox may have already exited, or exited while handling the Wait RPC.
	// The best we can do is ask Linux what the sandbox exit status was, since in
	// most cases that will be the same as the container exit status.
	if err := s.waitForStopped(); err != nil {
		return unix.WaitStatus(0), err
	}
	if !s.child {
		return unix.WaitStatus(0), fmt.Errorf("sandbox no longer running and its exit status is unavailable")
	}

	s.statusMu.Lock()
	defer s.statusMu.Unlock()
	return s.status, nil
}

// WaitPID waits for process 'pid' in the container's sandbox and returns its
// WaitStatus.
func (s *Sandbox) WaitPID(cid string, pid int32) (unix.WaitStatus, error) {
	log.Debugf("Waiting for PID %d in sandbox %q", pid, s.ID)
	var ws unix.WaitStatus
	conn, err := s.sandboxConnect()
	if err != nil {
		return ws, err
	}
	defer conn.Close()

	args := &boot.WaitPIDArgs{
		PID: pid,
		CID: cid,
	}
	if err := conn.Call(boot.ContMgrWaitPID, args, &ws); err != nil {
		return ws, fmt.Errorf("waiting on PID %d in sandbox %q: %v", pid, s.ID, err)
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
	pid := s.Pid.load()
	if pid != 0 {
		log.Debugf("Killing sandbox %q", s.ID)
		if err := unix.Kill(pid, unix.SIGKILL); err != nil && err != unix.ESRCH {
			return fmt.Errorf("killing sandbox %q PID %q: %v", s.ID, pid, err)
		}
		if err := s.waitForStopped(); err != nil {
			return fmt.Errorf("waiting sandbox %q stop: %v", s.ID, err)
		}
	}

	return nil
}

// SignalContainer sends the signal to a container in the sandbox. If all is
// true and signal is SIGKILL, then waits for all processes to exit before
// returning.
func (s *Sandbox) SignalContainer(cid string, sig unix.Signal, all bool) error {
	log.Debugf("Signal sandbox %q", s.ID)
	conn, err := s.sandboxConnect()
	if err != nil {
		return err
	}
	defer conn.Close()

	mode := boot.DeliverToProcess
	if all {
		mode = boot.DeliverToAllProcesses
	}

	args := boot.SignalArgs{
		CID:   cid,
		Signo: int32(sig),
		Mode:  mode,
	}
	if err := conn.Call(boot.ContMgrSignal, &args, nil); err != nil {
		return fmt.Errorf("signaling container %q: %v", cid, err)
	}
	return nil
}

// SignalProcess sends the signal to a particular process in the container. If
// fgProcess is true, then the signal is sent to the foreground process group
// in the same session that PID belongs to. This is only valid if the process
// is attached to a host TTY.
func (s *Sandbox) SignalProcess(cid string, pid int32, sig unix.Signal, fgProcess bool) error {
	log.Debugf("Signal sandbox %q", s.ID)
	conn, err := s.sandboxConnect()
	if err != nil {
		return err
	}
	defer conn.Close()

	mode := boot.DeliverToProcess
	if fgProcess {
		mode = boot.DeliverToForegroundProcessGroup
	}

	args := boot.SignalArgs{
		CID:   cid,
		Signo: int32(sig),
		PID:   pid,
		Mode:  mode,
	}
	if err := conn.Call(boot.ContMgrSignal, &args, nil); err != nil {
		return fmt.Errorf("signaling container %q PID %d: %v", cid, pid, err)
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

	if err := conn.Call(boot.ContMgrCheckpoint, &opt, nil); err != nil {
		return fmt.Errorf("checkpointing container %q: %v", cid, err)
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

	if err := conn.Call(boot.LifecyclePause, nil, nil); err != nil {
		return fmt.Errorf("pausing container %q: %v", cid, err)
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

	if err := conn.Call(boot.LifecycleResume, nil, nil); err != nil {
		return fmt.Errorf("resuming container %q: %v", cid, err)
	}
	return nil
}

// Usage sends the collect call for a container in the sandbox.
func (s *Sandbox) Usage(Full bool) (control.MemoryUsage, error) {
	log.Debugf("Usage sandbox %q", s.ID)
	conn, err := s.sandboxConnect()
	if err != nil {
		return control.MemoryUsage{}, err
	}
	defer conn.Close()

	var m control.MemoryUsage
	err = conn.Call(boot.UsageCollect, &control.MemoryUsageOpts{
		Full: Full,
	}, &m)
	return m, err
}

// UsageFD sends the usagefd call for a container in the sandbox.
func (s *Sandbox) UsageFD() (*control.MemoryUsageRecord, error) {
	log.Debugf("Usage sandbox %q", s.ID)
	conn, err := s.sandboxConnect()
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	var m control.MemoryUsageFile
	if err := conn.Call(boot.UsageUsageFD, &control.MemoryUsageFileOpts{
		Version: 1,
	}, &m); err != nil {
		return nil, fmt.Errorf("UsageFD failed: %v", err)
	}

	if len(m.FilePayload.Files) != 2 {
		return nil, fmt.Errorf("wants exactly two fds")
	}

	return control.NewMemoryUsageRecord(*m.FilePayload.Files[0], *m.FilePayload.Files[1])
}

// Reduce sends the reduce call for a container in the sandbox.
func (s *Sandbox) Reduce(wait bool) error {
	log.Debugf("Reduce sandbox %q", s.ID)
	conn, err := s.sandboxConnect()
	if err != nil {
		return err
	}
	defer conn.Close()

	return conn.Call(boot.UsageReduce, &control.UsageReduceOpts{
		Wait: wait,
	}, nil)
}

// IsRunning returns true if the sandbox or gofer process is running.
func (s *Sandbox) IsRunning() bool {
	pid := s.Pid.load()
	if pid != 0 {
		// Send a signal 0 to the sandbox process.
		if err := unix.Kill(pid, 0); err == nil {
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
	if err := conn.Call(boot.DebugStacks, nil, &stacks); err != nil {
		return "", fmt.Errorf("getting sandbox %q stacks: %v", s.ID, err)
	}
	return stacks, nil
}

// HeapProfile writes a heap profile to the given file.
func (s *Sandbox) HeapProfile(f *os.File, delay time.Duration) error {
	log.Debugf("Heap profile %q", s.ID)
	conn, err := s.sandboxConnect()
	if err != nil {
		return err
	}
	defer conn.Close()

	opts := control.HeapProfileOpts{
		FilePayload: urpc.FilePayload{Files: []*os.File{f}},
		Delay:       delay,
	}
	return conn.Call(boot.ProfileHeap, &opts, nil)
}

// CPUProfile collects a CPU profile.
func (s *Sandbox) CPUProfile(f *os.File, duration time.Duration) error {
	log.Debugf("CPU profile %q", s.ID)
	conn, err := s.sandboxConnect()
	if err != nil {
		return err
	}
	defer conn.Close()

	opts := control.CPUProfileOpts{
		FilePayload: urpc.FilePayload{Files: []*os.File{f}},
		Duration:    duration,
	}
	return conn.Call(boot.ProfileCPU, &opts, nil)
}

// BlockProfile writes a block profile to the given file.
func (s *Sandbox) BlockProfile(f *os.File, duration time.Duration) error {
	log.Debugf("Block profile %q", s.ID)
	conn, err := s.sandboxConnect()
	if err != nil {
		return err
	}
	defer conn.Close()

	opts := control.BlockProfileOpts{
		FilePayload: urpc.FilePayload{Files: []*os.File{f}},
		Duration:    duration,
	}
	return conn.Call(boot.ProfileBlock, &opts, nil)
}

// MutexProfile writes a mutex profile to the given file.
func (s *Sandbox) MutexProfile(f *os.File, duration time.Duration) error {
	log.Debugf("Mutex profile %q", s.ID)
	conn, err := s.sandboxConnect()
	if err != nil {
		return err
	}
	defer conn.Close()

	opts := control.MutexProfileOpts{
		FilePayload: urpc.FilePayload{Files: []*os.File{f}},
		Duration:    duration,
	}
	return conn.Call(boot.ProfileMutex, &opts, nil)
}

// Trace collects an execution trace.
func (s *Sandbox) Trace(f *os.File, duration time.Duration) error {
	log.Debugf("Trace %q", s.ID)
	conn, err := s.sandboxConnect()
	if err != nil {
		return err
	}
	defer conn.Close()

	opts := control.TraceProfileOpts{
		FilePayload: urpc.FilePayload{Files: []*os.File{f}},
		Duration:    duration,
	}
	return conn.Call(boot.ProfileTrace, &opts, nil)
}

// ChangeLogging changes logging options.
func (s *Sandbox) ChangeLogging(args control.LoggingArgs) error {
	log.Debugf("Change logging start %q", s.ID)
	conn, err := s.sandboxConnect()
	if err != nil {
		return err
	}
	defer conn.Close()

	if err := conn.Call(boot.LoggingChange, &args, nil); err != nil {
		return fmt.Errorf("changing sandbox %q logging: %v", s.ID, err)
	}
	return nil
}

// DestroyContainer destroys the given container. If it is the root container,
// then the entire sandbox is destroyed.
func (s *Sandbox) DestroyContainer(cid string) error {
	if err := s.destroyContainer(cid); err != nil {
		// If the sandbox isn't running, the container has already been destroyed,
		// ignore the error in this case.
		if s.IsRunning() {
			return err
		}
	}
	return nil
}

func (s *Sandbox) destroyContainer(cid string) error {
	if s.IsRootContainer(cid) {
		log.Debugf("Destroying root container by destroying sandbox, cid: %s", cid)
		return s.destroy()
	}

	log.Debugf("Destroying container, cid: %s, sandbox: %s", cid, s.ID)
	conn, err := s.sandboxConnect()
	if err != nil {
		return err
	}
	defer conn.Close()
	if err := conn.Call(boot.ContMgrDestroySubcontainer, &cid, nil); err != nil {
		return fmt.Errorf("destroying container %q: %v", cid, err)
	}
	return nil
}

func (s *Sandbox) waitForStopped() error {
	if s.child {
		s.statusMu.Lock()
		defer s.statusMu.Unlock()
		pid := s.Pid.load()
		if pid == 0 {
			return nil
		}
		// The sandbox process is a child of the current process,
		// so we can wait it and collect its zombie.
		if _, err := unix.Wait4(int(pid), &s.status, 0, nil); err != nil {
			return fmt.Errorf("error waiting the sandbox process: %v", err)
		}
		s.Pid.store(0)
		return nil
	}

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

// configureStdios change stdios ownership to give access to the sandbox
// process. This may be skipped depending on the configuration.
func (s *Sandbox) configureStdios(conf *config.Config, stdios []*os.File) error {
	if conf.Rootless || conf.TestOnlyAllowRunAsCurrentUserWithoutChroot {
		// Cannot change ownership without CAP_CHOWN.
		return nil
	}

	if s.UID < 0 || s.GID < 0 {
		panic(fmt.Sprintf("sandbox UID/GID is not set: %d/%d", s.UID, s.GID))
	}
	for _, file := range stdios {
		log.Debugf("Changing %q ownership to %d/%d", file.Name(), s.UID, s.GID)
		if err := file.Chown(s.UID, s.GID); err != nil {
			if errors.Is(err, unix.EINVAL) || errors.Is(err, unix.EPERM) || errors.Is(err, unix.EROFS) {
				log.Warningf("can't change an owner of %s: %s", file.Name(), err)
				continue
			}
			return err
		}
	}
	return nil
}

// deviceFileForPlatform opens the device file for the given platform. If the
// platform does not need a device file, then nil is returned.
// devicePath may be empty to use a sane platform-specific default.
func deviceFileForPlatform(name, devicePath string) (*os.File, error) {
	p, err := platform.Lookup(name)
	if err != nil {
		return nil, err
	}

	f, err := p.OpenDevice(devicePath)
	if err != nil {
		return nil, fmt.Errorf("opening device file for platform %q: %w", name, err)
	}
	return f, nil
}

// checkBinaryPermissions verifies that the required binary bits are set on
// the runsc executable.
func checkBinaryPermissions(conf *config.Config) error {
	// All platforms need the other exe bit
	neededBits := os.FileMode(0001)
	if conf.Platform == "ptrace" {
		// Ptrace needs the other read bit
		neededBits |= os.FileMode(0004)
	}

	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("getting exe path: %v", err)
	}

	// Check the permissions of the runsc binary and print an error if it
	// doesn't match expectations.
	info, err := os.Stat(exePath)
	if err != nil {
		return fmt.Errorf("stat file: %v", err)
	}

	if info.Mode().Perm()&neededBits != neededBits {
		return fmt.Errorf(specutils.FaqErrorMsg("runsc-perms", fmt.Sprintf("%s does not have the correct permissions", exePath)))
	}
	return nil
}

// CgroupsReadControlFile reads a single cgroupfs control file in the sandbox.
func (s *Sandbox) CgroupsReadControlFile(file control.CgroupControlFile) (string, error) {
	log.Debugf("CgroupsReadControlFiles sandbox %q", s.ID)
	conn, err := s.sandboxConnect()
	if err != nil {
		return "", err
	}
	defer conn.Close()

	args := control.CgroupsReadArgs{
		Args: []control.CgroupsReadArg{
			{
				File: file,
			},
		},
	}
	var out control.CgroupsResults
	err = conn.Call(boot.CgroupsReadControlFiles, &args, &out)
	if err != nil {
		return "", err
	}
	if len(out.Results) != 1 {
		return "", fmt.Errorf("expected 1 result, got %d, raw: %+v", len(out.Results), out)
	}
	return out.Results[0].Unpack()
}

// CgroupsWriteControlFile writes a single cgroupfs control file in the sandbox.
func (s *Sandbox) CgroupsWriteControlFile(file control.CgroupControlFile, value string) error {
	log.Debugf("CgroupsReadControlFiles sandbox %q", s.ID)
	conn, err := s.sandboxConnect()
	if err != nil {
		return err
	}
	defer conn.Close()

	args := control.CgroupsWriteArgs{
		Args: []control.CgroupsWriteArg{
			{
				File:  file,
				Value: value,
			},
		},
	}
	var out control.CgroupsResults
	err = conn.Call(boot.CgroupsWriteControlFiles, &args, &out)
	if err != nil {
		return err
	}
	if len(out.Results) != 1 {
		return fmt.Errorf("expected 1 result, got %d, raw: %+v", len(out.Results), out)
	}
	return out.Results[0].AsError()
}

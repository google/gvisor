// Copyright 2018 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package shim implements Containerd Shim v2 interface.
package shim

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/containerd/cgroups"
	cgroupsstats "github.com/containerd/cgroups/stats/v1"
	"github.com/containerd/console"
	"github.com/containerd/containerd/api/events"
	"github.com/containerd/containerd/api/types/task"
	"github.com/containerd/containerd/errdefs"
	"github.com/containerd/containerd/log"
	"github.com/containerd/containerd/mount"
	"github.com/containerd/containerd/namespaces"
	"github.com/containerd/containerd/pkg/process"
	"github.com/containerd/containerd/pkg/stdio"
	"github.com/containerd/containerd/runtime"
	"github.com/containerd/containerd/runtime/linux/runctypes"
	"github.com/containerd/containerd/runtime/v2/shim"
	taskAPI "github.com/containerd/containerd/runtime/v2/task"
	"github.com/containerd/containerd/sys/reaper"
	"github.com/containerd/typeurl"
	"github.com/gogo/protobuf/types"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/cleanup"

	"gvisor.dev/gvisor/pkg/shim/proc"
	"gvisor.dev/gvisor/pkg/shim/runsc"
	"gvisor.dev/gvisor/pkg/shim/runtimeoptions"
	"gvisor.dev/gvisor/pkg/shim/utils"
	"gvisor.dev/gvisor/runsc/specutils"
)

var (
	empty   = &types.Empty{}
	bufPool = sync.Pool{
		New: func() interface{} {
			buffer := make([]byte, 32<<10)
			return &buffer
		},
	}
)

var _ = (taskAPI.TaskService)(&service{})

const (
	// configFile is the default config file name. For containerd 1.2,
	// we assume that a config.toml should exist in the runtime root.
	configFile = "config.toml"

	// shimAddressPath is the relative path to a file that contains the address
	// to the shim UDS. See service.shimAddress.
	shimAddressPath = "address"
)

// New returns a new shim service that can be used via GRPC.
func New(ctx context.Context, id string, publisher shim.Publisher, cancel func()) (shim.Shim, error) {
	var opts shim.Opts
	if ctxOpts := ctx.Value(shim.OptsKey{}); ctxOpts != nil {
		opts = ctxOpts.(shim.Opts)
	}

	ep, err := newOOMEpoller(publisher)
	if err != nil {
		return nil, err
	}
	go ep.run(ctx)
	s := &service{
		id:             id,
		processes:      make(map[string]process.Process),
		events:         make(chan interface{}, 128),
		ec:             proc.ExitCh,
		oomPoller:      ep,
		cancel:         cancel,
		genericOptions: opts,
	}
	go s.processExits(ctx)
	runsc.Monitor = &runsc.LogMonitor{Next: reaper.Default}
	if err := s.initPlatform(); err != nil {
		cancel()
		return nil, fmt.Errorf("failed to initialized platform behavior: %w", err)
	}
	go s.forward(ctx, publisher)

	if address, err := shim.ReadAddress(shimAddressPath); err == nil {
		s.shimAddress = address
	}

	return s, nil
}

// service is the shim implementation of a remote shim over GRPC. It runs in 2
// different modes:
//   1. Service: process runs for the life time of the container and receives
//      calls described in shimapi.TaskService interface.
//   2. Tool: process is short lived and runs only to perform the requested
//      operations and then exits. It implements the direct functions in
//      shim.Shim interface.
//
// When the service is running, it saves a json file with state information so
// that commands sent to the tool can load the state and perform the operation.
type service struct {
	mu sync.Mutex

	// id is the container ID.
	id string

	// bundle is a path provided by the caller on container creation. Store
	// because it's needed in commands that don't receive bundle in the request.
	bundle string

	// task is the main process that is running the container.
	task *proc.Init

	// processes maps ExecId to processes running through exec.
	processes map[string]process.Process

	events chan interface{}

	// platform handles operations related to the console.
	platform stdio.Platform

	// genericOptions are options that come from the shim interface and are common
	// to all shims.
	genericOptions shim.Opts

	// opts are configuration options specific for this shim.
	opts options

	// ex gets notified whenever the container init process or an exec'd process
	// exits from inside the sandbox.
	ec chan proc.Exit

	// oomPoller monitors the sandbox's cgroup for OOM notifications.
	oomPoller *epoller

	// cancel is a function that needs to be called before the shim stops. The
	// function is provided by the caller to New().
	cancel func()

	// shimAddress is the location of the UDS used to communicate to containerd.
	shimAddress string
}

func (s *service) newCommand(ctx context.Context, containerdBinary, containerdAddress string) (*exec.Cmd, error) {
	ns, err := namespaces.NamespaceRequired(ctx)
	if err != nil {
		return nil, err
	}
	self, err := os.Executable()
	if err != nil {
		return nil, err
	}
	cwd, err := os.Getwd()
	if err != nil {
		return nil, err
	}
	args := []string{
		"-namespace", ns,
		"-address", containerdAddress,
		"-publish-binary", containerdBinary,
	}
	if s.genericOptions.Debug {
		args = append(args, "-debug")
	}
	cmd := exec.Command(self, args...)
	cmd.Dir = cwd
	cmd.Env = append(os.Environ(), "GOMAXPROCS=2")
	cmd.SysProcAttr = &unix.SysProcAttr{
		Setpgid: true,
	}
	return cmd, nil
}

func (s *service) StartShim(ctx context.Context, id, containerdBinary, containerdAddress, containerdTTRPCAddress string) (string, error) {
	log.L.Debugf("StartShim, id: %s, binary: %q, address: %q", id, containerdBinary, containerdAddress)

	cmd, err := s.newCommand(ctx, containerdBinary, containerdAddress)
	if err != nil {
		return "", err
	}
	address, err := shim.SocketAddress(ctx, containerdAddress, id)
	if err != nil {
		return "", err
	}
	socket, err := shim.NewSocket(address)
	if err != nil {
		// The only time where this would happen is if there is a bug and the socket
		// was not cleaned up in the cleanup method of the shim or we are using the
		// grouping functionality where the new process should be run with the same
		// shim as an existing container.
		if !shim.SocketEaddrinuse(err) {
			return "", fmt.Errorf("create new shim socket: %w", err)
		}
		if shim.CanConnect(address) {
			if err := shim.WriteAddress(shimAddressPath, address); err != nil {
				return "", fmt.Errorf("write existing socket for shim: %w", err)
			}
			return address, nil
		}
		if err := shim.RemoveSocket(address); err != nil {
			return "", fmt.Errorf("remove pre-existing socket: %w", err)
		}
		if socket, err = shim.NewSocket(address); err != nil {
			return "", fmt.Errorf("try create new shim socket 2x: %w", err)
		}
	}
	cu := cleanup.Make(func() {
		socket.Close()
		_ = shim.RemoveSocket(address)
	})
	defer cu.Clean()

	f, err := socket.File()
	if err != nil {
		return "", err
	}

	cmd.ExtraFiles = append(cmd.ExtraFiles, f)

	log.L.Debugf("Executing: %q %s", cmd.Path, cmd.Args)
	if err := cmd.Start(); err != nil {
		f.Close()
		return "", err
	}
	cu.Add(func() { cmd.Process.Kill() })

	// make sure to wait after start
	go cmd.Wait()
	if err := shim.WritePidFile("shim.pid", cmd.Process.Pid); err != nil {
		return "", err
	}
	if err := shim.WriteAddress(shimAddressPath, address); err != nil {
		return "", err
	}
	if err := shim.SetScore(cmd.Process.Pid); err != nil {
		return "", fmt.Errorf("failed to set OOM Score on shim: %w", err)
	}
	cu.Release()
	return address, nil
}

// Cleanup is called from another process (need to reload state) to stop the
// container and undo all operations done in Create().
func (s *service) Cleanup(ctx context.Context) (*taskAPI.DeleteResponse, error) {
	log.L.Debugf("Cleanup")

	path, err := os.Getwd()
	if err != nil {
		return nil, err
	}
	ns, err := namespaces.NamespaceRequired(ctx)
	if err != nil {
		return nil, err
	}
	var st state
	if err := st.load(path); err != nil {
		return nil, err
	}
	r := proc.NewRunsc(s.opts.Root, path, ns, st.Options.BinaryName, nil)

	if err := r.Delete(ctx, s.id, &runsc.DeleteOpts{
		Force: true,
	}); err != nil {
		log.L.Infof("failed to remove runc container: %v", err)
	}
	if err := mount.UnmountAll(st.Rootfs, 0); err != nil {
		log.L.Infof("failed to cleanup rootfs mount: %v", err)
	}
	return &taskAPI.DeleteResponse{
		ExitedAt:   time.Now(),
		ExitStatus: 128 + uint32(unix.SIGKILL),
	}, nil
}

// Create creates a new initial process and container with the underlying OCI
// runtime.
func (s *service) Create(ctx context.Context, r *taskAPI.CreateTaskRequest) (*taskAPI.CreateTaskResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Save the main task id and bundle to the shim for additional requests.
	s.id = r.ID
	s.bundle = r.Bundle

	ns, err := namespaces.NamespaceRequired(ctx)
	if err != nil {
		return nil, fmt.Errorf("create namespace: %w", err)
	}

	// Read from root for now.
	if r.Options != nil {
		v, err := typeurl.UnmarshalAny(r.Options)
		if err != nil {
			return nil, err
		}
		var path string
		switch o := v.(type) {
		case *runctypes.CreateOptions: // containerd 1.2.x
			s.opts.IoUID = o.IoUid
			s.opts.IoGID = o.IoGid
			s.opts.ShimCgroup = o.ShimCgroup
		case *runctypes.RuncOptions: // containerd 1.2.x
			root := proc.RunscRoot
			if o.RuntimeRoot != "" {
				root = o.RuntimeRoot
			}

			s.opts.BinaryName = o.Runtime

			path = filepath.Join(root, configFile)
			if _, err := os.Stat(path); err != nil {
				if !os.IsNotExist(err) {
					return nil, fmt.Errorf("stat config file %q: %w", path, err)
				}
				// A config file in runtime root is not required.
				path = ""
			}
		case *runtimeoptions.Options: // containerd 1.3.x+
			if o.ConfigPath == "" {
				break
			}
			if o.TypeUrl != optionsType {
				return nil, fmt.Errorf("unsupported option type %q", o.TypeUrl)
			}
			path = o.ConfigPath
		default:
			return nil, fmt.Errorf("unsupported option type %q", r.Options.TypeUrl)
		}
		if path != "" {
			if _, err = toml.DecodeFile(path, &s.opts); err != nil {
				return nil, fmt.Errorf("decode config file %q: %w", path, err)
			}
		}
	}

	if len(s.opts.LogLevel) != 0 {
		lvl, err := logrus.ParseLevel(s.opts.LogLevel)
		if err != nil {
			return nil, err
		}
		logrus.SetLevel(lvl)
	}
	if len(s.opts.LogPath) != 0 {
		logPath := runsc.FormatShimLogPath(s.opts.LogPath, s.id)
		if err := os.MkdirAll(filepath.Dir(logPath), 0777); err != nil {
			return nil, fmt.Errorf("failed to create log dir: %w", err)
		}
		logFile, err := os.Create(logPath)
		if err != nil {
			return nil, fmt.Errorf("failed to create log file: %w", err)
		}
		log.L.Debugf("Starting mirror log at %q", logPath)
		std := logrus.StandardLogger()
		std.SetOutput(io.MultiWriter(std.Out, logFile))

		log.L.Debugf("Create shim")
		log.L.Debugf("***************************")
		log.L.Debugf("Args: %s", os.Args)
		log.L.Debugf("PID: %d", os.Getpid())
		log.L.Debugf("ID: %s", s.id)
		log.L.Debugf("Options: %+v", s.opts)
		log.L.Debugf("Bundle: %s", r.Bundle)
		log.L.Debugf("Terminal: %t", r.Terminal)
		log.L.Debugf("stdin: %s", r.Stdin)
		log.L.Debugf("stdout: %s", r.Stdout)
		log.L.Debugf("stderr: %s", r.Stderr)
		log.L.Debugf("***************************")
		if log.L.Logger.IsLevelEnabled(logrus.DebugLevel) {
			setDebugSigHandler()
		}
	}

	// Save state before any action is taken to ensure Cleanup() will have all
	// the information it needs to undo the operations.
	st := state{
		Rootfs:  filepath.Join(r.Bundle, "rootfs"),
		Options: s.opts,
	}
	if err := st.save(r.Bundle); err != nil {
		return nil, err
	}

	if err := os.Mkdir(st.Rootfs, 0711); err != nil && !os.IsExist(err) {
		return nil, err
	}

	// Convert from types.Mount to proc.Mount.
	var mounts []proc.Mount
	for _, m := range r.Rootfs {
		mounts = append(mounts, proc.Mount{
			Type:    m.Type,
			Source:  m.Source,
			Target:  m.Target,
			Options: m.Options,
		})
	}

	// Cleans up all mounts in case of failure.
	cu := cleanup.Make(func() {
		if err := mount.UnmountAll(st.Rootfs, 0); err != nil {
			log.L.Infof("failed to cleanup rootfs mount: %v", err)
		}
	})
	defer cu.Clean()
	for _, rm := range mounts {
		m := &mount.Mount{
			Type:    rm.Type,
			Source:  rm.Source,
			Options: rm.Options,
		}
		if err := m.Mount(st.Rootfs); err != nil {
			return nil, fmt.Errorf("failed to mount rootfs component %v: %w", m, err)
		}
	}

	config := &proc.CreateConfig{
		ID:       r.ID,
		Bundle:   r.Bundle,
		Runtime:  s.opts.BinaryName,
		Rootfs:   mounts,
		Terminal: r.Terminal,
		Stdin:    r.Stdin,
		Stdout:   r.Stdout,
		Stderr:   r.Stderr,
	}
	process, err := newInit(r.Bundle, filepath.Join(r.Bundle, "work"), ns, s.platform, config, &s.opts, st.Rootfs)
	if err != nil {
		return nil, errdefs.ToGRPC(err)
	}
	if err := process.Create(ctx, config); err != nil {
		return nil, errdefs.ToGRPC(err)
	}

	// Set up OOM notification on the sandbox's cgroup. This is done on
	// sandbox create since the sandbox process will be created here.
	pid := process.Pid()
	if pid > 0 {
		cg, err := cgroups.Load(cgroups.V1, cgroups.PidPath(pid))
		if err != nil {
			return nil, fmt.Errorf("loading cgroup for %d: %w", pid, err)
		}
		if err := s.oomPoller.add(s.id, cg); err != nil {
			return nil, fmt.Errorf("add cg to OOM monitor: %w", err)
		}
	}

	// Success
	cu.Release()
	s.task = process
	return &taskAPI.CreateTaskResponse{
		Pid: uint32(process.Pid()),
	}, nil
}

// Start starts a process.
func (s *service) Start(ctx context.Context, r *taskAPI.StartRequest) (*taskAPI.StartResponse, error) {
	log.L.Debugf("Start, id: %s, execID: %s", r.ID, r.ExecID)

	p, err := s.getProcess(r.ExecID)
	if err != nil {
		return nil, err
	}
	if err := p.Start(ctx); err != nil {
		return nil, err
	}
	// TODO: Set the cgroup and oom notifications on restore.
	// https://github.com/google/gvisor-containerd-shim/issues/58
	return &taskAPI.StartResponse{
		Pid: uint32(p.Pid()),
	}, nil
}

// Delete deletes the initial process and container.
func (s *service) Delete(ctx context.Context, r *taskAPI.DeleteRequest) (*taskAPI.DeleteResponse, error) {
	log.L.Debugf("Delete, id: %s, execID: %s", r.ID, r.ExecID)

	p, err := s.getProcess(r.ExecID)
	if err != nil {
		return nil, err
	}
	if err := p.Delete(ctx); err != nil {
		return nil, err
	}
	if len(r.ExecID) != 0 {
		s.mu.Lock()
		delete(s.processes, r.ExecID)
		s.mu.Unlock()
	} else if s.platform != nil {
		s.platform.Close()
	}
	return &taskAPI.DeleteResponse{
		ExitStatus: uint32(p.ExitStatus()),
		ExitedAt:   p.ExitedAt(),
		Pid:        uint32(p.Pid()),
	}, nil
}

// Exec spawns an additional process inside the container.
func (s *service) Exec(ctx context.Context, r *taskAPI.ExecProcessRequest) (*types.Empty, error) {
	log.L.Debugf("Exec, id: %s, execID: %s", r.ID, r.ExecID)

	s.mu.Lock()
	p := s.processes[r.ExecID]
	s.mu.Unlock()
	if p != nil {
		return nil, errdefs.ToGRPCf(errdefs.ErrAlreadyExists, "id %s", r.ExecID)
	}
	if s.task == nil {
		return nil, errdefs.ToGRPCf(errdefs.ErrFailedPrecondition, "container must be created")
	}
	process, err := s.task.Exec(ctx, s.bundle, &proc.ExecConfig{
		ID:       r.ExecID,
		Terminal: r.Terminal,
		Stdin:    r.Stdin,
		Stdout:   r.Stdout,
		Stderr:   r.Stderr,
		Spec:     r.Spec,
	})
	if err != nil {
		return nil, errdefs.ToGRPC(err)
	}
	s.mu.Lock()
	s.processes[r.ExecID] = process
	s.mu.Unlock()
	return empty, nil
}

// ResizePty resizes the terminal of a process.
func (s *service) ResizePty(ctx context.Context, r *taskAPI.ResizePtyRequest) (*types.Empty, error) {
	log.L.Debugf("ResizePty, id: %s, execID: %s, dimension: %dx%d", r.ID, r.ExecID, r.Height, r.Width)

	p, err := s.getProcess(r.ExecID)
	if err != nil {
		return nil, err
	}
	ws := console.WinSize{
		Width:  uint16(r.Width),
		Height: uint16(r.Height),
	}
	if err := p.Resize(ws); err != nil {
		return nil, errdefs.ToGRPC(err)
	}
	return empty, nil
}

// State returns runtime state information for a process.
func (s *service) State(ctx context.Context, r *taskAPI.StateRequest) (*taskAPI.StateResponse, error) {
	log.L.Debugf("State, id: %s, execID: %s", r.ID, r.ExecID)

	p, err := s.getProcess(r.ExecID)
	if err != nil {
		log.L.Debugf("State failed to find process: %v", err)
		return nil, err
	}
	st, err := p.Status(ctx)
	if err != nil {
		log.L.Debugf("State failed: %v", err)
		return nil, err
	}
	status := task.StatusUnknown
	switch st {
	case "created":
		status = task.StatusCreated
	case "running":
		status = task.StatusRunning
	case "stopped":
		status = task.StatusStopped
	}
	sio := p.Stdio()
	res := &taskAPI.StateResponse{
		ID:         p.ID(),
		Bundle:     s.bundle,
		Pid:        uint32(p.Pid()),
		Status:     status,
		Stdin:      sio.Stdin,
		Stdout:     sio.Stdout,
		Stderr:     sio.Stderr,
		Terminal:   sio.Terminal,
		ExitStatus: uint32(p.ExitStatus()),
		ExitedAt:   p.ExitedAt(),
	}
	log.L.Debugf("State succeeded, response: %+v", res)
	return res, nil
}

// Pause the container.
func (s *service) Pause(ctx context.Context, r *taskAPI.PauseRequest) (*types.Empty, error) {
	log.L.Debugf("Pause, id: %s", r.ID)
	if s.task == nil {
		log.L.Debugf("Pause error, id: %s: container not created", r.ID)
		return nil, errdefs.ToGRPCf(errdefs.ErrFailedPrecondition, "container must be created")
	}
	err := s.task.Runtime().Pause(ctx, r.ID)
	if err != nil {
		return nil, err
	}
	return empty, nil
}

// Resume the container.
func (s *service) Resume(ctx context.Context, r *taskAPI.ResumeRequest) (*types.Empty, error) {
	log.L.Debugf("Resume, id: %s", r.ID)
	if s.task == nil {
		log.L.Debugf("Resume error, id: %s: container not created", r.ID)
		return nil, errdefs.ToGRPCf(errdefs.ErrFailedPrecondition, "container must be created")
	}
	err := s.task.Runtime().Resume(ctx, r.ID)
	if err != nil {
		return nil, err
	}
	return empty, nil
}

// Kill a process with the provided signal.
func (s *service) Kill(ctx context.Context, r *taskAPI.KillRequest) (*types.Empty, error) {
	log.L.Debugf("Kill, id: %s, execID: %s, signal: %d, all: %t", r.ID, r.ExecID, r.Signal, r.All)

	p, err := s.getProcess(r.ExecID)
	if err != nil {
		return nil, err
	}
	if err := p.Kill(ctx, r.Signal, r.All); err != nil {
		log.L.Debugf("Kill failed: %v", err)
		return nil, errdefs.ToGRPC(err)
	}
	log.L.Debugf("Kill succeeded")
	return empty, nil
}

// Pids returns all pids inside the container.
func (s *service) Pids(ctx context.Context, r *taskAPI.PidsRequest) (*taskAPI.PidsResponse, error) {
	log.L.Debugf("Pids, id: %s", r.ID)

	pids, err := s.getContainerPids(ctx, r.ID)
	if err != nil {
		return nil, errdefs.ToGRPC(err)
	}
	var processes []*task.ProcessInfo
	for _, pid := range pids {
		pInfo := task.ProcessInfo{
			Pid: pid,
		}
		for _, p := range s.processes {
			if p.Pid() == int(pid) {
				d := &runctypes.ProcessDetails{
					ExecID: p.ID(),
				}
				a, err := typeurl.MarshalAny(d)
				if err != nil {
					return nil, fmt.Errorf("failed to marshal process %d info: %w", pid, err)
				}
				pInfo.Info = a
				break
			}
		}
		processes = append(processes, &pInfo)
	}
	return &taskAPI.PidsResponse{
		Processes: processes,
	}, nil
}

// CloseIO closes the I/O context of a process.
func (s *service) CloseIO(ctx context.Context, r *taskAPI.CloseIORequest) (*types.Empty, error) {
	log.L.Debugf("CloseIO, id: %s, execID: %s, stdin: %t", r.ID, r.ExecID, r.Stdin)

	p, err := s.getProcess(r.ExecID)
	if err != nil {
		return nil, err
	}
	if stdin := p.Stdin(); stdin != nil {
		if err := stdin.Close(); err != nil {
			return nil, fmt.Errorf("close stdin: %w", err)
		}
	}
	return empty, nil
}

// Checkpoint checkpoints the container.
func (s *service) Checkpoint(ctx context.Context, r *taskAPI.CheckpointTaskRequest) (*types.Empty, error) {
	log.L.Debugf("Checkpoint, id: %s", r.ID)
	return empty, errdefs.ToGRPC(errdefs.ErrNotImplemented)
}

// Connect returns shim information such as the shim's pid.
func (s *service) Connect(ctx context.Context, r *taskAPI.ConnectRequest) (*taskAPI.ConnectResponse, error) {
	log.L.Debugf("Connect, id: %s", r.ID)

	var pid int
	if s.task != nil {
		pid = s.task.Pid()
	}
	return &taskAPI.ConnectResponse{
		ShimPid: uint32(os.Getpid()),
		TaskPid: uint32(pid),
	}, nil
}

func (s *service) Shutdown(ctx context.Context, r *taskAPI.ShutdownRequest) (*types.Empty, error) {
	log.L.Debugf("Shutdown, id: %s", r.ID)
	s.cancel()
	if s.shimAddress != "" {
		_ = shim.RemoveSocket(s.shimAddress)
	}
	os.Exit(0)
	panic("Should not get here")
}

func (s *service) Stats(ctx context.Context, r *taskAPI.StatsRequest) (*taskAPI.StatsResponse, error) {
	log.L.Debugf("Stats, id: %s", r.ID)
	if s.task == nil {
		log.L.Debugf("Stats error, id: %s: container not created", r.ID)
		return nil, errdefs.ToGRPCf(errdefs.ErrFailedPrecondition, "container must be created")
	}
	stats, err := s.task.Stats(ctx, s.id)
	if err != nil {
		log.L.Debugf("Stats error, id: %s: %v", r.ID, err)
		return nil, err
	}

	// gvisor currently (as of 2020-03-03) only returns the total memory
	// usage and current PID value[0]. However, we copy the common fields here
	// so that future updates will propagate correct information.  We're
	// using the cgroups.Metrics structure so we're returning the same type
	// as runc.
	//
	// [0]: https://github.com/google/gvisor/blob/277a0d5a1fbe8272d4729c01ee4c6e374d047ebc/runsc/boot/events.go#L61-L81
	metrics := &cgroupsstats.Metrics{
		CPU: &cgroupsstats.CPUStat{
			Usage: &cgroupsstats.CPUUsage{
				Total:  stats.Cpu.Usage.Total,
				Kernel: stats.Cpu.Usage.Kernel,
				User:   stats.Cpu.Usage.User,
				PerCPU: stats.Cpu.Usage.Percpu,
			},
			Throttling: &cgroupsstats.Throttle{
				Periods:          stats.Cpu.Throttling.Periods,
				ThrottledPeriods: stats.Cpu.Throttling.ThrottledPeriods,
				ThrottledTime:    stats.Cpu.Throttling.ThrottledTime,
			},
		},
		Memory: &cgroupsstats.MemoryStat{
			Cache: stats.Memory.Cache,
			Usage: &cgroupsstats.MemoryEntry{
				Limit:   stats.Memory.Usage.Limit,
				Usage:   stats.Memory.Usage.Usage,
				Max:     stats.Memory.Usage.Max,
				Failcnt: stats.Memory.Usage.Failcnt,
			},
			Swap: &cgroupsstats.MemoryEntry{
				Limit:   stats.Memory.Swap.Limit,
				Usage:   stats.Memory.Swap.Usage,
				Max:     stats.Memory.Swap.Max,
				Failcnt: stats.Memory.Swap.Failcnt,
			},
			Kernel: &cgroupsstats.MemoryEntry{
				Limit:   stats.Memory.Kernel.Limit,
				Usage:   stats.Memory.Kernel.Usage,
				Max:     stats.Memory.Kernel.Max,
				Failcnt: stats.Memory.Kernel.Failcnt,
			},
			KernelTCP: &cgroupsstats.MemoryEntry{
				Limit:   stats.Memory.KernelTCP.Limit,
				Usage:   stats.Memory.KernelTCP.Usage,
				Max:     stats.Memory.KernelTCP.Max,
				Failcnt: stats.Memory.KernelTCP.Failcnt,
			},
		},
		Pids: &cgroupsstats.PidsStat{
			Current: stats.Pids.Current,
			Limit:   stats.Pids.Limit,
		},
	}
	data, err := typeurl.MarshalAny(metrics)
	if err != nil {
		log.L.Debugf("Stats error, id: %s: %v", r.ID, err)
		return nil, err
	}
	log.L.Debugf("Stats success, id: %s: %+v", r.ID, data)
	return &taskAPI.StatsResponse{
		Stats: data,
	}, nil
}

// Update updates a running container.
func (s *service) Update(ctx context.Context, r *taskAPI.UpdateTaskRequest) (*types.Empty, error) {
	return empty, errdefs.ToGRPC(errdefs.ErrNotImplemented)
}

// Wait waits for a process to exit.
func (s *service) Wait(ctx context.Context, r *taskAPI.WaitRequest) (*taskAPI.WaitResponse, error) {
	log.L.Debugf("Wait, id: %s, execID: %s", r.ID, r.ExecID)

	p, err := s.getProcess(r.ExecID)
	if err != nil {
		log.L.Debugf("Wait failed to find process: %v", err)
		return nil, err
	}
	p.Wait()

	res := &taskAPI.WaitResponse{
		ExitStatus: uint32(p.ExitStatus()),
		ExitedAt:   p.ExitedAt(),
	}
	log.L.Debugf("Wait succeeded, response: %+v", res)
	return res, nil
}

func (s *service) processExits(ctx context.Context) {
	for e := range s.ec {
		s.checkProcesses(ctx, e)
	}
}

func (s *service) checkProcesses(ctx context.Context, e proc.Exit) {
	// TODO(random-liu): Add `shouldKillAll` logic if container pid
	// namespace is supported.
	for _, p := range s.allProcesses() {
		if p.ID() == e.ID {
			if ip, ok := p.(*proc.Init); ok {
				// Ensure all children are killed.
				log.L.Debugf("Container init process exited, killing all container processes")
				ip.KillAll(ctx)
			}
			p.SetExited(e.Status)
			s.events <- &events.TaskExit{
				ContainerID: s.id,
				ID:          p.ID(),
				Pid:         uint32(p.Pid()),
				ExitStatus:  uint32(e.Status),
				ExitedAt:    p.ExitedAt(),
			}
			return
		}
	}
}

func (s *service) allProcesses() (o []process.Process) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, p := range s.processes {
		o = append(o, p)
	}
	if s.task != nil {
		o = append(o, s.task)
	}
	return o
}

func (s *service) getContainerPids(ctx context.Context, id string) ([]uint32, error) {
	s.mu.Lock()
	p := s.task
	s.mu.Unlock()
	if p == nil {
		return nil, fmt.Errorf("container must be created: %w", errdefs.ErrFailedPrecondition)
	}
	ps, err := p.Runtime().Ps(ctx, id)
	if err != nil {
		return nil, err
	}
	pids := make([]uint32, 0, len(ps))
	for _, pid := range ps {
		pids = append(pids, uint32(pid))
	}
	return pids, nil
}

func (s *service) forward(ctx context.Context, publisher shim.Publisher) {
	for e := range s.events {
		err := publisher.Publish(ctx, getTopic(e), e)
		if err != nil {
			// Should not happen.
			panic(fmt.Errorf("post event: %w", err))
		}
	}
}

func (s *service) getProcess(execID string) (process.Process, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if execID == "" {
		if s.task == nil {
			return nil, errdefs.ToGRPCf(errdefs.ErrFailedPrecondition, "container must be created")
		}
		return s.task, nil
	}

	p := s.processes[execID]
	if p == nil {
		return nil, errdefs.ToGRPCf(errdefs.ErrNotFound, "process does not exist %s", execID)
	}
	return p, nil
}

func getTopic(e interface{}) string {
	switch e.(type) {
	case *events.TaskCreate:
		return runtime.TaskCreateEventTopic
	case *events.TaskStart:
		return runtime.TaskStartEventTopic
	case *events.TaskOOM:
		return runtime.TaskOOMEventTopic
	case *events.TaskExit:
		return runtime.TaskExitEventTopic
	case *events.TaskDelete:
		return runtime.TaskDeleteEventTopic
	case *events.TaskExecAdded:
		return runtime.TaskExecAddedEventTopic
	case *events.TaskExecStarted:
		return runtime.TaskExecStartedEventTopic
	default:
		log.L.Infof("no topic for type %#v", e)
	}
	return runtime.TaskUnknownTopic
}

func newInit(path, workDir, namespace string, platform stdio.Platform, r *proc.CreateConfig, options *options, rootfs string) (*proc.Init, error) {
	spec, err := utils.ReadSpec(r.Bundle)
	if err != nil {
		return nil, fmt.Errorf("read oci spec: %w", err)
	}

	updated, err := utils.UpdateVolumeAnnotations(spec)
	if err != nil {
		return nil, fmt.Errorf("update volume annotations: %w", err)
	}
	updated = updateCgroup(spec) || updated

	if updated {
		if err := utils.WriteSpec(r.Bundle, spec); err != nil {
			return nil, err
		}
	}

	runsc.FormatRunscLogPath(r.ID, options.RunscConfig)
	runtime := proc.NewRunsc(options.Root, path, namespace, options.BinaryName, options.RunscConfig)
	p := proc.New(r.ID, runtime, stdio.Stdio{
		Stdin:    r.Stdin,
		Stdout:   r.Stdout,
		Stderr:   r.Stderr,
		Terminal: r.Terminal,
	})
	p.Bundle = r.Bundle
	p.Platform = platform
	p.Rootfs = rootfs
	p.WorkDir = workDir
	p.IoUID = int(options.IoUID)
	p.IoGID = int(options.IoGID)
	p.Sandbox = specutils.SpecContainerType(spec) == specutils.ContainerTypeSandbox
	p.UserLog = utils.UserLogPath(spec)
	p.Monitor = reaper.Default
	return p, nil
}

// updateCgroup updates cgroup path for the sandbox to make the sandbox join the
// pod cgroup and not the pause container cgroup. Returns true if the spec was
// modified. Ex.:
//   /kubepods/burstable/pod123/abc => kubepods/burstable/pod123
//
func updateCgroup(spec *specs.Spec) bool {
	if !utils.IsSandbox(spec) {
		return false
	}
	if spec.Linux == nil || len(spec.Linux.CgroupsPath) == 0 {
		return false
	}

	// Search backwards for the pod cgroup path to make the sandbox use it,
	// instead of the pause container's cgroup.
	parts := strings.Split(spec.Linux.CgroupsPath, string(filepath.Separator))
	for i := len(parts) - 1; i >= 0; i-- {
		if strings.HasPrefix(parts[i], "pod") {
			var path string
			for j := 0; j <= i; j++ {
				path = filepath.Join(path, parts[j])
			}
			// Add back the initial '/' that may have been lost above.
			if filepath.IsAbs(spec.Linux.CgroupsPath) {
				path = string(filepath.Separator) + path
			}
			if spec.Linux.CgroupsPath == path {
				return false
			}
			spec.Linux.CgroupsPath = path
			return true
		}
	}
	return false
}

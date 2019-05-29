// +build linux

/*
   Copyright The containerd Authors.
   Copyright 2018 Google LLC

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

package v2

import (
	"context"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/containerd/cgroups"
	"github.com/containerd/console"
	eventstypes "github.com/containerd/containerd/api/events"
	"github.com/containerd/containerd/api/types/task"
	"github.com/containerd/containerd/errdefs"
	"github.com/containerd/containerd/events"
	"github.com/containerd/containerd/log"
	"github.com/containerd/containerd/mount"
	"github.com/containerd/containerd/namespaces"
	"github.com/containerd/containerd/runtime"
	"github.com/containerd/containerd/runtime/linux/runctypes"
	rproc "github.com/containerd/containerd/runtime/proc"
	"github.com/containerd/containerd/runtime/v2/shim"
	taskAPI "github.com/containerd/containerd/runtime/v2/task"
	runtimeoptions "github.com/containerd/cri/pkg/api/runtimeoptions/v1"
	"github.com/containerd/typeurl"
	ptypes "github.com/gogo/protobuf/types"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"

	runsc "github.com/google/gvisor-containerd-shim/pkg/go-runsc"
	"github.com/google/gvisor-containerd-shim/pkg/v1/proc"
	"github.com/google/gvisor-containerd-shim/pkg/v1/utils"
	"github.com/google/gvisor-containerd-shim/pkg/v2/options"
)

var (
	empty   = &ptypes.Empty{}
	bufPool = sync.Pool{
		New: func() interface{} {
			buffer := make([]byte, 32<<10)
			return &buffer
		},
	}
)

var _ = (taskAPI.TaskService)(&service{})

// configFile is the default config file name. For containerd 1.2,
// we assume that a config.toml should exist in the runtime root.
const configFile = "config.toml"

// New returns a new shim service that can be used via GRPC
func New(ctx context.Context, id string, publisher events.Publisher) (shim.Shim, error) {
	ctx, cancel := context.WithCancel(ctx)
	s := &service{
		id:        id,
		context:   ctx,
		processes: make(map[string]rproc.Process),
		events:    make(chan interface{}, 128),
		ec:        proc.ExitCh,
		cancel:    cancel,
	}
	go s.processExits()
	runsc.Monitor = shim.Default
	if err := s.initPlatform(); err != nil {
		cancel()
		return nil, errors.Wrap(err, "failed to initialized platform behavior")
	}
	go s.forward(publisher)
	return s, nil
}

// service is the shim implementation of a remote shim over GRPC
type service struct {
	mu sync.Mutex

	context   context.Context
	task      rproc.Process
	processes map[string]rproc.Process
	events    chan interface{}
	platform  rproc.Platform
	ec        chan proc.Exit

	id     string
	bundle string
	cancel func()
}

func newCommand(ctx context.Context, containerdBinary, containerdAddress string) (*exec.Cmd, error) {
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
	cmd := exec.Command(self, args...)
	cmd.Dir = cwd
	cmd.Env = append(os.Environ(), "GOMAXPROCS=2")
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: true,
	}
	return cmd, nil
}

func (s *service) StartShim(ctx context.Context, id, containerdBinary, containerdAddress string) (string, error) {
	cmd, err := newCommand(ctx, containerdBinary, containerdAddress)
	if err != nil {
		return "", err
	}
	address, err := shim.SocketAddress(ctx, id)
	if err != nil {
		return "", err
	}
	socket, err := shim.NewSocket(address)
	if err != nil {
		return "", err
	}
	defer socket.Close()
	f, err := socket.File()
	if err != nil {
		return "", err
	}
	defer f.Close()

	cmd.ExtraFiles = append(cmd.ExtraFiles, f)

	if err := cmd.Start(); err != nil {
		return "", err
	}
	defer func() {
		if err != nil {
			cmd.Process.Kill()
		}
	}()
	// make sure to wait after start
	go cmd.Wait()
	if err := shim.WritePidFile("shim.pid", cmd.Process.Pid); err != nil {
		return "", err
	}
	if err := shim.WriteAddress("address", address); err != nil {
		return "", err
	}
	if err := shim.SetScore(cmd.Process.Pid); err != nil {
		return "", errors.Wrap(err, "failed to set OOM Score on shim")
	}
	return address, nil
}

func (s *service) Cleanup(ctx context.Context) (*taskAPI.DeleteResponse, error) {
	path, err := os.Getwd()
	if err != nil {
		return nil, err
	}
	ns, err := namespaces.NamespaceRequired(ctx)
	if err != nil {
		return nil, err
	}
	runtime, err := s.readRuntime(path)
	if err != nil {
		return nil, err
	}
	r := proc.NewRunsc(proc.RunscRoot, path, ns, runtime, nil)
	if err := r.Delete(ctx, s.id, &runsc.DeleteOpts{
		Force: true,
	}); err != nil {
		logrus.WithError(err).Warn("failed to remove runc container")
	}
	if err := mount.UnmountAll(filepath.Join(path, "rootfs"), 0); err != nil {
		logrus.WithError(err).Warn("failed to cleanup rootfs mount")
	}
	return &taskAPI.DeleteResponse{
		ExitedAt:   time.Now(),
		ExitStatus: 128 + uint32(unix.SIGKILL),
	}, nil
}

func (s *service) readRuntime(path string) (string, error) {
	data, err := ioutil.ReadFile(filepath.Join(path, "runtime"))
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func (s *service) writeRuntime(path, runtime string) error {
	return ioutil.WriteFile(filepath.Join(path, "runtime"), []byte(runtime), 0600)
}

// Create a new initial process and container with the underlying OCI runtime
func (s *service) Create(ctx context.Context, r *taskAPI.CreateTaskRequest) (_ *taskAPI.CreateTaskResponse, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	ns, err := namespaces.NamespaceRequired(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "create namespace")
	}

	// Read from root for now.
	var opts options.Options
	if r.Options != nil {
		v, err := typeurl.UnmarshalAny(r.Options)
		if err != nil {
			return nil, err
		}
		var path string
		switch o := v.(type) {
		case *runctypes.CreateOptions: // containerd 1.2.x
			opts.IoUid = o.IoUid
			opts.IoGid = o.IoGid
			opts.ShimCgroup = o.ShimCgroup
		case *runctypes.RuncOptions: // containerd 1.2.x
			root := proc.RunscRoot
			if o.RuntimeRoot != "" {
				root = o.RuntimeRoot
			}

			opts.BinaryName = o.Runtime

			path = filepath.Join(root, configFile)
			if _, err := os.Stat(path); err != nil {
				if !os.IsNotExist(err) {
					return nil, errors.Wrapf(err, "stat config file %q", path)
				}
				// A config file in runtime root is not required.
				path = ""
			}
		case *runtimeoptions.Options: // containerd 1.3.x+
			if o.ConfigPath == "" {
				break
			}
			if o.TypeUrl != options.OptionType {
				return nil, errors.Errorf("unsupported runtimeoptions %q", o.TypeUrl)
			}
			path = o.ConfigPath
		default:
			return nil, errors.Errorf("unsupported option type %q", r.Options.TypeUrl)
		}
		if path != "" {
			if _, err = toml.DecodeFile(path, &opts); err != nil {
				return nil, errors.Wrapf(err, "decode config file %q", path)
			}
		}
	}

	var mounts []proc.Mount
	for _, m := range r.Rootfs {
		mounts = append(mounts, proc.Mount{
			Type:    m.Type,
			Source:  m.Source,
			Target:  m.Target,
			Options: m.Options,
		})
	}

	rootfs := filepath.Join(r.Bundle, "rootfs")
	if err := os.Mkdir(rootfs, 0711); err != nil && !os.IsExist(err) {
		return nil, err
	}

	config := &proc.CreateConfig{
		ID:       r.ID,
		Bundle:   r.Bundle,
		Runtime:  opts.BinaryName,
		Rootfs:   mounts,
		Terminal: r.Terminal,
		Stdin:    r.Stdin,
		Stdout:   r.Stdout,
		Stderr:   r.Stderr,
		Options:  r.Options,
	}
	if err := s.writeRuntime(r.Bundle, opts.BinaryName); err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			if err2 := mount.UnmountAll(rootfs, 0); err2 != nil {
				logrus.WithError(err2).Warn("failed to cleanup rootfs mount")
			}
		}
	}()
	for _, rm := range mounts {
		m := &mount.Mount{
			Type:    rm.Type,
			Source:  rm.Source,
			Options: rm.Options,
		}
		if err := m.Mount(rootfs); err != nil {
			return nil, errors.Wrapf(err, "failed to mount rootfs component %v", m)
		}
	}
	process, err := newInit(
		ctx,
		r.Bundle,
		filepath.Join(r.Bundle, "work"),
		ns,
		s.platform,
		config,
		&opts,
		rootfs,
	)
	if err != nil {
		return nil, errdefs.ToGRPC(err)
	}
	if err := process.Create(ctx, config); err != nil {
		return nil, errdefs.ToGRPC(err)
	}
	// save the main task id and bundle to the shim for additional requests
	s.id = r.ID
	s.bundle = r.Bundle
	s.task = process
	return &taskAPI.CreateTaskResponse{
		Pid: uint32(process.Pid()),
	}, nil

}

// Start a process
func (s *service) Start(ctx context.Context, r *taskAPI.StartRequest) (*taskAPI.StartResponse, error) {
	p, err := s.getProcess(r.ExecID)
	if err != nil {
		return nil, err
	}
	if err := p.Start(ctx); err != nil {
		return nil, err
	}
	return &taskAPI.StartResponse{
		Pid: uint32(p.Pid()),
	}, nil
}

// Delete the initial process and container
func (s *service) Delete(ctx context.Context, r *taskAPI.DeleteRequest) (*taskAPI.DeleteResponse, error) {
	p, err := s.getProcess(r.ExecID)
	if err != nil {
		return nil, err
	}
	if p == nil {
		return nil, errdefs.ToGRPCf(errdefs.ErrFailedPrecondition, "container must be created")
	}
	if err := p.Delete(ctx); err != nil {
		return nil, err
	}
	isTask := r.ExecID == ""
	if !isTask {
		s.mu.Lock()
		delete(s.processes, r.ExecID)
		s.mu.Unlock()
	}
	if isTask && s.platform != nil {
		s.platform.Close()
	}
	return &taskAPI.DeleteResponse{
		ExitStatus: uint32(p.ExitStatus()),
		ExitedAt:   p.ExitedAt(),
		Pid:        uint32(p.Pid()),
	}, nil
}

// Exec an additional process inside the container
func (s *service) Exec(ctx context.Context, r *taskAPI.ExecProcessRequest) (*ptypes.Empty, error) {
	s.mu.Lock()
	p := s.processes[r.ExecID]
	s.mu.Unlock()
	if p != nil {
		return nil, errdefs.ToGRPCf(errdefs.ErrAlreadyExists, "id %s", r.ExecID)
	}
	p = s.task
	if p == nil {
		return nil, errdefs.ToGRPCf(errdefs.ErrFailedPrecondition, "container must be created")
	}
	process, err := p.(*proc.Init).Exec(ctx, s.bundle, &proc.ExecConfig{
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

// ResizePty of a process
func (s *service) ResizePty(ctx context.Context, r *taskAPI.ResizePtyRequest) (*ptypes.Empty, error) {
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

// State returns runtime state information for a process
func (s *service) State(ctx context.Context, r *taskAPI.StateRequest) (*taskAPI.StateResponse, error) {
	p, err := s.getProcess(r.ExecID)
	if err != nil {
		return nil, err
	}
	st, err := p.Status(ctx)
	if err != nil {
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
	return &taskAPI.StateResponse{
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
	}, nil
}

// Pause the container
func (s *service) Pause(ctx context.Context, r *taskAPI.PauseRequest) (*ptypes.Empty, error) {
	return empty, errdefs.ToGRPC(errdefs.ErrNotImplemented)
}

// Resume the container
func (s *service) Resume(ctx context.Context, r *taskAPI.ResumeRequest) (*ptypes.Empty, error) {
	return empty, errdefs.ToGRPC(errdefs.ErrNotImplemented)
}

// Kill a process with the provided signal
func (s *service) Kill(ctx context.Context, r *taskAPI.KillRequest) (*ptypes.Empty, error) {
	p, err := s.getProcess(r.ExecID)
	if err != nil {
		return nil, err
	}
	if p == nil {
		return nil, errdefs.ToGRPCf(errdefs.ErrFailedPrecondition, "container must be created")
	}
	if err := p.Kill(ctx, r.Signal, r.All); err != nil {
		return nil, errdefs.ToGRPC(err)
	}
	return empty, nil
}

// Pids returns all pids inside the container
func (s *service) Pids(ctx context.Context, r *taskAPI.PidsRequest) (*taskAPI.PidsResponse, error) {
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
					return nil, errors.Wrapf(err, "failed to marshal process %d info", pid)
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

// CloseIO of a process
func (s *service) CloseIO(ctx context.Context, r *taskAPI.CloseIORequest) (*ptypes.Empty, error) {
	p, err := s.getProcess(r.ExecID)
	if err != nil {
		return nil, err
	}
	if stdin := p.Stdin(); stdin != nil {
		if err := stdin.Close(); err != nil {
			return nil, errors.Wrap(err, "close stdin")
		}
	}
	return empty, nil
}

// Checkpoint the container
func (s *service) Checkpoint(ctx context.Context, r *taskAPI.CheckpointTaskRequest) (*ptypes.Empty, error) {
	return empty, errdefs.ToGRPC(errdefs.ErrNotImplemented)
}

// Connect returns shim information such as the shim's pid
func (s *service) Connect(ctx context.Context, r *taskAPI.ConnectRequest) (*taskAPI.ConnectResponse, error) {
	var pid int
	if s.task != nil {
		pid = s.task.Pid()
	}
	return &taskAPI.ConnectResponse{
		ShimPid: uint32(os.Getpid()),
		TaskPid: uint32(pid),
	}, nil
}

func (s *service) Shutdown(ctx context.Context, r *taskAPI.ShutdownRequest) (*ptypes.Empty, error) {
	s.cancel()
	os.Exit(0)
	return empty, nil
}

func (s *service) Stats(ctx context.Context, r *taskAPI.StatsRequest) (*taskAPI.StatsResponse, error) {
	// TODO(random-liu): Use `runsc events --stats`.
	data, err := typeurl.MarshalAny(&cgroups.Metrics{})
	if err != nil {
		return nil, err
	}
	return &taskAPI.StatsResponse{
		Stats: data,
	}, nil
}

// Update a running container
func (s *service) Update(ctx context.Context, r *taskAPI.UpdateTaskRequest) (*ptypes.Empty, error) {
	return empty, errdefs.ToGRPC(errdefs.ErrNotImplemented)
}

// Wait for a process to exit
func (s *service) Wait(ctx context.Context, r *taskAPI.WaitRequest) (*taskAPI.WaitResponse, error) {
	p, err := s.getProcess(r.ExecID)
	if err != nil {
		return nil, err
	}
	if p == nil {
		return nil, errdefs.ToGRPCf(errdefs.ErrFailedPrecondition, "container must be created")
	}
	p.Wait()

	return &taskAPI.WaitResponse{
		ExitStatus: uint32(p.ExitStatus()),
		ExitedAt:   p.ExitedAt(),
	}, nil
}

func (s *service) processExits() {
	for e := range s.ec {
		s.checkProcesses(e)
	}
}

func (s *service) checkProcesses(e proc.Exit) {
	// TODO(random-liu): Add `shouldKillAll` logic if container pid
	// namespace is supported.
	for _, p := range s.allProcesses() {
		if p.ID() == e.ID {
			if ip, ok := p.(*proc.Init); ok {
				// Ensure all children are killed
				if err := ip.KillAll(s.context); err != nil {
					log.G(s.context).WithError(err).WithField("id", ip.ID()).
						Error("failed to kill init's children")
				}
			}
			p.SetExited(e.Status)
			s.events <- &eventstypes.TaskExit{
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

func (s *service) allProcesses() (o []rproc.Process) {
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
		return nil, errors.Wrapf(errdefs.ErrFailedPrecondition, "container must be created")
	}
	ps, err := p.(*proc.Init).Runtime().Ps(ctx, id)
	if err != nil {
		return nil, err
	}
	pids := make([]uint32, 0, len(ps))
	for _, pid := range ps {
		pids = append(pids, uint32(pid))
	}
	return pids, nil
}

func (s *service) forward(publisher events.Publisher) {
	for e := range s.events {
		ctx, cancel := context.WithTimeout(s.context, 5*time.Second)
		err := publisher.Publish(ctx, getTopic(e), e)
		cancel()
		if err != nil {
			logrus.WithError(err).Error("post event")
		}
	}
}

func (s *service) getProcess(execID string) (rproc.Process, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if execID == "" {
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
	case *eventstypes.TaskCreate:
		return runtime.TaskCreateEventTopic
	case *eventstypes.TaskStart:
		return runtime.TaskStartEventTopic
	case *eventstypes.TaskOOM:
		return runtime.TaskOOMEventTopic
	case *eventstypes.TaskExit:
		return runtime.TaskExitEventTopic
	case *eventstypes.TaskDelete:
		return runtime.TaskDeleteEventTopic
	case *eventstypes.TaskExecAdded:
		return runtime.TaskExecAddedEventTopic
	case *eventstypes.TaskExecStarted:
		return runtime.TaskExecStartedEventTopic
	default:
		logrus.Warnf("no topic for type %#v", e)
	}
	return runtime.TaskUnknownTopic
}

func newInit(ctx context.Context, path, workDir, namespace string, platform rproc.Platform, r *proc.CreateConfig, options *options.Options, rootfs string) (*proc.Init, error) {
	spec, err := utils.ReadSpec(r.Bundle)
	if err != nil {
		return nil, errors.Wrap(err, "read oci spec")
	}
	runsc.FormatLogPath(r.ID, options.RunscConfig)
	runtime := proc.NewRunsc(options.Root, path, namespace, options.BinaryName, options.RunscConfig)
	p := proc.New(r.ID, runtime, rproc.Stdio{
		Stdin:    r.Stdin,
		Stdout:   r.Stdout,
		Stderr:   r.Stderr,
		Terminal: r.Terminal,
	})
	p.Bundle = r.Bundle
	p.Platform = platform
	p.Rootfs = rootfs
	p.WorkDir = workDir
	p.IoUID = int(options.IoUid)
	p.IoGID = int(options.IoGid)
	p.Sandbox = utils.IsSandbox(spec)
	p.UserLog = utils.UserLogPath(spec)
	p.Monitor = shim.Default
	return p, nil
}

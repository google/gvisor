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

package v2

import (
	"context"
	"fmt"
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
	"golang.org/x/sys/unix"

	"gvisor.dev/gvisor/pkg/shim/runsc"
	"gvisor.dev/gvisor/pkg/shim/v1/proc"
	"gvisor.dev/gvisor/pkg/shim/v1/utils"
	"gvisor.dev/gvisor/pkg/shim/v2/options"
	"gvisor.dev/gvisor/pkg/shim/v2/runtimeoptions"
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

// configFile is the default config file name. For containerd 1.2,
// we assume that a config.toml should exist in the runtime root.
const configFile = "config.toml"

// New returns a new shim service that can be used via GRPC.
func New(ctx context.Context, id string, publisher shim.Publisher, cancel func()) (shim.Shim, error) {
	ep, err := newOOMEpoller(publisher)
	if err != nil {
		return nil, err
	}
	go ep.run(ctx)
	s := &service{
		id:        id,
		context:   ctx,
		processes: make(map[string]process.Process),
		events:    make(chan interface{}, 128),
		ec:        proc.ExitCh,
		oomPoller: ep,
		cancel:    cancel,
	}
	go s.processExits()
	runsc.Monitor = reaper.Default
	if err := s.initPlatform(); err != nil {
		cancel()
		return nil, fmt.Errorf("failed to initialized platform behavior: %w", err)
	}
	go s.forward(publisher)
	return s, nil
}

// service is the shim implementation of a remote shim over GRPC.
type service struct {
	mu sync.Mutex

	context   context.Context
	task      process.Process
	processes map[string]process.Process
	events    chan interface{}
	platform  stdio.Platform
	opts      options.Options
	ec        chan proc.Exit
	oomPoller *epoller

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

func (s *service) StartShim(ctx context.Context, id, containerdBinary, containerdAddress, containerdTTRPCAddress string) (string, error) {
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
		return "", fmt.Errorf("failed to set OOM Score on shim: %w", err)
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
	r := proc.NewRunsc(s.opts.Root, path, ns, runtime, nil)
	if err := r.Delete(ctx, s.id, &runsc.DeleteOpts{
		Force: true,
	}); err != nil {
		log.L.Printf("failed to remove runc container: %v", err)
	}
	if err := mount.UnmountAll(filepath.Join(path, "rootfs"), 0); err != nil {
		log.L.Printf("failed to cleanup rootfs mount: %v", err)
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

// Create creates a new initial process and container with the underlying OCI
// runtime.
func (s *service) Create(ctx context.Context, r *taskAPI.CreateTaskRequest) (_ *taskAPI.CreateTaskResponse, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	ns, err := namespaces.NamespaceRequired(ctx)
	if err != nil {
		return nil, fmt.Errorf("create namespace: %w", err)
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
					return nil, fmt.Errorf("stat config file %q: %w", path, err)
				}
				// A config file in runtime root is not required.
				path = ""
			}
		case *runtimeoptions.Options: // containerd 1.3.x+
			if o.ConfigPath == "" {
				break
			}
			if o.TypeUrl != options.OptionType {
				return nil, fmt.Errorf("unsupported option type %q", o.TypeUrl)
			}
			path = o.ConfigPath
		default:
			return nil, fmt.Errorf("unsupported option type %q", r.Options.TypeUrl)
		}
		if path != "" {
			if _, err = toml.DecodeFile(path, &opts); err != nil {
				return nil, fmt.Errorf("decode config file %q: %w", path, err)
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
			if err := mount.UnmountAll(rootfs, 0); err != nil {
				log.L.Printf("failed to cleanup rootfs mount: %v", err)
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
			return nil, fmt.Errorf("failed to mount rootfs component %v: %w", m, err)
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
	// Save the main task id and bundle to the shim for additional
	// requests.
	s.id = r.ID
	s.bundle = r.Bundle

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
	s.task = process
	s.opts = opts
	return &taskAPI.CreateTaskResponse{
		Pid: uint32(process.Pid()),
	}, nil

}

// Start starts a process.
func (s *service) Start(ctx context.Context, r *taskAPI.StartRequest) (*taskAPI.StartResponse, error) {
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

// Exec spawns an additional process inside the container.
func (s *service) Exec(ctx context.Context, r *taskAPI.ExecProcessRequest) (*types.Empty, error) {
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

// ResizePty resizes the terminal of a process.
func (s *service) ResizePty(ctx context.Context, r *taskAPI.ResizePtyRequest) (*types.Empty, error) {
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

// Pause the container.
func (s *service) Pause(ctx context.Context, r *taskAPI.PauseRequest) (*types.Empty, error) {
	return empty, errdefs.ToGRPC(errdefs.ErrNotImplemented)
}

// Resume the container.
func (s *service) Resume(ctx context.Context, r *taskAPI.ResumeRequest) (*types.Empty, error) {
	return empty, errdefs.ToGRPC(errdefs.ErrNotImplemented)
}

// Kill a process with the provided signal.
func (s *service) Kill(ctx context.Context, r *taskAPI.KillRequest) (*types.Empty, error) {
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

// Pids returns all pids inside the container.
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
	return empty, errdefs.ToGRPC(errdefs.ErrNotImplemented)
}

// Connect returns shim information such as the shim's pid.
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

func (s *service) Shutdown(ctx context.Context, r *taskAPI.ShutdownRequest) (*types.Empty, error) {
	s.cancel()
	os.Exit(0)
	return empty, nil
}

func (s *service) Stats(ctx context.Context, r *taskAPI.StatsRequest) (*taskAPI.StatsResponse, error) {
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
	rs := proc.NewRunsc(s.opts.Root, path, ns, runtime, nil)
	stats, err := rs.Stats(ctx, s.id)
	if err != nil {
		return nil, err
	}

	// gvisor currently (as of 2020-03-03) only returns the total memory
	// usage and current PID value[0]. However, we copy the common fields here
	// so that future updates will propagate correct information.  We're
	// using the cgroups.Metrics structure so we're returning the same type
	// as runc.
	//
	// [0]: https://github.com/google/gvisor/blob/277a0d5a1fbe8272d4729c01ee4c6e374d047ebc/runsc/boot/events.go#L61-L81
	data, err := typeurl.MarshalAny(&cgroups.Metrics{
		CPU: &cgroups.CPUStat{
			Usage: &cgroups.CPUUsage{
				Total:  stats.Cpu.Usage.Total,
				Kernel: stats.Cpu.Usage.Kernel,
				User:   stats.Cpu.Usage.User,
				PerCPU: stats.Cpu.Usage.Percpu,
			},
			Throttling: &cgroups.Throttle{
				Periods:          stats.Cpu.Throttling.Periods,
				ThrottledPeriods: stats.Cpu.Throttling.ThrottledPeriods,
				ThrottledTime:    stats.Cpu.Throttling.ThrottledTime,
			},
		},
		Memory: &cgroups.MemoryStat{
			Cache: stats.Memory.Cache,
			Usage: &cgroups.MemoryEntry{
				Limit:   stats.Memory.Usage.Limit,
				Usage:   stats.Memory.Usage.Usage,
				Max:     stats.Memory.Usage.Max,
				Failcnt: stats.Memory.Usage.Failcnt,
			},
			Swap: &cgroups.MemoryEntry{
				Limit:   stats.Memory.Swap.Limit,
				Usage:   stats.Memory.Swap.Usage,
				Max:     stats.Memory.Swap.Max,
				Failcnt: stats.Memory.Swap.Failcnt,
			},
			Kernel: &cgroups.MemoryEntry{
				Limit:   stats.Memory.Kernel.Limit,
				Usage:   stats.Memory.Kernel.Usage,
				Max:     stats.Memory.Kernel.Max,
				Failcnt: stats.Memory.Kernel.Failcnt,
			},
			KernelTCP: &cgroups.MemoryEntry{
				Limit:   stats.Memory.KernelTCP.Limit,
				Usage:   stats.Memory.KernelTCP.Usage,
				Max:     stats.Memory.KernelTCP.Max,
				Failcnt: stats.Memory.KernelTCP.Failcnt,
			},
		},
		Pids: &cgroups.PidsStat{
			Current: stats.Pids.Current,
			Limit:   stats.Pids.Limit,
		},
	})
	if err != nil {
		return nil, err
	}
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
				// Ensure all children are killed.
				if err := ip.KillAll(s.context); err != nil {
					log.G(s.context).WithError(err).WithField("id", ip.ID()).
						Error("failed to kill init's children")
				}
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

func (s *service) forward(publisher shim.Publisher) {
	for e := range s.events {
		ctx, cancel := context.WithTimeout(s.context, 5*time.Second)
		err := publisher.Publish(ctx, getTopic(e), e)
		cancel()
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
		log.L.Printf("no topic for type %#v", e)
	}
	return runtime.TaskUnknownTopic
}

func newInit(ctx context.Context, path, workDir, namespace string, platform stdio.Platform, r *proc.CreateConfig, options *options.Options, rootfs string) (*proc.Init, error) {
	spec, err := utils.ReadSpec(r.Bundle)
	if err != nil {
		return nil, fmt.Errorf("read oci spec: %w", err)
	}
	if err := utils.UpdateVolumeAnnotations(r.Bundle, spec); err != nil {
		return nil, fmt.Errorf("update volume annotations: %w", err)
	}
	runsc.FormatLogPath(r.ID, options.RunscConfig)
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
	p.IoUID = int(options.IoUid)
	p.IoGID = int(options.IoGid)
	p.Sandbox = specutils.SpecContainerType(spec) == specutils.ContainerTypeSandbox
	p.UserLog = utils.UserLogPath(spec)
	p.Monitor = reaper.Default
	return p, nil
}

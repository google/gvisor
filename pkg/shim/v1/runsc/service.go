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

// Package runsc implements Containerd Shim v2 interface.
package runsc

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/containerd/cgroups"
	cgroupsv2 "github.com/containerd/cgroups/v2"
	"github.com/containerd/containerd/api/events"
	"github.com/containerd/containerd/api/types/task"
	"github.com/containerd/containerd/pkg/process"
	"github.com/containerd/containerd/pkg/stdio"
	"github.com/containerd/containerd/runtime"
	"github.com/containerd/containerd/runtime/linux/runctypes"
	"github.com/containerd/containerd/runtime/v2/shim"
	taskAPI "github.com/containerd/containerd/runtime/v2/task"
	"github.com/containerd/containerd/sys/reaper"
	"github.com/containerd/errdefs"
	"github.com/containerd/log"
	"github.com/containerd/typeurl"
	"github.com/gogo/protobuf/types"
	specs "github.com/opencontainers/runtime-spec/specs-go"

	"gvisor.dev/gvisor/pkg/shim/v1/extension"
	"gvisor.dev/gvisor/pkg/shim/v1/proc"
	"gvisor.dev/gvisor/pkg/shim/v1/runsccmd"
	"gvisor.dev/gvisor/pkg/shim/v1/utils"
	"gvisor.dev/gvisor/runsc/specutils"
)

var (
	empty   = &types.Empty{}
	bufPool = sync.Pool{
		New: func() any {
			buffer := make([]byte, 32<<10)
			return &buffer
		},
	}
)

const (
	// configFile is the default config file name. For containerd 1.2,
	// we assume that a config.toml should exist in the runtime root.
	configFile = "config.toml"

	cgroupParentAnnotation = "dev.gvisor.spec.cgroup-parent"
)

type oomPoller interface {
	io.Closer
	// add adds `cg` cgroup to oom poller. `cg` is cgroups.Cgroup in v1 and
	// `cgroupsv2.Manager` in v2
	add(id string, cg any) error
	// run monitors oom event and notifies the shim about them
	run(ctx context.Context)
}

// runscService is the shim implementation of a remote shim over gRPC. It converts
// shim calls into `runsc` commands. It runs in 2 different modes:
//  1. Service: process runs for the life time of the container and receives
//     calls described in shimapi.TaskService interface.
//  2. Tool: process is short lived and runs only to perform the requested
//     operations and then exits. It implements the direct functions in
//     shim.Shim interface.
//
// When the service is running, it saves a json file with state information so
// that commands sent to the tool can load the state and perform the operation
// with the required context.
type runscService struct {
	mu sync.Mutex

	// id is the container ID.
	id string

	events chan any

	// platform handles operations related to the console.
	platform stdio.Platform

	// ex gets notified whenever the container init process or an exec'd process
	// exits from inside the sandbox.
	ec chan proc.Exit

	// oomPoller monitors the sandbox's cgroup for OOM notifications.
	oomPoller oomPoller

	// containers maps container id to a container.
	containers map[string]*Container
}

var _ extension.TaskServiceExt = (*runscService)(nil)

// NewTaskService returns a runsc task service.
func NewTaskService(ctx context.Context, id string, publisher shim.Publisher) (extension.TaskServiceExt, error) {
	var (
		ep  oomPoller
		err error
	)
	if cgroups.Mode() == cgroups.Unified {
		ep, err = newOOMv2Poller(publisher)
	} else {
		ep, err = newOOMEpoller(publisher)
	}
	if err != nil {
		return nil, err
	}
	go ep.run(ctx)
	s := &runscService{
		id:         id,
		events:     make(chan any, 128),
		containers: make(map[string]*Container),
		ec:         proc.ExitCh,
		oomPoller:  ep,
	}
	go s.processExits(ctx)
	runsccmd.Monitor = &runsccmd.LogMonitor{Next: reaper.Default}
	if err := s.initPlatform(); err != nil {
		return nil, fmt.Errorf("failed to initialized platform behavior: %w", err)
	}
	go s.forward(ctx, publisher)
	return s, nil
}

// getContainer returns the container by id.
func (s *runscService) getContainer(id string) (*Container, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.containers[id]
	if c == nil {
		return nil, errdefs.ToGRPCf(errdefs.ErrNotFound, "container not created")
	}
	return c, nil
}

// Create creates a new initial process and container with the underlying OCI
// runtime.
func (s *runscService) Create(ctx context.Context, r *taskAPI.CreateTaskRequest) (*taskAPI.CreateTaskResponse, error) {
	return s.CreateWithFSRestore(ctx, &extension.CreateWithFSRestoreRequest{
		Create: r,
	})
}

// CreateWithFSRestore is the same as Create, but it additionally restores the
// container's filesystem from a snapshot.
func (s *runscService) CreateWithFSRestore(ctx context.Context, rfs *extension.CreateWithFSRestoreRequest) (*taskAPI.CreateTaskResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	c, err := NewContainer(ctx, s.platform, rfs.Create, rfs.Conf.ImagePath, rfs.Conf.Direct)
	if err != nil {
		return nil, err
	}

	s.containers[rfs.Create.ID] = c

	p, err := c.Process("")
	if err != nil {
		return nil, err
	}

	// Set up OOM notification on the sandbox's cgroup. This is done on
	// sandbox create since the sandbox process will be created here.
	pid := p.Pid()
	if pid > 0 {
		var (
			cg  any
			err error
		)
		if cgroups.Mode() == cgroups.Unified {
			var cgPath string
			cgPath, err = cgroupsv2.PidGroupPath(pid)
			if err == nil {
				cg, err = cgroupsv2.LoadManager("/sys/fs/cgroup", cgPath)
			}
		} else {
			cg, err = cgroups.Load(cgroups.V1, cgroups.PidPath(pid))
		}
		if err != nil {
			return nil, fmt.Errorf("loading cgroup for %d: %w", pid, err)
		}
		if err := s.oomPoller.add(s.id, cg); err != nil {
			return nil, fmt.Errorf("add cg to OOM monitor: %w", err)
		}
	}
	return &taskAPI.CreateTaskResponse{
		Pid: uint32(pid),
	}, nil
}

// Start starts the container.
func (s *runscService) Start(ctx context.Context, r *taskAPI.StartRequest) (*taskAPI.StartResponse, error) {
	c, err := s.getContainer(r.ID)
	if err != nil {
		return nil, err
	}
	p, err := c.Start(ctx, r)
	if err != nil {
		return nil, errdefs.ToGRPC(err)
	}
	// TODO: Set the cgroup and oom notifications on restore.
	return &taskAPI.StartResponse{
		Pid: uint32(p.Pid()),
	}, nil
}

// Delete deletes the initial process and container.
func (s *runscService) Delete(ctx context.Context, r *taskAPI.DeleteRequest) (*taskAPI.DeleteResponse, error) {
	c, err := s.getContainer(r.ID)
	if err != nil {
		return nil, err
	}
	p, err := c.Delete(ctx, r)
	if err != nil {
		return nil, errdefs.ToGRPC(err)
	}

	// ExecID will be empty for init container process.
	if len(r.ExecID) == 0 {
		s.mu.Lock()
		delete(s.containers, r.ID)
		hasCont := len(s.containers) > 0
		s.mu.Unlock()

		if !hasCont && s.platform != nil {
			s.platform.Close()
		}
	}
	return &taskAPI.DeleteResponse{
		ExitStatus: uint32(p.ExitStatus()),
		ExitedAt:   p.ExitedAt(),
		Pid:        uint32(p.Pid()),
	}, nil
}

// Exec spawns an additional process inside the container.
func (s *runscService) Exec(ctx context.Context, r *taskAPI.ExecProcessRequest) (*types.Empty, error) {
	c, err := s.getContainer(r.ID)
	if err != nil {
		return nil, err
	}
	// Check whether or not the process already exists in the container.
	p, _ := c.Process(r.ExecID)
	if p != nil {
		return nil, errdefs.ToGRPCf(errdefs.ErrAlreadyExists, "id %s", r.ExecID)
	}
	p, err = c.Exec(ctx, r)
	if err != nil {
		return nil, err
	}
	s.send(&events.TaskExecAdded{
		ContainerID: r.ID,
		ExecID:      p.ID(),
	})
	return empty, nil
}

// ResizePty resizes the terminal of a process.
func (s *runscService) ResizePty(ctx context.Context, r *taskAPI.ResizePtyRequest) (*types.Empty, error) {
	c, err := s.getContainer(r.ID)
	if err != nil {
		return nil, errdefs.ToGRPCf(errdefs.ErrFailedPrecondition, "container must be created")
	}
	if err := c.ResizePty(ctx, r); err != nil {
		return nil, errdefs.ToGRPC(err)
	}
	return empty, nil
}

// State returns runtime state information for the container.
func (s *runscService) State(ctx context.Context, r *taskAPI.StateRequest) (*taskAPI.StateResponse, error) {
	c, err := s.getContainer(r.ID)
	if err != nil {
		return nil, err
	}
	p, err := c.Process(r.ExecID)
	if err != nil {
		log.L.Debugf("State failed to find process: %v", err)
		return nil, errdefs.ToGRPC(err)
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
	case "pausing":
		status = task.StatusPausing
	}
	sio := p.Stdio()
	return &taskAPI.StateResponse{
		ID:         p.ID(),
		Bundle:     c.Bundle,
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
func (s *runscService) Pause(ctx context.Context, r *taskAPI.PauseRequest) (*types.Empty, error) {
	c, err := s.getContainer(r.ID)
	if err != nil {
		return nil, err
	}
	if err := c.Pause(ctx, r); err != nil {
		return nil, errdefs.ToGRPC(err)
	}
	s.send(&events.TaskPaused{
		ContainerID: c.ID,
	})
	return empty, nil
}

// Resume the container.
func (s *runscService) Resume(ctx context.Context, r *taskAPI.ResumeRequest) (*types.Empty, error) {
	c, err := s.getContainer(r.ID)
	if err != nil {
		return nil, err
	}
	if err := c.Resume(ctx, r); err != nil {
		return nil, errdefs.ToGRPC(err)
	}
	s.send(&events.TaskResumed{
		ContainerID: c.ID,
	})
	return empty, nil
}

// Kill the container with the provided signal.
func (s *runscService) Kill(ctx context.Context, r *taskAPI.KillRequest) (*types.Empty, error) {
	c, err := s.getContainer(r.ID)
	if err != nil {
		return nil, err
	}
	if err := c.Kill(ctx, r); err != nil {
		return nil, errdefs.ToGRPC(err)
	}
	return empty, nil
}

// Pids returns all pids inside the container.
func (s *runscService) Pids(ctx context.Context, r *taskAPI.PidsRequest) (*taskAPI.PidsResponse, error) {
	c, err := s.getContainer(r.ID)
	if err != nil {
		return nil, err
	}
	pids, err := s.getContainerPids(ctx, c)
	if err != nil {
		return nil, errdefs.ToGRPC(err)
	}
	var processes []*task.ProcessInfo
	for _, pid := range pids {
		pInfo := task.ProcessInfo{
			Pid: pid,
		}
		for _, p := range c.ExecdProcesses() {
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

// CloseIO closes the I/O context of the container.
func (s *runscService) CloseIO(ctx context.Context, r *taskAPI.CloseIORequest) (*types.Empty, error) {
	c, err := s.getContainer(r.ID)
	if err != nil {
		return nil, err
	}
	if err := c.CloseIO(ctx, r); err != nil {
		return nil, errdefs.ToGRPC(err)
	}
	return empty, nil
}

// Checkpoint checkpoints the container.
func (s *runscService) Checkpoint(ctx context.Context, r *taskAPI.CheckpointTaskRequest) (*types.Empty, error) {
	return empty, errdefs.ErrNotImplemented
}

// Restore restores the container.
func (s *runscService) Restore(ctx context.Context, r *extension.RestoreRequest) (*taskAPI.StartResponse, error) {
	c, err := s.getContainer(r.Start.ID)
	if err != nil {
		return nil, err
	}
	p, err := c.Restore(ctx, r)
	if err != nil {
		return nil, err
	}
	return &taskAPI.StartResponse{
		Pid: uint32(p.Pid()),
	}, nil
}

// Connect returns shim information such as the shim's pid.
func (s *runscService) Connect(ctx context.Context, r *taskAPI.ConnectRequest) (*taskAPI.ConnectResponse, error) {
	var pid int
	if c, err := s.getContainer(r.ID); err == nil {
		pid = c.Pid()
	}
	return &taskAPI.ConnectResponse{
		ShimPid: uint32(os.Getpid()),
		TaskPid: uint32(pid),
	}, nil
}

func (s *runscService) Shutdown(ctx context.Context, r *taskAPI.ShutdownRequest) (*types.Empty, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// return out if the shim is still servicing containers
	if len(s.containers) > 0 {
		return empty, nil
	}

	return empty, nil
}

func (s *runscService) Stats(ctx context.Context, r *taskAPI.StatsRequest) (*taskAPI.StatsResponse, error) {
	c, err := s.getContainer(r.ID)
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
	return c.Stats(ctx)
}

// Update updates a running container.
func (s *runscService) Update(ctx context.Context, r *taskAPI.UpdateTaskRequest) (*types.Empty, error) {
	return empty, errdefs.ErrNotImplemented
}

// Wait waits for the container to exit.
func (s *runscService) Wait(ctx context.Context, r *taskAPI.WaitRequest) (*taskAPI.WaitResponse, error) {
	c, err := s.getContainer(r.ID)
	if err != nil {
		return nil, err
	}
	p, err := c.Process(r.ExecID)
	if err != nil {
		return nil, errdefs.ToGRPC(err)
	}
	p.Wait()

	res := &taskAPI.WaitResponse{
		ExitStatus: uint32(p.ExitStatus()),
		ExitedAt:   p.ExitedAt(),
	}
	log.L.Debugf("Wait succeeded, response: %+v", res)
	return res, nil
}

func (s *runscService) processExits(ctx context.Context) {
	for e := range s.ec {
		s.checkProcesses(ctx, e)
	}
}

func (s *runscService) checkProcesses(ctx context.Context, e proc.Exit) {
	for _, p := range s.allProcessesForAllContainers() {
		if p.ID() == e.ID {
			if ip, ok := p.(*proc.Init); ok {
				// Ensure all children are killed.
				log.L.Debugf("Container init process exited, killing all container processes")
				ip.KillAll(ctx)
			}
			p.SetExited(e.Status)
			s.send(&events.TaskExit{
				ContainerID: s.id,
				ID:          p.ID(),
				Pid:         uint32(p.Pid()),
				ExitStatus:  uint32(e.Status),
				ExitedAt:    p.ExitedAt(),
			})
			return
		}
	}
}

func (s *runscService) send(event any) {
	s.events <- event
}

func (s *runscService) allProcessesForAllContainers() (o []process.Process) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, p := range s.containers {
		for _, p := range p.All() {
			o = append(o, p)
		}
	}
	return o
}

func (s *runscService) getContainerPids(ctx context.Context, c *Container) ([]uint32, error) {
	p, err := c.Process("")
	if err != nil {
		return nil, err
	}
	ps, err := p.(*proc.Init).Runtime().Ps(ctx, c.ID)
	if err != nil {
		return nil, err
	}
	pids := make([]uint32, 0, len(ps))
	for _, pid := range ps {
		pids = append(pids, uint32(pid))
	}
	return pids, nil
}

func (s *runscService) forward(ctx context.Context, publisher shim.Publisher) {
	for e := range s.events {
		err := publisher.Publish(ctx, getTopic(e), e)
		if err != nil {
			// Should not happen.
			panic(fmt.Errorf("post event: %w", err))
		}
	}
}

func getTopic(e any) string {
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

func newInit(workDir, namespace string, platform stdio.Platform, r *proc.CreateConfig, options *Options, rootfs string) (*proc.Init, error) {
	spec, err := utils.ReadSpec(r.Bundle)
	if err != nil {
		return nil, fmt.Errorf("read oci spec: %w", err)
	}

	updated, err := utils.UpdateVolumeAnnotations(spec)
	if err != nil {
		return nil, fmt.Errorf("update volume annotations: %w", err)
	}
	updated = setPodCgroup(spec) || updated

	if updated {
		if err := utils.WriteSpec(r.Bundle, spec); err != nil {
			return nil, err
		}
	}

	runtime := proc.NewRunsc(options.Root, r.Bundle, namespace, options.BinaryName, options.RunscConfig, spec)
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

// setPodCgroup searches for the pod cgroup path inside the container's cgroup
// path. If found, it's set as an annotation in the spec. This is done so that
// the sandbox joins the pod cgroup. Otherwise, the sandbox would join the pause
// container cgroup. Returns true if the spec was modified. Ex.:
// /kubepods/burstable/pod123/container123 => kubepods/burstable/pod123
func setPodCgroup(spec *specs.Spec) bool {
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
			if spec.Annotations == nil {
				spec.Annotations = make(map[string]string)
			}
			spec.Annotations[cgroupParentAnnotation] = path
			return true
		}
	}
	return false
}

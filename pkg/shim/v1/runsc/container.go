// Copyright 2026 The gVisor Authors.
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

package runsc

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"

	"github.com/BurntSushi/toml"
	"github.com/containerd/cgroups"
	cgroupsstats "github.com/containerd/cgroups/stats/v1"
	cgroupsv2stats "github.com/containerd/cgroups/v2/stats"
	"github.com/containerd/console"
	"github.com/containerd/containerd/mount"
	"github.com/containerd/containerd/namespaces"
	"github.com/containerd/containerd/pkg/stdio"
	"github.com/containerd/containerd/runtime/v2/task"
	"github.com/containerd/errdefs"
	runc "github.com/containerd/go-runc"
	"github.com/containerd/log"
	"github.com/containerd/typeurl"
	"github.com/sirupsen/logrus"
	"gvisor.dev/gvisor/pkg/cleanup"
	"gvisor.dev/gvisor/pkg/shim/v1/extension"
	"gvisor.dev/gvisor/pkg/shim/v1/proc"
	"gvisor.dev/gvisor/pkg/shim/v1/runsccmd"
	"gvisor.dev/gvisor/pkg/shim/v1/runtimeoptions"
)

// CgroupMode is the cgroups mode that is being used by the container.
// Accepts values from the containerd cgroups package.
// Legacy for cgroups v1 and Unified for cgroups v2.
type CgroupMode int

// Container for operating on a runsc container and its processes
type Container struct {
	mu sync.Mutex

	// ID of the container
	ID string

	// Bundle path
	Bundle string

	// task is the main process that is running the container.
	task *proc.Init

	// processes maps ExecId to processes running through exec.
	//
	// +checklocks:mu
	processes map[string]extension.Process

	// cgroup is the cgroups mode that is being used by the container.
	cgroup CgroupMode
}

// NewContainer returns a new runsc container
func NewContainer(ctx context.Context, platform stdio.Platform, r *task.CreateTaskRequest, FSRestoreImagePath string, FSRestoreDirect bool) (*Container, error) {
	ns, err := namespaces.NamespaceRequired(ctx)
	if err != nil {
		return nil, fmt.Errorf("create namespace: %w", err)
	}
	var opts Options
	if r.Options != nil {
		v, err := typeurl.UnmarshalAny(r.Options)
		if err != nil {
			return nil, err
		}
		var path string
		switch o := v.(type) {
		case *runtimeoptions.Options: // containerd 1.5+
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
			// Read runsc options from the config file.
			if _, err = toml.DecodeFile(path, &opts); err != nil {
				return nil, fmt.Errorf("decode config file %q: %w", path, err)
			}
		}
	}

	if len(opts.LogLevel) != 0 {
		lvl, err := logrus.ParseLevel(opts.LogLevel)
		if err != nil {
			return nil, err
		}
		logrus.SetLevel(lvl)
	}
	if len(opts.LogPath) != 0 {
		logPath := runsccmd.FormatShimLogPath(opts.LogPath, r.ID)
		if err := os.MkdirAll(filepath.Dir(logPath), 0777); err != nil {
			return nil, fmt.Errorf("failed to create log dir: %w", err)
		}
		logFile, err := os.Create(logPath)
		if err != nil {
			return nil, fmt.Errorf("failed to create log file: %w", err)
		}
		std := logrus.StandardLogger()
		std.SetOutput(io.MultiWriter(std.Out, logFile))

		log.L.Debugf("Create runsc container")
		log.L.Debugf("***************************")
		log.L.Debugf("Args: %s", os.Args)
		log.L.Debugf("PID: %d", os.Getpid())
		log.L.Debugf("ID: %s", r.ID)
		log.L.Debugf("Options: %+v", opts)
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
	st := State{
		Rootfs:  filepath.Join(r.Bundle, "rootfs"),
		Options: opts,
	}
	if err := st.Save(r.Bundle); err != nil {
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
			log.L.Warningf("failed to cleanup rootfs mount: %v", err)
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
		ID:                 r.ID,
		Bundle:             r.Bundle,
		Runtime:            opts.BinaryName,
		Rootfs:             mounts,
		Terminal:           r.Terminal,
		Stdin:              r.Stdin,
		Stdout:             r.Stdout,
		Stderr:             r.Stderr,
		FSRestoreImagePath: FSRestoreImagePath,
		FSRestoreDirect:    FSRestoreDirect,
	}

	process, err := newInit(filepath.Join(r.Bundle, "work"), ns, platform, config, &opts, st.Rootfs)
	if err != nil {
		return nil, err
	}
	if err := process.Create(ctx, config); err != nil {
		return nil, err
	}
	// Set up cgroup mode.
	cgroupMode := CgroupMode(cgroups.Legacy)
	if opts.RunscConfig["systemd-cgroup"] == "true" {
		cgroupMode = CgroupMode(cgroups.Unified)
	}

	// Success
	cu.Release()
	c := Container{
		ID:        r.ID,
		Bundle:    r.Bundle,
		task:      process,
		cgroup:    cgroupMode,
		processes: make(map[string]extension.Process),
	}
	return &c, nil
}

// Pid of the main process of a container
func (c *Container) Pid() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.task.Pid()
}

// All processes in the container.
func (c *Container) All() []extension.Process {
	c.mu.Lock()
	defer c.mu.Unlock()

	o := make([]extension.Process, 0, len(c.processes)+1)
	for _, p := range c.processes {
		o = append(o, p)
	}
	if c.task != nil {
		o = append(o, c.task)
	}
	return o
}

// ExecdProcesses added to the container.
func (c *Container) ExecdProcesses() []extension.Process {
	c.mu.Lock()
	defer c.mu.Unlock()

	o := make([]extension.Process, 0, len(c.processes))
	for _, p := range c.processes {
		o = append(o, p)
	}
	return o
}

// Process returns the process by id.
// If id is empty, return the init process.
func (c *Container) Process(id string) (extension.Process, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if id == "" {
		if c.task == nil {
			return nil, fmt.Errorf("container must be created: %w", errdefs.ErrFailedPrecondition)
		}
		return c.task, nil
	}
	p, ok := c.processes[id]
	if !ok {
		return nil, fmt.Errorf("process does not exist %s: %w", id, errdefs.ErrNotFound)
	}
	return p, nil
}

// ProcessAdd adds a process to the container.
func (c *Container) ProcessAdd(p extension.Process) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.processes[p.ID()] = p
}

// ProcessRemove removes the process by id from the container.
func (c *Container) ProcessRemove(id string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.processes, id)
}

// Start a container process.
func (c *Container) Start(ctx context.Context, r *task.StartRequest) (extension.Process, error) {
	p, err := c.Process(r.ExecID)
	if err != nil {
		return nil, err
	}
	if err := p.Start(ctx); err != nil {
		return nil, err
	}
	return p, nil
}

// Delete the container or a process by id
func (c *Container) Delete(ctx context.Context, r *task.DeleteRequest) (extension.Process, error) {
	p, err := c.Process(r.ExecID)
	if err != nil {
		return nil, err
	}
	if err := p.Delete(ctx); err != nil {
		return nil, err
	}
	// When ExecID is empty, it removes the init task in the container.
	if r.ExecID != "" {
		c.ProcessRemove(r.ExecID)
	}
	return p, nil
}

// Exec starts an additional process in the container.
func (c *Container) Exec(ctx context.Context, r *task.ExecProcessRequest) (extension.Process, error) {
	if c.task == nil {
		return nil, fmt.Errorf("container must be created")
	}
	p, err := c.task.Exec(ctx, c.Bundle, &proc.ExecConfig{
		ID:       r.ExecID,
		Terminal: r.Terminal,
		Stdin:    r.Stdin,
		Stdout:   r.Stdout,
		Stderr:   r.Stderr,
		Spec:     r.Spec,
	})
	if err != nil {
		return nil, err
	}
	c.ProcessAdd(p)
	return p, nil
}

// ResizePty of a process
func (c *Container) ResizePty(ctx context.Context, r *task.ResizePtyRequest) error {
	p, err := c.Process(r.ExecID)
	if err != nil {
		return err
	}
	ws := console.WinSize{
		Width:  uint16(r.Width),
		Height: uint16(r.Height),
	}
	return p.Resize(ws)
}

// Pause the container.
func (c *Container) Pause(ctx context.Context, r *task.PauseRequest) error {
	if c.task == nil {
		log.L.Debugf("Pause error, id: %s: container not created", r.ID)
		return fmt.Errorf("container must be created")
	}
	return c.task.Runtime().Pause(ctx, r.ID)
}

// Resume the container.
func (c *Container) Resume(ctx context.Context, r *task.ResumeRequest) error {
	if c.task == nil {
		log.L.Debugf("Resume error, id: %s: container not created", r.ID)
		return fmt.Errorf("container must be created")
	}
	return c.task.Runtime().Resume(ctx, r.ID)
}

// Kill a process with the provided signal
func (c *Container) Kill(ctx context.Context, r *task.KillRequest) error {
	p, err := c.Process(r.ExecID)
	if err != nil {
		log.L.Debugf("Kill failed: %v", err)
		return err
	}
	return p.Kill(ctx, r.Signal, r.All)
}

// CloseIO of a process.
func (c *Container) CloseIO(ctx context.Context, r *task.CloseIORequest) error {
	p, err := c.Process(r.ExecID)
	if err != nil {
		return err
	}
	if stdin := p.Stdin(); stdin != nil {
		if err := stdin.Close(); err != nil {
			return fmt.Errorf("close stdin: %w", err)
		}
	}
	return nil
}

// Update applies cgroup resource limits for the init task.
func (c *Container) Update(ctx context.Context, r *task.UpdateTaskRequest) error {
	if r.Resources == nil {
		return fmt.Errorf("resources are required: %w", errdefs.ErrInvalidArgument)
	}
	p, err := c.Process("")
	if err != nil {
		return err
	}
	return p.(*proc.Init).Update(ctx, r.Resources)
}

// Restore a process in the container.
func (c *Container) Restore(ctx context.Context, r *extension.RestoreRequest) (extension.Process, error) {
	p, err := c.Process(r.Start.ExecID)
	if err != nil {
		return nil, err
	}
	if err := p.Restore(ctx, &r.Conf); err != nil {
		return nil, err
	}
	// TODO: Set the cgroup and oom notifications on restore.
	// https://github.com/google/gvisor-containerd-shim/issues/58
	return p, nil
}

// Stats returns the stats for the container.
func (c *Container) Stats(ctx context.Context) (*task.StatsResponse, error) {
	p, err := c.Process("")
	if err != nil {
		return nil, errdefs.ToGRPC(err)
	}
	stats, err := p.(*proc.Init).Stats(ctx, c.ID)
	if err != nil {
		log.L.Debugf("Stats error, id: %s: %v", c.ID, err)
		return nil, err
	}
	switch c.cgroup {
	case CgroupMode(cgroups.Legacy):
		return c.getV1Stats(stats)
	case CgroupMode(cgroups.Unified):
		return c.getV2Stats(stats)
	default:
		return nil, errdefs.ErrInvalidArgument
	}
}

func (c *Container) getV1Stats(stats *runc.Stats) (*task.StatsResponse, error) {
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
		log.L.Debugf("Stats error v1, id: %s: %v", c.ID, err)
		return nil, err
	}
	return &task.StatsResponse{
		Stats: data,
	}, nil
}

func (c *Container) getV2Stats(stats *runc.Stats) (*task.StatsResponse, error) {
	metrics := &cgroupsv2stats.Metrics{
		// The CGroup V2 stats are in microseconds instead of nanoseconds so divide by 1000
		CPU: &cgroupsv2stats.CPUStat{
			UsageUsec:     stats.Cpu.Usage.Total / 1000,
			UserUsec:      stats.Cpu.Usage.User / 1000,
			SystemUsec:    stats.Cpu.Usage.Kernel / 1000,
			NrPeriods:     stats.Cpu.Throttling.Periods,
			NrThrottled:   stats.Cpu.Throttling.ThrottledPeriods,
			ThrottledUsec: stats.Cpu.Throttling.ThrottledTime / 1000,
		},
		Memory: &cgroupsv2stats.MemoryStat{
			Usage:      stats.Memory.Usage.Usage,
			UsageLimit: stats.Memory.Usage.Limit,
			SwapUsage:  stats.Memory.Swap.Usage,
			SwapLimit:  stats.Memory.Swap.Limit,
			Slab:       stats.Memory.Kernel.Usage,
			File:       stats.Memory.Cache,
		},
		Pids: &cgroupsv2stats.PidsStat{
			Current: stats.Pids.Current,
			Limit:   stats.Pids.Limit,
		},
	}
	data, err := typeurl.MarshalAny(metrics)
	if err != nil {
		log.L.Debugf("Stats error v2, id: %s: %v", c.ID, err)
		return nil, err
	}
	return &task.StatsResponse{
		Stats: data,
	}, nil
}

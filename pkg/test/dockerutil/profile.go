// Copyright 2020 The gVisor Authors.
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

package dockerutil

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

// Profile represents profile-like operations on a container,
// such as running perf or pprof. It is meant to be added to containers
// such that the container type calls the Profile during its lifecycle.
type Profile interface {
	// OnCreate is called just after the container is created when the container
	// has a valid ID (e.g. c.ID()).
	OnCreate(c *Container) error

	// OnStart is called just after the container is started when the container
	// has a valid Pid (e.g. c.SandboxPid()).
	OnStart(c *Container) error

	// Restart restarts the Profile on request.
	Restart(c *Container) error

	// OnCleanUp is called during the container's cleanup method.
	// Cleanups should just log errors if they have them.
	OnCleanUp(c *Container) error
}

// Pprof is for running profiles with 'runsc debug'. Pprof workloads
// should be run as root and ONLY against runsc sandboxes. The runtime
// should have --profile set as an option in /etc/docker/daemon.json in
// order for profiling to work with Pprof.
type Pprof struct {
	BasePath         string // path to put profiles
	BlockProfile     bool
	CPUProfile       bool
	GoRoutineProfile bool
	HeapProfile      bool
	MutexProfile     bool
	Duration         time.Duration // duration to run profiler e.g. '10s' or '1m'.
	shouldRun        bool
	cmd              *exec.Cmd
	stdout           io.ReadCloser
	stderr           io.ReadCloser
}

// MakePprofFromFlags makes a Pprof profile from flags.
func MakePprofFromFlags(c *Container) *Pprof {
	if !(*pprofBlock || *pprofCPU || *pprofGo || *pprofHeap || *pprofMutex) {
		return nil
	}
	return &Pprof{
		BasePath:         filepath.Join(*pprofBaseDir, c.runtime, c.Name),
		BlockProfile:     *pprofBlock,
		CPUProfile:       *pprofCPU,
		GoRoutineProfile: *pprofGo,
		HeapProfile:      *pprofHeap,
		MutexProfile:     *pprofMutex,
		Duration:         *duration,
	}
}

// OnCreate implements Profile.OnCreate.
func (p *Pprof) OnCreate(c *Container) error {
	return os.MkdirAll(p.BasePath, 0755)
}

// OnStart implements Profile.OnStart.
func (p *Pprof) OnStart(c *Container) error {
	path, err := RuntimePath()
	if err != nil {
		return fmt.Errorf("failed to get runtime path: %v", err)
	}

	// The root directory of this container's runtime.
	root := fmt.Sprintf("--root=/var/run/docker/runtime-%s/moby", c.runtime)
	// Format is `runsc --root=rootdir debug --profile-*=file --duration=* containerID`.
	args := []string{root, "debug"}
	args = append(args, p.makeProfileArgs(c)...)
	args = append(args, c.ID())

	// Best effort wait until container is running.
	for now := time.Now(); time.Since(now) < 5*time.Second; {
		if status, err := c.Status(context.Background()); err != nil {
			return fmt.Errorf("failed to get status with: %v", err)

		} else if status.Running {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	p.cmd = exec.Command(path, args...)
	if err := p.cmd.Start(); err != nil {
		return fmt.Errorf("process failed: %v", err)
	}
	return nil
}

// Restart implements Profile.Restart.
func (p *Pprof) Restart(c *Container) error {
	p.OnCleanUp(c)
	return p.OnStart(c)
}

// OnCleanUp implements Profile.OnCleanup
func (p *Pprof) OnCleanUp(c *Container) error {
	defer func() { p.cmd = nil }()
	if p.cmd != nil && p.cmd.Process != nil && p.cmd.ProcessState != nil && !p.cmd.ProcessState.Exited() {
		return p.cmd.Process.Kill()
	}
	return nil
}

// makeProfileArgs turns Pprof fields into runsc debug flags.
func (p *Pprof) makeProfileArgs(c *Container) []string {
	var ret []string
	if p.BlockProfile {
		ret = append(ret, fmt.Sprintf("--profile-block=%s", filepath.Join(p.BasePath, "block.pprof")))
	}
	if p.CPUProfile {
		ret = append(ret, fmt.Sprintf("--profile-cpu=%s", filepath.Join(p.BasePath, "cpu.pprof")))
	}
	if p.GoRoutineProfile {
		ret = append(ret, fmt.Sprintf("--profile-goroutine=%s", filepath.Join(p.BasePath, "go.pprof")))
	}
	if p.HeapProfile {
		ret = append(ret, fmt.Sprintf("--profile-heap=%s", filepath.Join(p.BasePath, "heap.pprof")))
	}
	if p.MutexProfile {
		ret = append(ret, fmt.Sprintf("--profile-mutex=%s", filepath.Join(p.BasePath, "mutex.pprof")))
	}
	ret = append(ret, fmt.Sprintf("--duration=%s", p.Duration))
	return ret
}

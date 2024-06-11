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
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"time"

	"golang.org/x/sys/unix"
)

// profile represents profile-like operations on a container.
//
// It is meant to be added to containers such that the container type calls
// the profile during its lifecycle. Standard implementations are below.

// profile is for running profiles with 'runsc debug'.
type profile struct {
	BasePath    string
	Types       []string
	Duration    time.Duration
	errorBuf    bytes.Buffer
	isProfiling bool
	cmd         *exec.Cmd
}

// profileInit initializes a profile object, if required.
//
// N.B. The profiling filename initialized here will use the *image*
// name, and not the unique container name. This is intentional. Most
// of the time, profiling will be used for benchmarks. Benchmarks will
// be run iteratively until a sufficiently large N is reached. It is
// useful in this context to overwrite previous runs, and generate a
// single profile result for the final test.
func (c *Container) profileInit(image string) {
	if !*pprofBlock && !*pprofCPU && !*pprofMutex && !*pprofHeap && !*trace {
		return // Nothing to do.
	}
	c.profile = &profile{
		BasePath: filepath.Join(*pprofBaseDir, c.runtime, c.logger.Name(), image),
		Duration: *pprofDuration,
	}
	if *pprofCPU {
		c.profile.Types = append(c.profile.Types, "cpu")
	}
	if *pprofHeap {
		c.profile.Types = append(c.profile.Types, "heap")
	}
	if *pprofMutex {
		c.profile.Types = append(c.profile.Types, "mutex")
	}
	if *pprofBlock {
		c.profile.Types = append(c.profile.Types, "block")
	}
}

// createProcess creates the collection process.
func (p *profile) createProcess(c *Container) error {
	// Ensure our directory exists.
	if err := os.MkdirAll(p.BasePath, 0755); err != nil {
		return err
	}

	// Find the runtime to invoke.
	path, err := RuntimePath()
	if err != nil {
		return fmt.Errorf("failed to get runtime path: %v", err)
	}

	rootDir, err := c.RootDirectory()
	if err != nil {
		return fmt.Errorf("failed to get root directory: %v", err)
	}

	// Format is `runsc --debug-log=/dev/stderr --root=rootDir debug --profile-*=file --duration=24h containerID`.
	args := []string{"--debug-log=/dev/stderr", fmt.Sprintf("--root=%s", rootDir), "debug"}
	for _, profileArg := range p.Types {
		p.isProfiling = true
		outputPath := filepath.Join(p.BasePath, fmt.Sprintf("%s.pprof", profileArg))
		args = append(args, fmt.Sprintf("--profile-%s=%s", profileArg, outputPath))
	}
	if *trace {
		p.isProfiling = true
		args = append(args, fmt.Sprintf("--trace=%s", filepath.Join(p.BasePath, "sentry.trace")))
	}
	args = append(args, fmt.Sprintf("--duration=%s", p.Duration)) // Or until container exits.
	args = append(args, fmt.Sprintf("--delay=%s", p.Duration))    // Ditto.
	args = append(args, c.ID())

	// Best effort wait until container is running.
	for now := time.Now(); time.Since(now) < 5*time.Second; {
		if status, err := c.Status(context.Background()); err != nil {
			return fmt.Errorf("failed to get status with: %v", err)
		} else if status.Running {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	p.cmd = exec.Command(path, args...)
	p.cmd.Stderr = &p.errorBuf
	if err := p.cmd.Start(); err != nil {
		return fmt.Errorf("start process failed: %v", err)
	}

	return nil
}

// killProcess kills the process, if running.
func (p *profile) killProcess() error {
	if p.cmd != nil && p.cmd.Process != nil {
		return p.cmd.Process.Signal(unix.SIGTERM)
	}
	return nil
}

// waitProcess waits for the process, if running.
func (p *profile) waitProcess() error {
	defer func() { p.cmd = nil }()
	if p.cmd != nil {
		return p.cmd.Wait()
	}
	return nil
}

// Start is called when profiling is started.
func (p *profile) Start(c *Container) error {
	return p.createProcess(c)
}

// Stop is called when profiling is started.
func (p *profile) Stop(c *Container) error {
	killErr := p.killProcess()
	waitErr := p.waitProcess()
	if waitErr != nil || killErr != nil {
		if output := p.errorBuf.String(); output != "" {
			fmt.Fprintf(os.Stderr, "\nprofile subcommand output:\n%s\n", output)
			p.errorBuf.Reset()
		}
		if p.isProfiling {
			runtimeArgs, err := RuntimeArgs()
			if err != nil {
				return fmt.Errorf("profiling failed (%v / %v) and we failed to get runtime args (%v); perhaps the runtime is not configured for profiling", killErr, waitErr, err)
			}
			profileEnabled := false
			for _, possibleFlag := range []string{"-profile", "--profile", "-profile=true", "--profile=true"} {
				if slices.Contains(runtimeArgs, possibleFlag) {
					profileEnabled = true
					break
				}
			}
			if !profileEnabled {
				return errors.New("runtime does not have profiling enabled, profiling will not work; either disable profiling (e.g. BENCHMARKS_PROFILE='') or add --profile=true to runtime flags")
			}
		}
	}
	if waitErr != nil && killErr != nil {
		return killErr
	}
	return waitErr // Ignore okay wait, err kill.
}

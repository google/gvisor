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

package cmd

import (
	"context"
	"os"
	"syscall"
	"time"

	"flag"
	"github.com/google/subcommands"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/runsc/boot"
	"gvisor.dev/gvisor/runsc/container"
)

// Debug implements subcommands.Command for the "debug" command.
type Debug struct {
	pid          int
	stacks       bool
	signal       int
	profileHeap  string
	profileCPU   string
	profileDelay int
	trace        string
}

// Name implements subcommands.Command.
func (*Debug) Name() string {
	return "debug"
}

// Synopsis implements subcommands.Command.
func (*Debug) Synopsis() string {
	return "shows a variety of debug information"
}

// Usage implements subcommands.Command.
func (*Debug) Usage() string {
	return `debug [flags] <container id>`
}

// SetFlags implements subcommands.Command.
func (d *Debug) SetFlags(f *flag.FlagSet) {
	f.IntVar(&d.pid, "pid", 0, "sandbox process ID. Container ID is not necessary if this is set")
	f.BoolVar(&d.stacks, "stacks", false, "if true, dumps all sandbox stacks to the log")
	f.StringVar(&d.profileHeap, "profile-heap", "", "writes heap profile to the given file.")
	f.StringVar(&d.profileCPU, "profile-cpu", "", "writes CPU profile to the given file.")
	f.IntVar(&d.profileDelay, "profile-delay", 5, "amount of time to wait before stoping CPU profile")
	f.StringVar(&d.trace, "trace", "", "writes an execution trace to the given file.")
	f.IntVar(&d.signal, "signal", -1, "sends signal to the sandbox")
}

// Execute implements subcommands.Command.Execute.
func (d *Debug) Execute(_ context.Context, f *flag.FlagSet, args ...interface{}) subcommands.ExitStatus {
	var c *container.Container
	conf := args[0].(*boot.Config)

	if d.pid == 0 {
		// No pid, container ID must have been provided.
		if f.NArg() != 1 {
			f.Usage()
			return subcommands.ExitUsageError
		}
		var err error
		c, err = container.Load(conf.RootDir, f.Arg(0))
		if err != nil {
			Fatalf("loading container %q: %v", f.Arg(0), err)
		}
	} else {
		if f.NArg() != 0 {
			f.Usage()
			return subcommands.ExitUsageError
		}
		// Go over all sandboxes and find the one that matches PID.
		ids, err := container.List(conf.RootDir)
		if err != nil {
			Fatalf("listing containers: %v", err)
		}
		for _, id := range ids {
			candidate, err := container.Load(conf.RootDir, id)
			if err != nil {
				Fatalf("loading container %q: %v", id, err)
			}
			if candidate.SandboxPid() == d.pid {
				c = candidate
				break
			}
		}
		if c == nil {
			Fatalf("container with PID %d not found", d.pid)
		}
	}

	if c.Sandbox == nil || !c.Sandbox.IsRunning() {
		Fatalf("container sandbox is not running")
	}
	log.Infof("Found sandbox %q, PID: %d", c.Sandbox.ID, c.Sandbox.Pid)

	if d.signal > 0 {
		log.Infof("Sending signal %d to process: %d", d.signal, c.Sandbox.Pid)
		if err := syscall.Kill(c.Sandbox.Pid, syscall.Signal(d.signal)); err != nil {
			Fatalf("failed to send signal %d to processs %d", d.signal, c.Sandbox.Pid)
		}
	}
	if d.stacks {
		log.Infof("Retrieving sandbox stacks")
		stacks, err := c.Sandbox.Stacks()
		if err != nil {
			Fatalf("retrieving stacks: %v", err)
		}
		log.Infof("     *** Stack dump ***\n%s", stacks)
	}
	if d.profileHeap != "" {
		f, err := os.Create(d.profileHeap)
		if err != nil {
			Fatalf(err.Error())
		}
		defer f.Close()

		if err := c.Sandbox.HeapProfile(f); err != nil {
			Fatalf(err.Error())
		}
		log.Infof("Heap profile written to %q", d.profileHeap)
	}

	delay := false
	if d.profileCPU != "" {
		delay = true
		f, err := os.Create(d.profileCPU)
		if err != nil {
			Fatalf(err.Error())
		}
		defer func() {
			f.Close()
			if err := c.Sandbox.StopCPUProfile(); err != nil {
				Fatalf(err.Error())
			}
			log.Infof("CPU profile written to %q", d.profileCPU)
		}()
		if err := c.Sandbox.StartCPUProfile(f); err != nil {
			Fatalf(err.Error())
		}
		log.Infof("CPU profile started for %d sec, writing to %q", d.profileDelay, d.profileCPU)
	}
	if d.trace != "" {
		delay = true
		f, err := os.Create(d.trace)
		if err != nil {
			Fatalf(err.Error())
		}
		defer func() {
			f.Close()
			if err := c.Sandbox.StopTrace(); err != nil {
				Fatalf(err.Error())
			}
			log.Infof("Trace written to %q", d.trace)
		}()
		if err := c.Sandbox.StartTrace(f); err != nil {
			Fatalf(err.Error())
		}
		log.Infof("Tracing started for %d sec, writing to %q", d.profileDelay, d.trace)

	}

	if delay {
		time.Sleep(time.Duration(d.profileDelay) * time.Second)

	}

	return subcommands.ExitSuccess
}

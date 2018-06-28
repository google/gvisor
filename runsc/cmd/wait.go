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

package cmd

import (
	"syscall"

	"context"
	"flag"
	"github.com/google/subcommands"
	"gvisor.googlesource.com/gvisor/runsc/boot"
	"gvisor.googlesource.com/gvisor/runsc/container"
)

const (
	unsetPID = -1
)

// Wait implements subcommands.Command for the "wait" command.
type Wait struct {
	rootPID int
	pid     int
}

// Name implements subcommands.Command.Name.
func (*Wait) Name() string {
	return "wait"
}

// Synopsis implements subcommands.Command.Synopsis.
func (*Wait) Synopsis() string {
	return "wait on a process inside a container"
}

// Usage implements subcommands.Command.Usage.
func (*Wait) Usage() string {
	return `wait [flags] <container id>`
}

// SetFlags implements subcommands.Command.SetFlags.
func (wt *Wait) SetFlags(f *flag.FlagSet) {
	f.IntVar(&wt.rootPID, "rootpid", unsetPID, "select a PID in the sandbox root PID namespace to wait on instead of the container's root process")
	f.IntVar(&wt.pid, "pid", unsetPID, "select a PID in the container's PID namespace to wait on instead of the container's root process")
}

// Execute implements subcommands.Command.Execute. It waits for a process in a
// container to exit before returning.
func (wt *Wait) Execute(_ context.Context, f *flag.FlagSet, args ...interface{}) subcommands.ExitStatus {
	if f.NArg() != 1 {
		f.Usage()
		return subcommands.ExitUsageError
	}
	// You can't specify both -pid and -rootpid.
	if wt.rootPID != unsetPID && wt.pid != unsetPID {
		Fatalf("only up to one of -pid and -rootPid can be set")
	}

	id := f.Arg(0)
	conf := args[0].(*boot.Config)

	c, err := container.Load(conf.RootDir, id)
	if err != nil {
		Fatalf("error loading container: %v", err)
	}

	waitStatus := args[1].(*syscall.WaitStatus)
	switch {
	// Wait on the whole container.
	case wt.rootPID == unsetPID && wt.pid == unsetPID:
		ws, err := c.Wait()
		if err != nil {
			Fatalf("error waiting on container %q: %v", c.ID, err)
		}
		*waitStatus = ws
	// Wait on a PID in the root PID namespace.
	case wt.rootPID != unsetPID:
		ws, err := c.WaitRootPID(int32(wt.rootPID))
		if err != nil {
			Fatalf("error waiting on PID in root PID namespace %d in container %q: %v", wt.rootPID, c.ID, err)
		}
		*waitStatus = ws
	// Wait on a PID in the container's PID namespace.
	case wt.pid != unsetPID:
		ws, err := c.WaitPID(int32(wt.pid))
		if err != nil {
			Fatalf("error waiting on PID %d in container %q: %v", wt.pid, c.ID, err)
		}
		*waitStatus = ws
	}
	return subcommands.ExitSuccess
}

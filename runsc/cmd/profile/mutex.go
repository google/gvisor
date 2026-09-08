// Copyright 2026 The gVisor Authors.
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

package profile

import (
	"context"
	"os"
	"time"

	"github.com/google/subcommands"
	"gvisor.dev/gvisor/runsc/cmd/util"
	"gvisor.dev/gvisor/runsc/config"
	"gvisor.dev/gvisor/runsc/container"
	"gvisor.dev/gvisor/runsc/flag"
)

// mutex implements subcommands.Command for the "mutex" command.
type mutex struct {
	duration time.Duration
	output   string
}

// Name implements subcommands.Command.
func (*mutex) Name() string {
	return "mutex"
}

// Synopsis implements subcommands.Command.
func (*mutex) Synopsis() string {
	return "collects a mutex contention profile of a running sandbox"
}

// Usage implements subcommands.Command.
func (*mutex) Usage() string {
	return "mutex [flags] <container id> - collects a mutex profile of the sandbox\n"
}

// SetFlags implements subcommands.Command.
func (m *mutex) SetFlags(f *flag.FlagSet) {
	f.DurationVar(&m.duration, "duration", 30*time.Second, "amount of time to collect the mutex profile")
	f.StringVar(&m.output, "output", "", "path to write mutex profile output (default: stdout)")
}

// Execute implements subcommands.Command.
func (m *mutex) Execute(_ context.Context, f *flag.FlagSet, args ...any) subcommands.ExitStatus {
	if f.NArg() != 1 {
		if f.Usage != nil {
			f.Usage()
		}
		return subcommands.ExitUsageError
	}

	id := f.Arg(0)
	conf := args[0].(*config.Config)

	opts := container.LoadOpts{
		SkipCheck:     true,
		RootContainer: true,
	}
	cont, err := container.Load(conf.RootDir, container.FullID{ContainerID: id}, opts)
	if err != nil {
		util.Fatalf("loading sandbox: %v", err)
	}

	if !cont.IsSandboxRunning() {
		util.Fatalf("container sandbox is not running")
	}

	out := os.Stdout
	if m.output != "" {
		f, err := os.OpenFile(m.output, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
		if err != nil {
			util.Fatalf("failed to open output file: %v", err)
		}
		defer f.Close()
		out = f
	}

	util.Infof("Collecting mutex profile for sandbox %q (%v)...", cont.Sandbox.ID, m.duration)
	if err := cont.Sandbox.MutexProfile(out, m.duration); err != nil {
		util.Fatalf("mutex profiling failed: %v", err)
	}
	if m.output != "" {
		util.Infof("Mutex profile written to %s", m.output)
	}
	return subcommands.ExitSuccess
}

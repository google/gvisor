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

// trace implements subcommands.Command for the "trace" command.
type trace struct {
	duration time.Duration
	output   string
}

// Name implements subcommands.Command.
func (*trace) Name() string {
	return "trace"
}

// Synopsis implements subcommands.Command.
func (*trace) Synopsis() string {
	return "collects an execution trace of a running sandbox"
}

// Usage implements subcommands.Command.
func (*trace) Usage() string {
	return "trace [flags] <container id> - collects an execution trace of the sandbox\n"
}

// SetFlags implements subcommands.Command.
func (t *trace) SetFlags(f *flag.FlagSet) {
	f.DurationVar(&t.duration, "duration", 30*time.Second, "amount of time to collect the execution trace")
	f.StringVar(&t.output, "output", "", "path to write trace profile output (default: stdout)")
}

// Execute implements subcommands.Command.
func (t *trace) Execute(_ context.Context, f *flag.FlagSet, args ...any) subcommands.ExitStatus {
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
	if t.output != "" {
		f, err := os.OpenFile(t.output, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
		if err != nil {
			util.Fatalf("failed to open output file: %v", err)
		}
		defer f.Close()
		out = f
	}

	util.Infof("Collecting execution trace for sandbox %q (%v)...", cont.Sandbox.ID, t.duration)
	if err := cont.Sandbox.Trace(out, t.duration); err != nil {
		util.Fatalf("execution trace profiling failed: %v", err)
	}
	if t.output != "" {
		util.Infof("Execution trace written to %s", t.output)
	}
	return subcommands.ExitSuccess
}

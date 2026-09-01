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

	"github.com/google/subcommands"
	"gvisor.dev/gvisor/runsc/cmd/util"
	"gvisor.dev/gvisor/runsc/config"
	"gvisor.dev/gvisor/runsc/container"
	"gvisor.dev/gvisor/runsc/flag"
)

// goroutine implements subcommands.Command for the "goroutine" command.
type goroutine struct {
	output string
}

// Name implements subcommands.Command.
func (*goroutine) Name() string {
	return "goroutine"
}

// Synopsis implements subcommands.Command.
func (*goroutine) Synopsis() string {
	return "dumps the current stack traces of all running goroutines in a sandbox"
}

// Usage implements subcommands.Command.
func (*goroutine) Usage() string {
	return "goroutine [flags] <container id> - collects a goroutine profile of the sandbox\n"
}

// SetFlags implements subcommands.Command.
func (g *goroutine) SetFlags(f *flag.FlagSet) {
	f.StringVar(&g.output, "output", "", "path to write goroutine profile output (default: stdout)")
}

// Execute implements subcommands.Command.
func (g *goroutine) Execute(_ context.Context, f *flag.FlagSet, args ...any) subcommands.ExitStatus {
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
	if g.output != "" {
		f, err := os.OpenFile(g.output, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
		if err != nil {
			util.Fatalf("failed to open output file: %v", err)
		}
		defer f.Close()
		out = f
	}

	util.Infof("Collecting goroutine profile for sandbox %q...", cont.Sandbox.ID)
	if err := cont.Sandbox.GoroutineProfile(out); err != nil {
		util.Fatalf("goroutine profiling failed: %v", err)
	}
	if g.output != "" {
		util.Infof("Goroutine profile written to %s", g.output)
	}
	return subcommands.ExitSuccess
}

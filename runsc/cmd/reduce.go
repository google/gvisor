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

package cmd

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/subcommands"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"gvisor.dev/gvisor/pkg/sentry/control"
	"gvisor.dev/gvisor/runsc/cmd/util"
	"gvisor.dev/gvisor/runsc/config"
	"gvisor.dev/gvisor/runsc/container"
	"gvisor.dev/gvisor/runsc/flag"
)

// Reduce implements subcommands.Command for the "reduce" command.
type Reduce struct {
	containerLoader
	noGC  bool
	quiet bool
}

// Name implements subcommands.Command.Name.
func (*Reduce) Name() string {
	return "reduce"
}

// Synopsis implements subcommands.Command.Synopsis.
func (*Reduce) Synopsis() string {
	return "reduce the sandbox's memory usage via the Usage.Reduce RPC"
}

// Usage implements subcommands.Command.Usage.
func (*Reduce) Usage() string {
	return "reduce [flags] <container id> - evict reclaimable MemoryFile ranges and run GC.\n"
}

// SetFlags implements subcommands.Command.SetFlags.
func (r *Reduce) SetFlags(f *flag.FlagSet) {
	f.BoolVar(&r.noGC, "no-gc", false, "skip the GC step")
	f.BoolVar(&r.quiet, "quiet", false, "suppress JSON output")
}

// FetchSpec implements util.SubCommand.FetchSpec.
func (r *Reduce) FetchSpec(conf *config.Config, f *flag.FlagSet) (string, *specs.Spec, error) {
	c, err := r.loadContainer(conf, f, container.LoadOpts{SkipCheck: true})
	if err != nil {
		return "", nil, fmt.Errorf("loading container: %w", err)
	}
	return c.ID, c.Spec, nil
}

// Execute implements subcommands.Command.Execute.
func (r *Reduce) Execute(_ context.Context, f *flag.FlagSet, args ...any) subcommands.ExitStatus {
	if f.NArg() != 1 {
		f.Usage()
		return subcommands.ExitUsageError
	}

	conf := args[0].(*config.Config)

	c, err := r.loadContainer(conf, f, container.LoadOpts{SkipCheck: true})
	if err != nil {
		util.Fatalf("loading container: %v", err)
	}

	opts := control.UsageReduceOpts{Wait: true, DoNotGC: r.noGC}
	out, err := c.Sandbox.Reduce(opts)
	if err != nil {
		util.Fatalf("reduce failed: %v", err)
	}

	if r.quiet {
		return subcommands.ExitSuccess
	}

	encoder := json.NewEncoder(&util.Writer{})
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(out); err != nil {
		util.Fatalf("encoding output: %v", err)
	}
	return subcommands.ExitSuccess
}

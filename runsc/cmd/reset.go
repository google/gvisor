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
	"fmt"

	"github.com/google/subcommands"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"gvisor.dev/gvisor/runsc/cmd/util"
	"gvisor.dev/gvisor/runsc/config"
	"gvisor.dev/gvisor/runsc/container"
	"gvisor.dev/gvisor/runsc/flag"
)

// Reset implements subcommands.Command for the "reset" command.
type Reset struct {
	containerLoader
}

// Name implements subcommands.Command.Name.
func (*Reset) Name() string { return "reset" }

// Synopsis implements subcommands.Command.Synopsis.
func (*Reset) Synopsis() string {
	return "reset a container's sentry for warm reuse (experimental)"
}

// Usage implements subcommands.Command.Usage.
func (*Reset) Usage() string {
	return "reset <container-id>\n"
}

// SetFlags implements subcommands.Command.SetFlags.
func (*Reset) SetFlags(*flag.FlagSet) {}

// FetchSpec implements util.SubCommand.FetchSpec.
func (r *Reset) FetchSpec(conf *config.Config, f *flag.FlagSet) (string, *specs.Spec, error) {
	c, err := r.loadContainer(conf, f, container.LoadOpts{})
	if err != nil {
		return "", nil, fmt.Errorf("loading container: %w", err)
	}
	return c.ID, c.Spec, nil
}

// Execute implements subcommands.Command.Execute.
func (r *Reset) Execute(_ context.Context, f *flag.FlagSet, args ...any) subcommands.ExitStatus {
	if f.NArg() != 1 {
		f.Usage()
		return subcommands.ExitUsageError
	}

	conf := args[0].(*config.Config)

	c, err := r.loadContainer(conf, f, container.LoadOpts{})
	if err != nil {
		return util.Errorf("loading container: %v", err)
	}
	if c.Sandbox == nil || !c.Sandbox.WarmSentry {
		return util.Errorf("reset requires a sandbox created with --warm-sentry")
	}

	if err := c.Reset(); err != nil {
		return util.Errorf("resetting container: %v", err)
	}
	return subcommands.ExitSuccess
}

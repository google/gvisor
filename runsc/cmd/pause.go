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
	"fmt"

	"github.com/google/subcommands"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"gvisor.dev/gvisor/runsc/client"
	"gvisor.dev/gvisor/runsc/cmd/util"
	"gvisor.dev/gvisor/runsc/config"
	"gvisor.dev/gvisor/runsc/flag"
)

// Pause implements subcommands.Command for the "pause" command.
type Pause struct {
}

// Name implements subcommands.Command.Name.
func (*Pause) Name() string {
	return "pause"
}

// Synopsis implements subcommands.Command.Synopsis.
func (*Pause) Synopsis() string {
	return "pause suspends all processes in a container"
}

// Usage implements subcommands.Command.Usage.
func (*Pause) Usage() string {
	return "pause <container id> - pause process in instance of container.\n"
}

// SetFlags implements subcommands.Command.SetFlags.
func (*Pause) SetFlags(*flag.FlagSet) {
}

// FetchSpec implements util.SubCommand.FetchSpec.
func (p *Pause) FetchSpec(conf *config.Config, f *flag.FlagSet) (string, *specs.Spec, error) {
	if f.NArg() < 1 {
		f.Usage()
		return "", nil, fmt.Errorf("a container-id is required")
	}
	id := f.Arg(0)
	spec, err := client.New(conf).Spec(context.Background(), id)
	if err != nil {
		return "", nil, err
	}
	return id, spec, nil
}

// Execute implements subcommands.Command.Execute.
func (p *Pause) Execute(ctx context.Context, f *flag.FlagSet, args ...any) subcommands.ExitStatus {
	if f.NArg() != 1 {
		f.Usage()
		return subcommands.ExitUsageError
	}

	conf := args[0].(*config.Config)
	if err := client.New(conf).Pause(ctx, f.Arg(0)); err != nil {
		util.Fatalf("pause failed: %v", err)
	}

	return subcommands.ExitSuccess
}

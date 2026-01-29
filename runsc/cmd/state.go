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
	"encoding/json"
	"fmt"
	"os"

	"github.com/google/subcommands"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/runsc/cmd/util"
	"gvisor.dev/gvisor/runsc/config"
	"gvisor.dev/gvisor/runsc/container"
	"gvisor.dev/gvisor/runsc/flag"
)

// State implements subcommands.Command for the "state" command.
type State struct {
	containerLoader
}

// Name implements subcommands.Command.Name.
func (*State) Name() string {
	return "state"
}

// Synopsis implements subcommands.Command.Synopsis.
func (*State) Synopsis() string {
	return "get the state of a container"
}

// Usage implements subcommands.Command.Usage.
func (*State) Usage() string {
	return "state [flags] <container id> - get the state of a container\n"
}

// SetFlags implements subcommands.Command.SetFlags.
func (*State) SetFlags(*flag.FlagSet) {}

// FetchSpec implements util.SubCommand.FetchSpec.
func (s *State) FetchSpec(conf *config.Config, f *flag.FlagSet) (string, *specs.Spec, error) {
	c, err := s.loadContainer(conf, f, container.LoadOpts{})
	if err != nil {
		return "", nil, fmt.Errorf("loading container: %w", err)
	}
	return c.ID, c.Spec, nil
}

// Execute implements subcommands.Command.Execute.
func (s *State) Execute(_ context.Context, f *flag.FlagSet, args ...any) subcommands.ExitStatus {
	if f.NArg() != 1 {
		f.Usage()
		return subcommands.ExitUsageError
	}

	conf := args[0].(*config.Config)

	c, err := s.loadContainer(conf, f, container.LoadOpts{})
	if err != nil {
		util.Fatalf("loading container: %v", err)
	}

	state := c.State()
	log.Debugf("Returning state for container %q: %+v", c.ID, state)

	// Write json-encoded state directly to stdout.
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(state); err != nil {
		util.Fatalf("error marshaling container state: %v", err)
	}
	return subcommands.ExitSuccess
}

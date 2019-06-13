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
	"os"

	"flag"
	"github.com/google/subcommands"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/runsc/boot"
	"gvisor.dev/gvisor/runsc/container"
)

// State implements subcommands.Command for the "state" command.
type State struct{}

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
	return `state [flags] <container id> - get the state of a container`
}

// SetFlags implements subcommands.Command.SetFlags.
func (*State) SetFlags(f *flag.FlagSet) {}

// Execute implements subcommands.Command.Execute.
func (*State) Execute(_ context.Context, f *flag.FlagSet, args ...interface{}) subcommands.ExitStatus {
	if f.NArg() != 1 {
		f.Usage()
		return subcommands.ExitUsageError
	}

	id := f.Arg(0)
	conf := args[0].(*boot.Config)

	c, err := container.Load(conf.RootDir, id)
	if err != nil {
		Fatalf("loading container: %v", err)
	}
	log.Debugf("Returning state for container %+v", c)

	state := c.State()
	log.Debugf("State: %+v", state)

	// Write json-encoded state directly to stdout.
	b, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		Fatalf("marshaling container state: %v", err)
	}
	os.Stdout.Write(b)
	return subcommands.ExitSuccess
}

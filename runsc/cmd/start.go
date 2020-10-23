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

	"github.com/google/subcommands"
	"gvisor.dev/gvisor/runsc/config"
	"gvisor.dev/gvisor/runsc/container"
	"gvisor.dev/gvisor/runsc/flag"
	"gvisor.dev/gvisor/runsc/specutils"
)

// Start implements subcommands.Command for the "start" command.
type Start struct{}

// Name implements subcommands.Command.Name.
func (*Start) Name() string {
	return "start"
}

// Synopsis implements subcommands.Command.Synopsis.
func (*Start) Synopsis() string {
	return "start a secure container"
}

// Usage implements subcommands.Command.Usage.
func (*Start) Usage() string {
	return `start <container id> - start a secure container.`
}

// SetFlags implements subcommands.Command.SetFlags.
func (*Start) SetFlags(f *flag.FlagSet) {}

// Execute implements subcommands.Command.Execute.
func (*Start) Execute(_ context.Context, f *flag.FlagSet, args ...interface{}) subcommands.ExitStatus {
	if f.NArg() != 1 {
		f.Usage()
		return subcommands.ExitUsageError
	}

	id := f.Arg(0)
	conf := args[0].(*config.Config)

	c, err := container.Load(conf.RootDir, id)
	if err != nil {
		Fatalf("loading container: %v", err)
	}
	// Read the spec again here to ensure flag annotations from the spec are
	// applied to "conf".
	if _, err := specutils.ReadSpec(c.BundleDir, conf); err != nil {
		Fatalf("reading spec: %v", err)
	}

	if err := c.Start(conf); err != nil {
		Fatalf("starting container: %v", err)
	}
	return subcommands.ExitSuccess
}

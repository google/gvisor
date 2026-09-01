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

// Package profile provides subcommands for the profile command.
package profile

import (
	"bytes"
	"context"

	"github.com/google/subcommands"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"gvisor.dev/gvisor/runsc/config"
	"gvisor.dev/gvisor/runsc/flag"
)

// Profile implements subcommands.Command for the "profile" command.
type Profile struct{}

// Name implements subcommands.Command.
func (*Profile) Name() string {
	return "profile"
}

// Synopsis implements subcommands.Command.
func (*Profile) Synopsis() string {
	return "collects runtime profiling data from a running sandbox"
}

// Usage implements subcommands.Command.
func (*Profile) Usage() string {
	buf := bytes.Buffer{}
	buf.WriteString("Usage: profile <flags> <subcommand> <subcommand args>\n\n")

	cdr := createCommander(&flag.FlagSet{})
	cdr.VisitGroups(func(grp *subcommands.CommandGroup) {
		cdr.ExplainGroup(&buf, grp)
	})

	return buf.String()
}

// SetFlags implements subcommands.Command.
func (*Profile) SetFlags(f *flag.FlagSet) {}

// FetchSpec implements util.SubCommand.FetchSpec.
func (*Profile) FetchSpec(conf *config.Config, f *flag.FlagSet) (string, *specs.Spec, error) {
	return "", nil, nil
}

// Execute implements subcommands.Command.
func (*Profile) Execute(ctx context.Context, f *flag.FlagSet, args ...any) subcommands.ExitStatus {
	return createCommander(f).Execute(ctx, args...)
}

func createCommander(f *flag.FlagSet) *subcommands.Commander {
	cdr := subcommands.NewCommander(f, "profile")
	cdr.Register(cdr.HelpCommand(), "")
	cdr.Register(cdr.FlagsCommand(), "")
	cdr.Register(new(cpu), "")
	cdr.Register(new(heap), "")
	return cdr
}

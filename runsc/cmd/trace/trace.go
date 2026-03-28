// Copyright 2022 The gVisor Authors.
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

// Package trace provides subcommands for the trace command.
package trace

import (
	"bytes"
	"context"

	"github.com/google/subcommands"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"gvisor.dev/gvisor/pkg/sentry/seccheck"
	"gvisor.dev/gvisor/runsc/config"
	"gvisor.dev/gvisor/runsc/flag"
)

// Trace implements subcommands.Command for the "trace" command.
type Trace struct{}

// Name implements subcommands.Command.
func (*Trace) Name() string {
	return "trace"
}

// Synopsis implements subcommands.Command.
func (*Trace) Synopsis() string {
	return "manages trace sessions for a given sandbox"
}

// Usage implements subcommands.Command.
func (*Trace) Usage() string {
	buf := bytes.Buffer{}
	buf.WriteString("Usage: trace <flags> <subcommand> <subcommand args>\n\n")

	cdr := createCommander(&flag.FlagSet{})
	cdr.VisitGroups(func(grp *subcommands.CommandGroup) {
		cdr.ExplainGroup(&buf, grp)
	})

	return buf.String()
}

// SetFlags implements subcommands.Command.
func (*Trace) SetFlags(f *flag.FlagSet) {}

// FetchSpec implements util.SubCommand.FetchSpec.
func (*Trace) FetchSpec(conf *config.Config, f *flag.FlagSet) (string, *specs.Spec, error) {
	// This command has subcommands that may operate on individual containers.
	// But that requires parsing the subcommand flags. To avoid complexity for
	// now, return nothing as though no container is involved.
	return "", nil, nil
}

// Execute implements subcommands.Command.
func (*Trace) Execute(ctx context.Context, f *flag.FlagSet, args ...any) subcommands.ExitStatus {
	seccheck.Initialize()
	return createCommander(f).Execute(ctx, args...)
}

func createCommander(f *flag.FlagSet) *subcommands.Commander {
	cdr := subcommands.NewCommander(f, "trace")
	cdr.Register(cdr.HelpCommand(), "")
	cdr.Register(cdr.FlagsCommand(), "")
	cdr.Register(new(create), "")
	cdr.Register(new(delete), "")
	cdr.Register(new(list), "")
	cdr.Register(new(metadata), "")
	cdr.Register(new(procfs), "")
	return cdr
}

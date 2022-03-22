// Copyright 2020 The gVisor Authors.
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
	"context"

	"github.com/google/subcommands"
	"gvisor.dev/gvisor/runsc/flag"
)

// Trace implements subcommands.Command for the "point" command.
type Trace struct {
}

// Name implements subcommands.command.name.
func (*Trace) Name() string {
	return "trace"
}

// Synopsis implements subcommands.Command.Synopsis.
func (*Trace) Synopsis() string {
	return "TODO"
}

// Usage implements subcommands.Command.Usage.
func (*Trace) Usage() string {
	return `point [flags]`
}

// SetFlags implements subcommands.Command.SetFlags.
func (l *Trace) SetFlags(f *flag.FlagSet) {
}

// Execute implements subcommands.Command.Execute.
func (l *Trace) Execute(ctx context.Context, f *flag.FlagSet, args ...interface{}) subcommands.ExitStatus {
	cdr := subcommands.NewCommander(f, "trace")
	cdr.Register(subcommands.HelpCommand(), "")
	cdr.Register(subcommands.FlagsCommand(), "")
	cdr.Register(new(create), "")
	cdr.Register(new(delete), "")
	cdr.Register(new(list), "")
	cdr.Register(new(metadata), "")
	return cdr.Execute(ctx, args...)
}

// Copyright 2021 The gVisor Authors.
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
	"os"

	"github.com/google/subcommands"
	"gvisor.dev/gvisor/pkg/sentry/platform"
	"gvisor.dev/gvisor/runsc/flag"
)

// Platforms implements subcommands.Command for the "platforms" command.
type Platforms struct{}

// Name implements subcommands.Command.Name.
func (*Platforms) Name() string {
	return "platforms"
}

// Synopsis implements subcommands.Command.Synopsis.
func (*Platforms) Synopsis() string {
	return "Print a list of available platforms."
}

// Usage implements subcommands.Command.Usage.
func (*Platforms) Usage() string {
	return `platforms [options] - Print available platforms.
`
}

// SetFlags implements subcommands.Command.SetFlags.
func (*Platforms) SetFlags(f *flag.FlagSet) {}

// Execute implements subcommands.Command.Execute.
func (*Platforms) Execute(_ context.Context, f *flag.FlagSet, args ...any) subcommands.ExitStatus {
	for _, p := range platform.List() {
		fmt.Fprintf(os.Stdout, "%s\n", p)
	}
	return subcommands.ExitSuccess
}

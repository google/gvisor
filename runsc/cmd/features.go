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
	"os"

	"github.com/google/subcommands"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"gvisor.dev/gvisor/runsc/config"
	"gvisor.dev/gvisor/runsc/flag"
	"gvisor.dev/gvisor/runsc/specutils"
)

// Features implements subcommands.Command for the "features" command.
type Features struct{}

// Name implements subcommands.command.name.
func (*Features) Name() string {
	return "features"
}

// Synopsis implements subcommands.Command.Synopsis.
func (*Features) Synopsis() string {
	return "list CPU features supported on current machine"
}

// Usage implements subcommands.Command.Usage.
func (*Features) Usage() string {
	return "features\n"
}

// SetFlags implements subcommands.Command.SetFlags.
func (*Features) SetFlags(*flag.FlagSet) {}

// FetchSpec implements util.SubCommand.FetchSpec.
func (*Features) FetchSpec(_ *config.Config, _ *flag.FlagSet) (string, *specs.Spec, error) {
	// This command does not operate on a single container, so nothing to fetch.
	return "", nil, nil
}

// Execute implements subcommands.Command.Execute.
func (*Features) Execute(_ context.Context, _ *flag.FlagSet, args ...any) subcommands.ExitStatus {
	feat := specutils.Features()

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(feat); err != nil {
		return subcommands.ExitFailure
	}

	return subcommands.ExitSuccess
}

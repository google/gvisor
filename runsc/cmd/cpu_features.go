// Copyright 2025 The gVisor Authors.
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
	"strings"

	"github.com/google/subcommands"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"gvisor.dev/gvisor/pkg/cpuid"
	"gvisor.dev/gvisor/runsc/config"
	"gvisor.dev/gvisor/runsc/flag"
)

// CPUFeatures implements subcommands.Command for the "cpu-features" command.
type CPUFeatures struct {
	bitmask bool
}

// Name implements subcommands.command.name.
func (*CPUFeatures) Name() string {
	return "cpu-features"
}

// Synopsis implements subcommands.Command.Synopsis.
func (*CPUFeatures) Synopsis() string {
	return "list CPU features supported on current machine"
}

// Usage implements subcommands.Command.Usage.
func (*CPUFeatures) Usage() string {
	return "cpu-features [flags]\n"
}

// SetFlags implements subcommands.Command.SetFlags.
func (c *CPUFeatures) SetFlags(f *flag.FlagSet) {
	f.BoolVar(&c.bitmask, "bitmask", false, "outputs CPU features as comma-separated hex uint32 block bitmasks.")
}

// FetchSpec implements util.SubCommand.FetchSpec.
func (*CPUFeatures) FetchSpec(_ *config.Config, _ *flag.FlagSet) (string, *specs.Spec, error) {
	// This command does not operate on a single container, so nothing to fetch.
	return "", nil, nil
}

// Execute implements subcommands.Command.Execute.
func (c *CPUFeatures) Execute(_ context.Context, _ *flag.FlagSet, args ...any) subcommands.ExitStatus {
	cpuid.Initialize()
	hfs := cpuid.HostFeatureSet().Fixed()
	if c.bitmask {
		fmt.Println(hfs.FeatureMaskString())
		return subcommands.ExitSuccess
	}
	fmt.Println(strings.Join(hfs.FeatureNames(), ","))

	return subcommands.ExitSuccess
}

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
	"gvisor.dev/gvisor/pkg/cpuid"
	"gvisor.dev/gvisor/runsc/flag"
)

// List implements subcommands.Command for the "cpu-feature" command.
type CPUFeature struct{}

// Name implements subcommands.command.name.
func (*CPUFeature) Name() string {
	return "cpu-feature"
}

// Synopsis implements subcommands.Command.Synopsis.
func (*CPUFeature) Synopsis() string {
	return "list CPU features supported on current machine"
}

// Usage implements subcommands.Command.Usage.
func (*CPUFeature) Usage() string {
	return "cpu-feature\n"
}

// SetFlags implements subcommands.Command.SetFlags.
func (*CPUFeature) SetFlags(*flag.FlagSet) {}

// Execute implements subcommands.Command.Execute.
func (*CPUFeature) Execute(_ context.Context, _ *flag.FlagSet, args ...any) subcommands.ExitStatus {
	cpuid.Initialize()
	hfs := cpuid.HostFeatureSet().Fixed()
	allFeatures := cpuid.AllFeatures()

	features := []string{}
	for _, v := range allFeatures {
		if hfs.HasFeature(v) {
			features = append(features, v.String())
		}
	}
	fmt.Println(strings.Join(features, ","))

	return subcommands.ExitSuccess
}

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
	"sort"

	"github.com/google/subcommands"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/opencontainers/runtime-spec/specs-go/features"
	"gvisor.dev/gvisor/runsc/config"
	"gvisor.dev/gvisor/runsc/flag"
	"gvisor.dev/gvisor/runsc/specutils"
	"gvisor.dev/gvisor/runsc/specutils/seccomp"
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

	feat := features.Features{
		OCIVersionMin: "1.0.0",
		OCIVersionMax: specs.Version,
		Hooks: []string{
			"prestart",
			"createRuntime",
			"createContainer",
			"startContainer",
			"poststart",
			"poststop",
		},
		MountOptions: specutils.KnownMountOptions(),
		Linux: &features.Linux{
			Namespaces:   specutils.KnownNamespaces(),
			Capabilities: specutils.AllCapabilities().Bounding,
			Cgroup: &features.Cgroup{
				V1:          boolPtr(true),
				V2:          boolPtr(false),
				Systemd:     boolPtr(false),
				SystemdUser: boolPtr(false),
				Rdma:        boolPtr(false),
			},
			Seccomp: &features.Seccomp{
				Enabled:        boolPtr(true),
				Actions:        seccomp.KnownActions(),
				Operators:      seccomp.KnownOperators(),
				Archs:          seccomp.KnownArchs(),
				KnownFlags:     seccomp.KnownFlags(),
				SupportedFlags: seccomp.SupportedFlags(),
			},
			Apparmor: &features.Apparmor{
				Enabled: boolPtr(false),
			},
			Selinux: &features.Selinux{
				Enabled: boolPtr(false),
			},
			IntelRdt: &features.IntelRdt{
				Enabled: boolPtr(false),
			},
			MountExtensions: &features.MountExtensions{
				IDMap: &features.IDMap{
					Enabled: boolPtr(false),
				},
			},
		},
	}

	tmpFs := flag.NewFlagSet("tmp", flag.ContinueOnError)
	config.RegisterFlags(tmpFs)
	annotations := make(map[string]string)
	tmpFs.VisitAll(func(f *flag.Flag) {
		key := "dev.gvisor.flag." + f.Name
		annotations[key] = f.DefValue
	})

	// LINT.IfChange
	annotations["dev.gvisor.container-name-remap."] = ""
	annotations[specutils.AnnotationRootfsUpperTar] = ""
	annotations["dev.gvisor.internal.seccomp."] = ""
	annotations["dev.gvisor.internal.seccomp.cont"] = "RuntimeDefault"
	annotations[specutils.AnnotationTPU] = ""
	annotations[specutils.AnnotationCPUFeatures] = ""
	// LINT.ThenChange(../specutils/specutils.go)
	feat.Annotations = annotations

	var unsafeAnnotations []string
	tmpFs.VisitAll(func(f *flag.Flag) {
		if !config.IsFlagSafeToOverride(f.Name) {
			unsafeAnnotations = append(unsafeAnnotations, "dev.gvisor.flag."+f.Name)
		}
	})

	// LINT.IfChange
	unsafeAnnotations = append(unsafeAnnotations,
		"dev.gvisor.container-name-remap.",
		specutils.AnnotationRootfsUpperTar,
		"dev.gvisor.internal.seccomp.",
		specutils.AnnotationTPU,
		specutils.AnnotationCPUFeatures,
	)
	// LINT.ThenChange(../specutils/specutils.go)

	sort.Strings(unsafeAnnotations)
	feat.PotentiallyUnsafeConfigAnnotations = unsafeAnnotations

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(feat); err != nil {
		return subcommands.ExitFailure
	}

	return subcommands.ExitSuccess
}

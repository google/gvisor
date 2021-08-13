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
	"encoding/json"
	"fmt"
	"os"

	"github.com/google/subcommands"
	"gvisor.dev/gvisor/runsc/config"
	"gvisor.dev/gvisor/runsc/container"
	"gvisor.dev/gvisor/runsc/flag"
)

// Usage implements subcommands.Command for the "usage" command.
type Usage struct {
	full bool
	fd   bool
}

// Name implements subcommands.Command.Name.
func (*Usage) Name() string {
	return "usage"
}

// Synopsis implements subcommands.Command.Synopsis.
func (*Usage) Synopsis() string {
	return "Usage shows application memory usage across various categories in bytes."
}

// Usage implements subcommands.Command.Usage.
func (*Usage) Usage() string {
	return `usage [flags] <container id> - print memory usages to standard output.`
}

// SetFlags implements subcommands.Command.SetFlags.
func (u *Usage) SetFlags(f *flag.FlagSet) {
	f.BoolVar(&u.full, "full", false, "enumerate all usage by categories")
	f.BoolVar(&u.fd, "fd", false, "retrieves a subset of usage through the established usage FD")
}

// Execute implements subcommands.Command.Execute.
func (u *Usage) Execute(_ context.Context, f *flag.FlagSet, args ...interface{}) subcommands.ExitStatus {
	if f.NArg() < 1 {
		f.Usage()
		return subcommands.ExitUsageError
	}

	id := f.Arg(0)
	conf := args[0].(*config.Config)

	cont, err := container.Load(conf.RootDir, container.FullID{ContainerID: id}, container.LoadOpts{})
	if err != nil {
		Fatalf("loading container: %v", err)
	}

	if !u.fd {
		m, err := cont.Usage(u.full)
		if err != nil {
			Fatalf("usage failed: %v", err)
		}
		if err := json.NewEncoder(os.Stdout).Encode(m); err != nil {
			Fatalf("Encode MemoryUsage failed: %v", err)
		}
	} else {
		m, err := cont.UsageFD()
		if err != nil {
			Fatalf("usagefd failed: %v", err)
		}

		mapped, unknown, total, err := m.Fetch()
		if err != nil {
			Fatalf("Fetch memory usage failed: %v", err)
		}

		fmt.Printf("Mapped %v, Unknown %v, Total %v\n", mapped, unknown, total)
	}
	return subcommands.ExitSuccess
}

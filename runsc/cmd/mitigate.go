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

	"github.com/google/subcommands"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/runsc/flag"
	"gvisor.dev/gvisor/runsc/mitigate"
)

// Mitigate implements subcommands.Command for the "mitigate" command.
type Mitigate struct {
	mitigate mitigate.Mitigate
}

// Name implements subcommands.command.name.
func (*Mitigate) Name() string {
	return "mitigate"
}

// Synopsis implements subcommands.Command.Synopsis.
func (*Mitigate) Synopsis() string {
	return "mitigate mitigates the underlying system against side channel attacks"
}

// Usage implements subcommands.Command.Usage.
func (m *Mitigate) Usage() string {
	return m.mitigate.Usage()
}

// SetFlags implements subcommands.Command.SetFlags.
func (m *Mitigate) SetFlags(f *flag.FlagSet) {
	m.mitigate.SetFlags(f)
}

// Execute implements subcommands.Command.Execute.
func (m *Mitigate) Execute(_ context.Context, f *flag.FlagSet, args ...interface{}) subcommands.ExitStatus {
	if f.NArg() != 0 {
		f.Usage()
		return subcommands.ExitUsageError
	}

	if err := m.mitigate.Execute(); err != nil {
		log.Warningf("Execute failed: %v", err)
		return subcommands.ExitFailure
	}

	return subcommands.ExitSuccess
}

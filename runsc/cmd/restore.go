// Copyright 2018 Google Inc.
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
	"flag"
	"github.com/google/subcommands"
)

// Restore implements subcommands.Command for the "restore" command.
type Restore struct {
}

// Name implements subcommands.Command.Name.
func (*Restore) Name() string {
	return "restore"
}

// Synopsis implements subcommands.Command.Synopsis.
func (*Restore) Synopsis() string {
	return "restore a saved state of container"
}

// Usage implements subcommands.Command.Usage.
func (*Restore) Usage() string {
	return `restore [flags] <container id> - restore last saved state of container.
`
}

// SetFlags implements subcommands.Command.SetFlags.
func (r *Restore) SetFlags(f *flag.FlagSet) {
}

// Execute implements subcommands.Command.Execute.
func (r *Restore) Execute(_ context.Context, f *flag.FlagSet, args ...interface{}) subcommands.ExitStatus {
	Fatalf("restore not implemented")
	return subcommands.ExitFailure
}

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

// Package forwardcmd implements commands that runsc runs in the Sentry
// binary, because they report on code that is linked into it.
package forwardcmd

import (
	"gvisor.dev/gvisor/runsc/flag"
)

const (
	// OSAll is the string name to use for printing compatibility for all
	// OSes.
	OSAll = "all"

	// ArchAll is the string name to use for printing compatibility for all
	// architectures.
	ArchAll = "all"
)

// Syscalls partially implements subcommands.Command for the "syscalls"
// command. The Sentry binary implements Execute, as it has the syscall tables.
type Syscalls struct {
	Format   string
	OS       string
	Arch     string
	Filename string
}

// Name implements subcommands.Command.Name.
func (*Syscalls) Name() string {
	return "syscalls"
}

// Synopsis implements subcommands.Command.Synopsis.
func (*Syscalls) Synopsis() string {
	return "Print compatibility information for syscalls."
}

// Usage implements subcommands.Command.Usage.
func (*Syscalls) Usage() string {
	return "syscalls [options] - Print compatibility information for syscalls.\n"
}

// SetFlags implements subcommands.Command.SetFlags.
func (s *Syscalls) SetFlags(f *flag.FlagSet) {
	f.StringVar(&s.Format, "format", "table", "Output format (table, csv, json).")
	f.StringVar(&s.OS, "os", OSAll, "The OS (e.g. linux)")
	f.StringVar(&s.Arch, "arch", ArchAll, "The CPU architecture (e.g. amd64).")
	f.StringVar(&s.Filename, "filename", "", "Output filename (otherwise stdout).")
}

// Copyright 2022 The gVisor Authors.
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

package main

import (
	"context"
	_ "embed"
	"log"

	"github.com/google/subcommands"
	"gvisor.dev/gvisor/runsc/flag"
)

//go:embed bpf/pass_ebpf.o
var passProgram []byte

// PassCommand is a subcommand for passing packets to the kernel network stack.
type PassCommand struct {
	device      string
	deviceIndex int
}

// Name implements subcommands.Command.Name.
func (*PassCommand) Name() string {
	return "pass"
}

// Synopsis implements subcommands.Command.Synopsis.
func (*PassCommand) Synopsis() string {
	return "Pass all packets to the kernel network stack."
}

// Usage implements subcommands.Command.Usage.
func (*PassCommand) Usage() string {
	return "pass -device <device> or -devidx <device index>"
}

// SetFlags implements subcommands.Command.SetFlags.
func (pc *PassCommand) SetFlags(fs *flag.FlagSet) {
	fs.StringVar(&pc.device, "device", "", "which device to attach to")
	fs.IntVar(&pc.deviceIndex, "devidx", 0, "which device to attach to")
}

// Execute implements subcommands.Command.Execute.
func (pc *PassCommand) Execute(context.Context, *flag.FlagSet, ...any) subcommands.ExitStatus {
	if err := runBasicProgram(passProgram, pc.device, pc.deviceIndex); err != nil {
		log.Printf("%v", err)
		return subcommands.ExitFailure
	}
	return subcommands.ExitSuccess
}

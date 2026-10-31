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

package main

import (
	"context"
	"fmt"
	"log"

	"github.com/google/subcommands"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/runsc/flag"
)

type clocks struct{}

// Name implements subcommands.Command.Name.
func (*clocks) Name() string {
	return "clocks"
}

// Synopsis implements subcommands.Command.Synopsis.
func (*clocks) Synopsis() string {
	return "prints CLOCK_REALTIME, CLOCK_MONOTONIC and CLOCK_BOOTTIME in nanoseconds"
}

// Usage implements subcommands.Command.Usage.
func (*clocks) Usage() string {
	return "clocks\n"
}

// SetFlags implements subcommands.Command.SetFlags.
func (*clocks) SetFlags(*flag.FlagSet) {}

// Execute implements subcommands.Command.Execute.
func (*clocks) Execute(ctx context.Context, f *flag.FlagSet, args ...any) subcommands.ExitStatus {
	var ns [3]int64
	for i, id := range []int32{unix.CLOCK_REALTIME, unix.CLOCK_MONOTONIC, unix.CLOCK_BOOTTIME} {
		var ts unix.Timespec
		if err := unix.ClockGettime(id, &ts); err != nil {
			log.Fatalf("clock_gettime(%d) failed: %v", id, err)
		}
		ns[i] = ts.Nano()
	}
	fmt.Printf("%d %d %d\n", ns[0], ns[1], ns[2])
	return subcommands.ExitSuccess
}

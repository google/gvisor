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
	"os"
	"time"

	"github.com/google/subcommands"
	"gvisor.dev/gvisor/runsc/flag"
)

// pacSR signs a pointer with the ARM64 APIA key, then repeatedly checks that
// the signature still authenticates, so that a checkpoint/restore test can
// check that pointers signed before a checkpoint work after restore.
type pacSR struct {
	file string
}

func (*pacSR) Name() string {
	return "pac-sr"
}

func (*pacSR) Synopsis() string {
	return "checks that a pointer signed with the APIA key keeps authenticating"
}

func (*pacSR) Usage() string {
	return "pac-sr --file=<path>"
}

func (p *pacSR) SetFlags(f *flag.FlagSet) {
	f.StringVar(&p.file, "file", "", "file for test output")
}

func (p *pacSR) Execute(ctx context.Context, f *flag.FlagSet, args ...any) subcommands.ExitStatus {
	if p.file == "" {
		log.Fatalf("--file is required")
	}
	out, err := os.OpenFile(p.file, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		log.Fatalf("OpenFile(%q): %v", p.file, err)
	}
	defer out.Close()

	const (
		ptr      = 0x0000aaaa00001000
		modifier = 0x0000ffffcafe0000
	)
	// If pointer authentication is not in use, signing leaves ptr unchanged.
	signed := pacia1716(ptr, modifier)
	fmt.Fprintf(out, "SIGNED active=%t\n", signed != ptr)
	for i := 0; ; i++ {
		// Authenticating a pointer signed with the current key returns the
		// original pointer. With FEAT_FPAC a failed authentication raises
		// SIGILL instead.
		if got := autia1716(signed, modifier); got != ptr {
			fmt.Fprintf(out, "FAIL authenticated %#x, want %#x\n", got, uint64(ptr))
			return subcommands.ExitFailure
		}
		if resigned := pacia1716(ptr, modifier); resigned != signed {
			fmt.Fprintf(out, "FAIL signed %#x, want %#x\n", resigned, signed)
			return subcommands.ExitFailure
		}
		fmt.Fprintf(out, "OK %d\n", i)
		time.Sleep(100 * time.Millisecond)
	}
}

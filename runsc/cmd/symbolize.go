// Copyright 2020 The gVisor Authors.
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
	"bufio"
	"context"
	"os"
	"strconv"
	"strings"

	"github.com/google/subcommands"
	"gvisor.dev/gvisor/pkg/coverage"
	"gvisor.dev/gvisor/runsc/cmd/util"
	"gvisor.dev/gvisor/runsc/flag"
)

// Symbolize implements subcommands.Command for the "symbolize" command.
type Symbolize struct {
	dumpAll bool
}

// Name implements subcommands.Command.Name.
func (*Symbolize) Name() string {
	return "symbolize"
}

// Synopsis implements subcommands.Command.Synopsis.
func (*Symbolize) Synopsis() string {
	return "Convert synthetic instruction pointers from kcov into positions in the runsc source code. Only used when Go coverage is enabled."
}

// Usage implements subcommands.Command.Usage.
func (*Symbolize) Usage() string {
	return `symbolize - converts synthetic instruction pointers into positions in the runsc source code.

This command takes instruction pointers from stdin and converts them into their
corresponding file names and line/column numbers in the runsc source code. The
inputs are not interpreted as actual addresses, but as synthetic values that are
exposed through /sys/kernel/debug/kcov. One can extract coverage information
from kcov and translate those values into locations in the source code by
running symbolize on the same runsc binary.
`
}

// SetFlags implements subcommands.Command.SetFlags.
func (c *Symbolize) SetFlags(f *flag.FlagSet) {
	f.BoolVar(&c.dumpAll, "all", false, "dump information on all coverage blocks along with their synthetic PCs")
}

// Execute implements subcommands.Command.Execute.
func (c *Symbolize) Execute(_ context.Context, f *flag.FlagSet, args ...any) subcommands.ExitStatus {
	if f.NArg() != 0 {
		f.Usage()
		return subcommands.ExitUsageError
	}
	if !coverage.Available() {
		return util.Errorf("symbolize can only be used when coverage is available.")
	}
	coverage.InitCoverageData()

	if c.dumpAll {
		if err := coverage.WriteAllBlocks(os.Stdout); err != nil {
			return util.Errorf("Failed to write out blocks: %v", err)
		}
		return subcommands.ExitSuccess
	}

	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		// Input is always base 16, but may or may not have a leading "0x".
		str := strings.TrimPrefix(scanner.Text(), "0x")
		pc, err := strconv.ParseUint(str, 16 /* base */, 64 /* bitSize */)
		if err != nil {
			return util.Errorf("Failed to symbolize \"%s\": %v", scanner.Text(), err)
		}
		if err := coverage.Symbolize(os.Stdout, pc); err != nil {
			return util.Errorf("Failed to symbolize \"%s\": %v", scanner.Text(), err)
		}
	}
	return subcommands.ExitSuccess
}

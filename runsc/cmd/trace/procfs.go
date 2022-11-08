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

package trace

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/subcommands"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/runsc/cmd/util"
	"gvisor.dev/gvisor/runsc/config"
	"gvisor.dev/gvisor/runsc/container"
	"gvisor.dev/gvisor/runsc/flag"
)

// procfs implements subcommands.Command for the "procfs" command.
type procfs struct {
}

// Name implements subcommands.Command.
func (*procfs) Name() string {
	return "procfs"
}

// Synopsis implements subcommands.Command.
func (*procfs) Synopsis() string {
	return "dump procfs state for sandbox"
}

// Usage implements subcommands.Command.
func (*procfs) Usage() string {
	return `procfs <sandbox id> - get procfs dump for a trace session
`
}

// SetFlags implements subcommands.Command.
func (*procfs) SetFlags(*flag.FlagSet) {}

// Execute implements subcommands.Command.
func (*procfs) Execute(_ context.Context, f *flag.FlagSet, args ...any) subcommands.ExitStatus {
	if f.NArg() != 1 {
		f.Usage()
		return subcommands.ExitUsageError
	}

	id := f.Arg(0)
	conf := args[0].(*config.Config)

	opts := container.LoadOpts{
		SkipCheck:     true,
		RootContainer: true,
	}
	c, err := container.Load(conf.RootDir, container.FullID{ContainerID: id}, opts)
	if err != nil {
		util.Fatalf("loading sandbox: %v", err)
	}

	dump, err := c.Sandbox.ProcfsDump()
	if err != nil {
		util.Fatalf("procfs dump: %v", err)
	}

	fmt.Println("PROCFS DUMP")
	for _, procDump := range dump {
		out, err := json.Marshal(procDump)
		if err != nil {
			log.Warningf("json.Marshal failed to marshal %+v: %v", procDump, err)
			continue
		}

		fmt.Println("")
		fmt.Println(string(out))
	}
	return subcommands.ExitSuccess
}

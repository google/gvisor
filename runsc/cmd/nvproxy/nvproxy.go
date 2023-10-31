// Copyright 2023 The gVisor Authors.
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

// Package nvproxy provides subcommands for the nvproxy command.
package nvproxy

import (
	"bytes"
	"context"

	"github.com/google/subcommands"
	"gvisor.dev/gvisor/pkg/sentry/devices/nvproxy"
	"gvisor.dev/gvisor/runsc/flag"
)

type Nvproxy struct{}

func (*Nvproxy) Name() string {
	return "nvproxy"
}

func (*Nvproxy) Synopsis() string {
	return "shows information about nvproxy support"
}

func (*Nvproxy) Usage() string {
	buf := bytes.Buffer{}
	buf.WriteString("Usage: nvproxy <flags> <subcommand> <subcommand args>\n\n")

	cdr := createCommander(&flag.FlagSet{})
	cdr.VisitGroups(func(grp *subcommands.CommandGroup) {
		cdr.ExplainGroup(&buf, grp)
	})

	return buf.String()
}

func (*Nvproxy) SetFlags(*flag.FlagSet) {}

func (*Nvproxy) Execute(ctx context.Context, f *flag.FlagSet, args ...any) subcommands.ExitStatus {
	nvproxy.Init()
	return createCommander(f).Execute(ctx, args...)
}

func createCommander(f *flag.FlagSet) *subcommands.Commander {
	cdr := subcommands.NewCommander(f, "nvproxy")
	cdr.Register(cdr.HelpCommand(), "")
	cdr.Register(cdr.FlagsCommand(), "")
	cdr.Register(new(listSupportedDrivers), "")
	return cdr
}

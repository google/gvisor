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

package cmd

import (
	"context"
	"os"
	"strings"

	"github.com/google/subcommands"
	"gvisor.dev/gvisor/runsc/cmd/nvproxy"
	"gvisor.dev/gvisor/runsc/cmd/sentry/forwardcmd"
	"gvisor.dev/gvisor/runsc/cmd/util"
	"gvisor.dev/gvisor/runsc/flag"
	"gvisor.dev/gvisor/runsc/gvisorbinaries"
)

// execSentry replaces the current process with the Sentry binary, running the
// same command line that runsc was invoked with.
func execSentry() subcommands.ExitStatus {
	sentry := &gvisorbinaries.GvisorSentry
	err := sentry.Exec(gvisorbinaries.Options{Argv: os.Args, Envv: os.Environ()})
	// Unreachable unless `sentry.Exec` fails.
	return util.Errorf("Failed to run %q in sidecar %q: %v", strings.Join(flag.CommandLine.Args(), " "), sentry.Name, err)
}

// MetricMetadata implements subcommands.Command for the "metric-metadata"
// command.
type MetricMetadata struct {
	forwardcmd.MetricMetadata
}

// Execute implements subcommands.Command.Execute.
func (*MetricMetadata) Execute(context.Context, *flag.FlagSet, ...any) subcommands.ExitStatus {
	return execSentry()
}

// Nvproxy implements subcommands.Command for the "nvproxy" command.
type Nvproxy struct {
	nvproxy.Nvproxy
}

// Execute implements subcommands.Command.Execute.
func (*Nvproxy) Execute(context.Context, *flag.FlagSet, ...any) subcommands.ExitStatus {
	return execSentry()
}

// Symbolize implements subcommands.Command for the "symbolize" command.
type Symbolize struct {
	forwardcmd.Symbolize
}

// Execute implements subcommands.Command.Execute.
func (*Symbolize) Execute(context.Context, *flag.FlagSet, ...any) subcommands.ExitStatus {
	return execSentry()
}

// Syscalls implements subcommands.Command for the "syscalls" help topic.
type Syscalls struct {
	forwardcmd.Syscalls
}

// Execute implements subcommands.Command.Execute.
func (*Syscalls) Execute(context.Context, *flag.FlagSet, ...any) subcommands.ExitStatus {
	return execSentry()
}

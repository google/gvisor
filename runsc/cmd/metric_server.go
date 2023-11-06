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

package cmd

import (
	"context"
	"os"

	"github.com/google/subcommands"
	"gvisor.dev/gvisor/runsc/cmd/metricserver"
	"gvisor.dev/gvisor/runsc/cmd/metricserver/metricservercmd"
	"gvisor.dev/gvisor/runsc/cmd/util"
	"gvisor.dev/gvisor/runsc/flag"
)

// MetricServer implements subcommands.Command for the "metric-server" command.
type MetricServer struct {
	metricservercmd.Cmd
}

// Execute implements subcommands.Command.Execute.
func (m *MetricServer) Execute(ctx context.Context, f *flag.FlagSet, args ...any) subcommands.ExitStatus {
	err := metricserver.Exec(metricserver.Options{
		Argv: os.Args,
		Envv: os.Environ(),
	})
	if err != nil {
		util.Fatalf("metric server: %v", err)
	}
	util.Fatalf("unreachable")
	return subcommands.ExitFailure
}

// Copyright 2025 The gVisor Authors.
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

// Package maincli is the main entrypoint for runsc.
package maincli

import (
	"github.com/google/subcommands"
	"gvisor.dev/gvisor/runsc/cli"
	"gvisor.dev/gvisor/runsc/cmd"
	"gvisor.dev/gvisor/runsc/cmd/nvproxy"
	"gvisor.dev/gvisor/runsc/cmd/trace"
)

// Main is the main entrypoint.
func Main() {
	cmds, helpCmds := commands()
	cli.Run(cmds, helpCmds)
}

func commands() (map[subcommands.Command]string, []subcommands.Command) {
	const helperGroup = "helpers"
	const debugGroup = "debug"
	const metricGroup = "metrics"
	const internalGroup = "internal use only"

	return map[subcommands.Command]string{
			// Register OCI user-facing runsc commands.
			new(cmd.Checkpoint):  "",
			new(cmd.Create):      "",
			new(cmd.Delete):      "",
			new(cmd.Do):          "",
			new(cmd.Events):      "",
			new(cmd.Exec):        "",
			new(cmd.Kill):        "",
			new(cmd.List):        "",
			new(cmd.PS):          "",
			new(cmd.Pause):       "",
			new(cmd.PortForward): "",
			new(cmd.Restore):     "",
			new(cmd.Resume):      "",
			new(cmd.Run):         "",
			new(cmd.Spec):        "",
			new(cmd.Start):       "",
			new(cmd.State):       "",
			new(cmd.Tar):         "",
			new(cmd.Update):      "",
			new(cmd.Wait):        "",

			// Helpers.
			new(cmd.Install):     helperGroup,
			new(cmd.Mitigate):    helperGroup,
			new(cmd.Uninstall):   helperGroup,
			new(nvproxy.Nvproxy): helperGroup,
			new(trace.Trace):     helperGroup,
			new(cmd.CPUFeatures): helperGroup,

			new(cmd.Debug):        debugGroup,
			new(cmd.Statefile):    debugGroup,
			new(cmd.Symbolize):    debugGroup,
			new(cmd.Usage):        debugGroup,
			new(cmd.ReadControl):  debugGroup,
			new(cmd.WriteControl): debugGroup,

			new(cmd.MetricMetadata): metricGroup,
			new(cmd.MetricExport):   metricGroup,
			new(cmd.MetricServer):   metricGroup,

			// Internal commands.
			new(cmd.Boot):   internalGroup,
			new(cmd.Gofer):  internalGroup,
			new(cmd.Umount): internalGroup,
		}, []subcommands.Command{
			// For historical reasons, these subcommands are invoked as `runsc help
			// platforms` and `runsc help syscalls`.
			new(cmd.Platforms),
			new(cmd.Syscalls),
		}
}

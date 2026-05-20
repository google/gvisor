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
	"gvisor.dev/gvisor/runsc/cmd/util"
)

const (
	userGroup     = ""
	helperGroup   = "helpers"
	debugGroup    = "debug"
	metricGroup   = "metrics"
	internalGroup = "internal use only"
)

// Main is the main entrypoint.
func Main() {
	cmds, helpCmds := commands()
	cli.Run(cmds, helpCmds)
}

func commands() (map[util.SubCommand]string, []subcommands.Command) {
	cmds := map[util.SubCommand]string{
		// Register OCI user-facing runsc commands.
		new(cmd.Checkpoint): userGroup,
		new(cmd.Create):     userGroup,
		new(cmd.Delete):     userGroup,
		new(cmd.Events):     userGroup,
		new(cmd.Exec):       userGroup,
		new(cmd.Kill):       userGroup,
		new(cmd.List):       userGroup,
		new(cmd.PS):         userGroup,
		new(cmd.Pause):      userGroup,
		new(cmd.Restore):    userGroup,
		new(cmd.Resume):     userGroup,
		new(cmd.Run):        userGroup,
		new(cmd.Spec):       userGroup,
		new(cmd.Start):      userGroup,
		new(cmd.State):      userGroup,
		new(cmd.Update):     userGroup,
		new(cmd.Wait):       userGroup,

		// Non-OCI user-facing runsc commands.
		new(cmd.Do):           userGroup,
		new(cmd.FSCheckpoint): userGroup,
		new(cmd.PortForward):  userGroup,
		new(cmd.SandboxExec):  userGroup,
		new(cmd.Tar):          userGroup,

		// Helpers.
		new(cmd.Install):     helperGroup,
		new(cmd.Mitigate):    helperGroup,
		new(cmd.Uninstall):   helperGroup,
		new(nvproxy.Nvproxy): helperGroup,
		new(trace.Trace):     helperGroup,
		new(cmd.CPUFeatures): helperGroup,
		new(cmd.Features):    helperGroup,

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
	}
	extraCmds(cmds)

	helpCmds := []subcommands.Command{
		// For historical reasons, these subcommands are invoked as `runsc help
		// platforms` and `runsc help syscalls`.
		new(cmd.Platforms),
		new(cmd.Syscalls),
	}

	return cmds, helpCmds
}

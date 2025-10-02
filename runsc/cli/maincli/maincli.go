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
	cli.Run(forEachCmd)
}

// forEachCmd invokes the passed callback for each command supported by runsc.
func forEachCmd(cb func(cmd subcommands.Command, group string)) {
	// Help and flags commands are generated automatically.
	help := cmd.NewHelp(subcommands.DefaultCommander)
	help.Register(new(cmd.Platforms))
	help.Register(new(cmd.Syscalls))
	cb(help, "")
	cb(subcommands.FlagsCommand(), "")

	// Register OCI user-facing runsc commands.
	cb(new(cmd.Checkpoint), "")
	cb(new(cmd.Create), "")
	cb(new(cmd.Delete), "")
	cb(new(cmd.Do), "")
	cb(new(cmd.Events), "")
	cb(new(cmd.Exec), "")
	cb(new(cmd.Kill), "")
	cb(new(cmd.List), "")
	cb(new(cmd.PS), "")
	cb(new(cmd.Pause), "")
	cb(new(cmd.PortForward), "")
	cb(new(cmd.Restore), "")
	cb(new(cmd.Resume), "")
	cb(new(cmd.Run), "")
	cb(new(cmd.Spec), "")
	cb(new(cmd.Start), "")
	cb(new(cmd.State), "")
	cb(new(cmd.Tar), "")
	cb(new(cmd.Wait), "")

	// Helpers.
	const helperGroup = "helpers"
	cb(new(cmd.Install), helperGroup)
	cb(new(cmd.Mitigate), helperGroup)
	cb(new(cmd.Uninstall), helperGroup)
	cb(new(nvproxy.Nvproxy), helperGroup)
	cb(new(trace.Trace), helperGroup)
	cb(new(cmd.CPUFeatures), helperGroup)

	const debugGroup = "debug"
	cb(new(cmd.Debug), debugGroup)
	cb(new(cmd.Statefile), debugGroup)
	cb(new(cmd.Symbolize), debugGroup)
	cb(new(cmd.Usage), debugGroup)
	cb(new(cmd.ReadControl), debugGroup)
	cb(new(cmd.WriteControl), debugGroup)

	const metricGroup = "metrics"
	cb(new(cmd.MetricMetadata), metricGroup)
	cb(new(cmd.MetricExport), metricGroup)
	cb(new(cmd.MetricServer), metricGroup)

	// Internal commands.
	const internalGroup = "internal use only"
	cb(new(cmd.Boot), internalGroup)
	cb(new(cmd.Gofer), internalGroup)
	cb(new(cmd.Umount), internalGroup)
}

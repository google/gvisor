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

//go:build !false && network_plugins
// +build !false,network_plugins

// The `gvisor_sentry_plugin_stack` binary runs the gVisor sentry with a
// third-party plugin network stack linked in.
package main

import (
	_ "gvisor.dev/gvisor/pkg/sentry/socket/plugin/stack"
	"gvisor.dev/gvisor/runsc/cli"
	"gvisor.dev/gvisor/runsc/cmd/sentry/sentrycmd"
	"gvisor.dev/gvisor/runsc/cmd/util"
	"gvisor.dev/gvisor/runsc/gvisorbinaries"
)

func main() {
	cli.Run(&gvisorbinaries.GvisorSentryPluginStack, map[util.SubCommand]string{
		new(sentrycmd.Boot):   "internal use only",
		new(sentrycmd.Umount): "internal use only",
	}, nil)
}

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

//go:build amd64 || arm64
// +build amd64 arm64

// The xdp_loader tool is used to load compiled XDP object files into the XDP
// hook of a net device. It is intended primarily for testing.
package main

import (
	"context"
	_ "embed"
	"os"

	"github.com/google/subcommands"
	"gvisor.dev/gvisor/runsc/flag"
	"gvisor.dev/gvisor/tools/xdp/cmd"
)

func main() {
	subcommands.Register(new(cmd.DropCommand), "")
	subcommands.Register(new(cmd.PassCommand), "")
	subcommands.Register(new(cmd.RedirectHostCommand), "")
	subcommands.Register(new(cmd.TcpdumpCommand), "")
	subcommands.Register(new(cmd.TunnelCommand), "")

	flag.Parse()
	ctx := context.Background()
	os.Exit(int(subcommands.Execute(ctx)))
}

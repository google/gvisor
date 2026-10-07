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

//go:build (linux && amd64) || (linux && arm64)
// +build linux,amd64 linux,arm64

package cmd

import (
	"context"
	_ "embed"
	"fmt"

	"github.com/google/subcommands"
	"gvisor.dev/gvisor/pkg/xdp"
	"gvisor.dev/gvisor/runsc/flag"
)

//go:embed bpf/tunnel_host_ebpf.o
var tunnelHostProgram []byte

// TunnelCommand is a subcommand for tunneling traffic between two NICs. It is
// intended as a fast path between the host NIC and the veth of a container.
//
// SSH traffic is not tunneled. It is passed through to the Linux network stack.
type TunnelCommand struct {
	device      string
	deviceIndex int
	unpin       bool
}

// Name implements subcommands.Command.Name.
func (*TunnelCommand) Name() string {
	return "tunnel"
}

// Synopsis implements subcommands.Command.Synopsis.
func (*TunnelCommand) Synopsis() string {
	return "Tunnel packets between two interfaces using AF_XDP. Pins eBPF objects in /sys/fs/bpf/<interface name>/."
}

// Usage implements subcommands.Command.Usage.
func (*TunnelCommand) Usage() string {
	return "tunnel {-device <device> | -device-idx <device index>} [--unpin]"
}

// SetFlags implements subcommands.Command.SetFlags.
func (tn *TunnelCommand) SetFlags(fs *flag.FlagSet) {
	fs.StringVar(&tn.device, "device", "", "which host device to attach to")
	fs.IntVar(&tn.deviceIndex, "device-idx", 0, "which host device to attach to")
	fs.BoolVar(&tn.unpin, "unpin", false, "unpin the map and program instead of pinning new ones; useful to reset state")
}

// Execute implements subcommands.Command.Execute.
func (tn *TunnelCommand) Execute(context.Context, *flag.FlagSet, ...any) subcommands.ExitStatus {
	if err := tn.execute(); err != nil {
		fmt.Printf("%v\n", err)
		return subcommands.ExitFailure
	}
	return subcommands.ExitSuccess
}

func (tn *TunnelCommand) execute() error {
	iface, err := getIface(tn.device, tn.deviceIndex)
	if err != nil {
		return fmt.Errorf("failed to get host iface: %v", err)
	}

	return installProgramAndMap(installProgramAndMapOpts{
		program:     tunnelHostProgram,
		iface:       iface,
		unpin:       tn.unpin,
		pinDir:      xdp.RedirectPinDir(iface.Name),
		mapPath:     xdp.TunnelHostMapPath(iface.Name),
		programPath: xdp.TunnelHostProgramPath(iface.Name),
		linkPath:    xdp.TunnelHostLinkPath(iface.Name),
	})
}

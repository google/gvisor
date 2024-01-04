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

package cmd

import (
	"context"
	_ "embed"
	"fmt"
	"path/filepath"

	"github.com/google/subcommands"
	"gvisor.dev/gvisor/runsc/flag"
)

// TunnelPinDir returns the directory to which eBPF objects will be pinned when
// xdp_loader is run against iface.
func TunnelPinDir(iface string) string {
	return filepath.Join(bpffsDirPath, iface)
}

// TunnelHostMapPath returns the path where the eBPF map will be pinned when
// xdp_loader is run against iface.
func TunnelHostMapPath(iface string) string {
	return filepath.Join(TunnelPinDir(iface), "tunnel_host_map")
}

// TunnelHostProgramPath returns the path where the eBPF program will be pinned
// when xdp_loader is run against iface.
func TunnelHostProgramPath(iface string) string {
	return filepath.Join(TunnelPinDir(iface), "tunnel_host_program")
}

// TunnelHostLinkPath returns the path where the eBPF link will be pinned when
// xdp_loader is run against iface.
func TunnelHostLinkPath(iface string) string {
	return filepath.Join(TunnelPinDir(iface), "tunnel_host_link")
}

// TunnelVethMapPath returns the path where the eBPF map should be pinned when
// xdp_loader is run against iface.
func TunnelVethMapPath(iface string) string {
	return filepath.Join(TunnelPinDir(iface), "tunnel_veth_map")
}

// TunnelVethProgramPath returns the path where the eBPF program should be pinned
// when xdp_loader is run against iface.
func TunnelVethProgramPath(iface string) string {
	return filepath.Join(TunnelPinDir(iface), "tunnel_veth_program")
}

// TunnelVethLinkPath returns the path where the eBPF link should be pinned when
// xdp_loader is run against iface.
func TunnelVethLinkPath(iface string) string {
	return filepath.Join(TunnelPinDir(iface), "tunnel_veth_link")
}

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
		pinDir:      RedirectPinDir(iface.Name),
		mapPath:     TunnelHostMapPath(iface.Name),
		programPath: TunnelHostProgramPath(iface.Name),
		linkPath:    TunnelHostLinkPath(iface.Name),
	})
}

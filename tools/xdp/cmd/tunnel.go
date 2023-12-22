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
	"bytes"
	"context"
	_ "embed"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/cilium/ebpf"
	"github.com/google/subcommands"
	"gvisor.dev/gvisor/runsc/flag"
)

// TunnelPinDir returns the directory to which eBPF objects will be pinned when
// xdp_loader is run against iface.
// TODO: Same as redirect pin dir.
func TunnelPinDir(iface string) string {
	return filepath.Join(bpffsDirPath, iface)
}

// TunnelMapPath returns the path where the eBPF map will be pinned when
// xdp_loader is run against iface.
func TunnelHostMapPath(iface string) string {
	return filepath.Join(TunnelPinDir(iface), "tunnel_host_map")
}

// TunnelProgramPath returns the path where the eBPF program will be pinned
// when xdp_loader is run against iface.
func TunnelHostProgramPath(iface string) string {
	return filepath.Join(TunnelPinDir(iface), "tunnel_host_program")
}

// TunnelLinkPath returns the path where the eBPF link will be pinned when
// xdp_loader is run against iface.
func TunnelHostLinkPath(iface string) string {
	return filepath.Join(TunnelPinDir(iface), "tunnel_host_link")
}

// TunnelMapPath returns the path where the eBPF map will be pinned when
// xdp_loader is run against iface.
func TunnelVethMapPath(iface string) string {
	return filepath.Join(TunnelPinDir(iface), "tunnel_veth_map")
}

// TunnelProgramPath returns the path where the eBPF program will be pinned
// when xdp_loader is run against iface.
func TunnelVethProgramPath(iface string) string {
	return filepath.Join(TunnelPinDir(iface), "tunnel_veth_program")
}

// TunnelLinkPath returns the path where the eBPF link will be pinned when
// xdp_loader is run against iface.
func TunnelVethLinkPath(iface string) string {
	return filepath.Join(TunnelPinDir(iface), "tunnel_veth_link")
}

// TODO: The two tunnel programs appear to be identical.

//go:embed bpf/tunnel_host_ebpf.o
var tunnelHostProgram []byte

//go:embed bpf/tunnel_veth_ebpf.o
var tunnelVethProgram []byte

// TunnelCommand is a subcommand for tunneling traffic between two NICs. It is
// intended as a fast path between the host NIC and the veth of a container.
//
// Packets are forwarded based on a pair of pinned eBPF maps.
//
// SSH traffic is not tunneled. It is passed through to the Linux network stack.
type TunnelCommand struct {
	hostDevice      string
	hostDeviceIndex int
	vethDevice      string
	vethDeviceIndex int
	unpin           bool
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
	return "tunnel {-host-device <device> | -host-device-idx <device index>} {-veth-device <device> | -veth-device-idx <device index>} [--unpin]"
}

// SetFlags implements subcommands.Command.SetFlags.
func (tn *TunnelCommand) SetFlags(fs *flag.FlagSet) {
	fs.StringVar(&tn.hostDevice, "host-device", "", "which host device to attach to")
	fs.IntVar(&tn.hostDeviceIndex, "host-device-idx", 0, "which host device to attach to")
	fs.StringVar(&tn.vethDevice, "veth-device", "", "which veth device to attach to")
	fs.IntVar(&tn.vethDeviceIndex, "veth-device-idx", 0, "which veth device to attach to")
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

// TODO: Lotta redundancy within this and with redirect.
func (tn *TunnelCommand) execute() error {
	hostIface, err := getIface(tn.hostDevice, tn.hostDeviceIndex)
	if err != nil {
		return fmt.Errorf("failed to get host iface: %v", err)
	}
	// vethIface, err := getIface(tn.vethDevice, tn.vethDeviceIndex)
	// if err != nil {
	// 	return fmt.Errorf("failed to get veth iface: %v", err)
	// }

	var (
		hostPinDir      = RedirectPinDir(hostIface.Name)
		hostMapPath     = TunnelHostMapPath(hostIface.Name)
		hostProgramPath = TunnelHostProgramPath(hostIface.Name)
		hostLinkPath    = TunnelHostLinkPath(hostIface.Name)

		// vethPinDir      = RedirectPinDir(vethIface.Name)
		// vethMapPath     = TunnelVethMapPath(vethIface.Name)
		// vethProgramPath = TunnelVethProgramPath(vethIface.Name)
		// vethLinkPath    = TunnelVethLinkPath(vethIface.Name)
	)

	// User just wants to unpin things.
	if tn.unpin {
		return errors.Join(
			unpin(hostMapPath, hostProgramPath, hostLinkPath),
			// unpin(vethMapPath, vethProgramPath, vethLinkPath)
		)
	}

	// Load into the kernel.
	{
		spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(tunnelHostProgram))
		if err != nil {
			return fmt.Errorf("failed to load spec: %v", err)
		}

		var objects struct {
			Program *ebpf.Program `ebpf:"xdp_prog"`
			DevMap  *ebpf.Map     `ebpf:"dev_map"`
		}
		if err := spec.LoadAndAssign(&objects, nil); err != nil {
			return fmt.Errorf("failed to load program: %v", err)
		}
		defer func() {
			if err := objects.Program.Close(); err != nil {
				log.Printf("failed to close program: %v", err)
			}
			if err := objects.DevMap.Close(); err != nil {
				log.Printf("failed to close sock map: %v", err)
			}
		}()

		attachedLink, cleanup, err := attach(objects.Program, hostIface)
		if err != nil {
			return fmt.Errorf("failed to attach: %v", err)
		}
		defer cleanup()

		// Create directory /sys/fs/bpf/<device name>/.
		if err := os.Mkdir(hostPinDir, 0700); err != nil && !os.IsExist(err) {
			return fmt.Errorf("failed to create directory for pinning at %s: %v", hostPinDir, err)
		}

		// Pin the map at /sys/fs/bpf/<device name>/tunnel_host_map.
		if err := objects.DevMap.Pin(hostMapPath); err != nil {
			return fmt.Errorf("failed to pin map at %s", hostMapPath)
		}
		log.Printf("Pinned map at %s", hostMapPath)

		// Pin the program at /sys/fs/bpf/<device name>/tunnel_host_program.
		if err := objects.Program.Pin(hostProgramPath); err != nil {
			return fmt.Errorf("failed to pin program at %s", hostProgramPath)
		}
		log.Printf("Pinned program at %s", hostProgramPath)

		// Make everything persistent by pinning the link. Otherwise, the XDP
		// program would detach when this process exits.
		if err := attachedLink.Pin(hostLinkPath); err != nil {
			return fmt.Errorf("failed to pin link at %s", hostLinkPath)
		}
		log.Printf("Pinned link at %s", hostLinkPath)
	}
	// {
	// 	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(tunnelVethProgram))
	// 	if err != nil {
	// 		return fmt.Errorf("failed to load spec: %v", err)
	// 	}

	// 	var objects struct {
	// 		Program *ebpf.Program `ebpf:"xdp_prog"`
	// 		DevMap *ebpf.Map     `ebpf:"dev_map"`
	// 	}
	// 	if err := spec.LoadAndAssign(&objects, nil); err != nil {
	// 		return fmt.Errorf("failed to load program: %v", err)
	// 	}
	// 	defer func() {
	// 		if err := objects.Program.Close(); err != nil {
	// 			log.Printf("failed to close program: %v", err)
	// 		}
	// 		if err := objects.DevMap.Close(); err != nil {
	// 			log.Printf("failed to close sock map: %v", err)
	// 		}
	// 	}()

	// 	attachedLink, cleanup, err := attach(objects.Program, vethIface)
	// 	if err != nil {
	// 		return fmt.Errorf("failed to attach: %v", err)
	// 	}
	// 	defer cleanup()

	// 	// Create directory /sys/fs/bpf/<device name>/.
	// 	if err := os.Mkdir(vethPinDir, 0700); err != nil && !os.IsExist(err) {
	// 		return fmt.Errorf("failed to create directory for pinning at %s: %v", vethPinDir, err)
	// 	}

	// 	// Pin the map at /sys/fs/bpf/<device name>/tunnel_host_map.
	// 	if err := objects.DevMap.Pin(vethMapPath); err != nil {
	// 		return fmt.Errorf("failed to pin map at %s", vethMapPath)
	// 	}
	// 	log.Printf("Pinned map at %s", vethMapPath)

	// 	// Pin the program at /sys/fs/bpf/<device name>/tunnel_host_program.
	// 	if err := objects.Program.Pin(vethProgramPath); err != nil {
	// 		return fmt.Errorf("failed to pin program at %s", vethProgramPath)
	// 	}
	// 	log.Printf("Pinned program at %s", vethProgramPath)

	// 	// Make everything persistent by pinning the link. Otherwise, the XDP
	// 	// program would detach when this process exits.
	// 	if err := attachedLink.Pin(vethLinkPath); err != nil {
	// 		return fmt.Errorf("failed to pin link at %s", vethLinkPath)
	// 	}
	// 	log.Printf("Pinned link at %s", vethLinkPath)
	// }

	return nil
}

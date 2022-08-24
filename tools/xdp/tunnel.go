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

package main

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/binary"
	"fmt"
	"log"
	"net"

	"github.com/cilium/ebpf"
	"github.com/google/subcommands"
	"gvisor.dev/gvisor/runsc/flag"
)

// tunnelEgress has one map that holds the the device to which all traffic is
// redirected.
//
//go:embed bpf/tunnel_egress_ebpf.o
var tunnelEgress []byte

// tunnelIngress has two maps: one that holds the veth device and one
// that holds the veth peer (i.e. container) IP.
//
//go:embed bpf/tunnel_ingress_ebpf.o
var tunnelIngress []byte

// TunnelCommand is a subcommand for tunneling packets between a veth and
// non-veth interface.
//
// Packets that arrive at the veth (i.e. sent by the container) are always
// redirected to the non-veth device. Packets that arrive at the non-veth
// device are handled based on IP or ARP header:
//
//   - Packets sent to the selected IP are redirected to the veth. This handles
//     traffic to the container.
//   - Packets sent from the selected IP bounced out the interface via XDP_TX.
//     This handles traffic sent from the container.
//   - Other packets are passed on to the kernel network stack.
type TunnelCommand struct {
	dev       string
	devIndex  int
	veth      string
	vethIndex int
	ipStr     string
}

// Name implements subcommands.Command.Name.
func (*TunnelCommand) Name() string {
	return "tunnel"
}

// Synopsis implements subcommands.Command.Synopsis.
func (*TunnelCommand) Synopsis() string {
	return "Tunnel packets between a veth and non-veth interface."
}

// Usage implements subcommands.Command.Usage.
func (*TunnelCommand) Usage() string {
	return "tunnel -dev[Idx] <device or index> -veth[Idx] <device or index> -ip <IP address of the other end of the veth>"
}

// SetFlags implements subcommands.Command.SetFlags.
func (rc *TunnelCommand) SetFlags(fs *flag.FlagSet) {
	fs.StringVar(&rc.dev, "dev", "", "non-veth device")
	fs.IntVar(&rc.devIndex, "devIdx", 0, "non-veth device")
	fs.StringVar(&rc.veth, "veth", "", "veth device")
	fs.IntVar(&rc.vethIndex, "vethIdx", 0, "veth device")
	fs.StringVar(&rc.ipStr, "ip", "", "IP address of the other end of the veth")
}

// Execute implements subcommands.Command.Execute.
func (rc *TunnelCommand) Execute(context.Context, *flag.FlagSet, ...interface{}) subcommands.ExitStatus {
	if err := rc.execute(); err != nil {
		log.Printf("%v", err)
		return subcommands.ExitFailure
	}
	return subcommands.ExitSuccess
}

func (rc *TunnelCommand) execute() error {
	dev, err := getIface(rc.dev, rc.devIndex)
	if err != nil {
		return fmt.Errorf("failed to get dev iface: %v", err)
	}
	veth, err := getIface(rc.veth, rc.vethIndex)
	if err != nil {
		return fmt.Errorf("failed to get veth iface: %v", err)
	}

	ip := net.ParseIP(rc.ipStr)
	if ip.To4() == nil {
		return fmt.Errorf("invalid IPv4 address: %s", rc.ipStr)
	}

	// Setup the redirect program, which simply redirects all traffic from
	// the container/veth to the non-veth device.
	{
		// Load the BPF program into the kernel.
		spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(tunnelEgress))
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

		// Attach the program to the veth interface.
		cleanup, err := attach(objects.Program, veth)
		if err != nil {
			return fmt.Errorf("failed to attach: %v", err)
		}
		defer cleanup()

		// Insert our non-veth device into the BPF map.
		key := uint32(0)
		val := uint32(dev.Index)
		if err := objects.DevMap.Update(&key, &val, 0 /* flags */); err != nil {
			return fmt.Errorf("failed to insert device into BPF map: %v", err)
		}
		log.Printf("updated key %d to value %d", key, val)
	}

	// Setup the redirect_bounce program, which reads the IP or ARP header
	// to make routing decisions.
	{
		// Load the BPF program into the kernel.
		spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(tunnelIngress))
		if err != nil {
			return fmt.Errorf("failed to load spec: %v", err)
		}

		var objects struct {
			Program *ebpf.Program `ebpf:"xdp_prog"`
			IPMap   *ebpf.Map     `ebpf:"ip_map"`
			DevMap  *ebpf.Map     `ebpf:"dev_map"`
		}
		if err := spec.LoadAndAssign(&objects, nil); err != nil {
			return fmt.Errorf("failed to load program: %v", err)
		}
		defer func() {
			if err := objects.Program.Close(); err != nil {
				log.Printf("failed to close program: %v", err)
			}
			if err := objects.IPMap.Close(); err != nil {
				log.Printf("failed to close sock map: %v", err)
			}
			if err := objects.DevMap.Close(); err != nil {
				log.Printf("failed to close sock map: %v", err)
			}
		}()

		// Attach the program to the non-veth interface.
		cleanup, err := attach(objects.Program, dev)
		if err != nil {
			return fmt.Errorf("failed to attach: %v", err)
		}
		defer cleanup()

		// Insert our veth interface into the BPF map.
		key := uint32(0)
		val := uint32(veth.Index)
		if err := objects.DevMap.Update(&key, &val, 0 /* flags */); err != nil {
			return fmt.Errorf("failed to insert device into BPF map: %v", err)
		}
		log.Printf("updated key %d to value %d", key, val)

		// Insert the IP address into the BPF map.
		val = binary.LittleEndian.Uint32(ip.To4())
		if err := objects.IPMap.Update(&key, &val, 0 /* flags */); err != nil {
			return fmt.Errorf("failed to insert IP into BPF map: %v", err)
		}
		log.Printf("updated key %d to value %d", key, val)
	}

	waitForever()
	return nil
}

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

package main

import (
	"bytes"
	"fmt"
	"net"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/link/xdp"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/runsc/sandbox/bpf"
)

func newXDPEndpoint(ifaceName string, mac net.HardwareAddr) (stack.LinkEndpoint, error) {
	// Get all interfaces in the namespace.
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("querying interfaces: %v", err)
	}

	// Find our specific interface.
	var iface net.Interface
	for _, netif := range ifaces {
		if netif.Name == ifaceName {
			iface = netif
			break
		}
	}
	// Zero is never used as an Index. Use that to determine whether an
	// interface was found.
	if iface.Index == 0 {
		return nil, fmt.Errorf("failed to find interface: %v", ifaceName)
	}

	// See sandbox.createSocketXDP.

	// Create an XDP socket. Later we'll mmap memory for the various rings
	// and bind to the device.
	fd, err := unix.Socket(unix.AF_XDP, unix.SOCK_RAW, 0)
	if err != nil {
		return nil, fmt.Errorf("unable to create AF_XDP socket: %v", err)
	}

	// Attach a program to the device and insert our socket into its map.

	// Load into the kernel.
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(bpf.AFXDPProgram))
	if err != nil {
		return nil, fmt.Errorf("failed to load spec: %v", err)
	}

	var objects struct {
		Program *ebpf.Program `ebpf:"xdp_prog"`
		SockMap *ebpf.Map     `ebpf:"sock_map"`
	}
	if err := spec.LoadAndAssign(&objects, nil); err != nil {
		return nil, fmt.Errorf("failed to load program: %v", err)
	}

	_, err = link.AttachRawLink(link.RawLinkOptions{
		Program: objects.Program,
		Attach:  ebpf.AttachXDP,
		Target:  iface.Index,
		// By not setting the Flag field, the kernel will choose the
		// fastest mode. In order those are:
		// - Offloaded onto the NIC.
		// - Running directly in the driver.
		// - Generic mode, which works with any NIC/driver but lacks
		//   much of the XDP performance boost.
	})
	if err != nil {
		return nil, fmt.Errorf("failed to attach BPF program: %v", err)
	}

	// Insert our AF_XDP socket into the BPF map that dictates where
	// packets are redirected to.
	key := uint32(0)
	val := uint32(fd)
	if err := objects.SockMap.Update(&key, &val, 0 /* flags */); err != nil {
		return nil, fmt.Errorf("failed to insert socket into BPF map: %v", err)
	}

	return xdp.New(&xdp.Options{
		FD:                fd,
		Address:           tcpip.LinkAddress(mac),
		TXChecksumOffload: false,
		RXChecksumOffload: true,
		InterfaceIndex:    iface.Index,
	})
}

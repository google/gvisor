// Copyright 2018 The gVisor Authors.
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

package sandbox

import (
	"bytes"
	"fmt"
	"net"
	"os"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/runsc/sandbox/bpf"
)

func createSocketXDP(iface net.Interface) ([]*os.File, error) {
	// Create an XDP socket. The sentry will mmap memory for the various
	// rings and bind to the device.
	fd, err := unix.Socket(unix.AF_XDP, unix.SOCK_RAW, 0)
	if err != nil {
		return nil, fmt.Errorf("unable to create AF_XDP socket: %v", err)
	}

	// We also need to, before dropping privileges, attach a program to the
	// device and insert our socket into its map.

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

	rawLink, err := link.AttachRawLink(link.RawLinkOptions{
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

	// We need to keep the Program, SockMap, and link FDs open until they
	// can be passed to the sandbox process.
	progFD, err := unix.Dup(objects.Program.FD())
	if err != nil {
		return nil, fmt.Errorf("failed to dup BPF program: %v", err)
	}
	sockMapFD, err := unix.Dup(objects.SockMap.FD())
	if err != nil {
		return nil, fmt.Errorf("failed to dup BPF map: %v", err)
	}
	linkFD, err := unix.Dup(rawLink.FD())
	if err != nil {
		return nil, fmt.Errorf("failed to dup BPF link: %v", err)
	}

	return []*os.File{
		os.NewFile(uintptr(fd), "xdp-fd"),            // The socket.
		os.NewFile(uintptr(progFD), "program-fd"),    // The XDP program.
		os.NewFile(uintptr(sockMapFD), "sockmap-fd"), // The XDP map.
		os.NewFile(uintptr(linkFD), "link-fd"),       // The XDP link.
	}, nil
}

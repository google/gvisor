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
	"bytes"
	_ "embed"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/bufferv2"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/sniffer"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/xdp"
)

// Flags.
var (
	device      = flag.String("device", "", "which device to attach to")
	deviceIndex = flag.Int("devidx", 0, "which device to attach to")
	program     = flag.String("program", "", "which program to install: one of [pass, drop, tcpdump]")
)

// Builtin programs selectable by users.
var (
	//go:embed bpf/pass_ebpf.o
	pass []byte

	//go:embed bpf/drop_ebpf.o
	drop []byte

	//go:embed bpf/tcpdump_ebpf.o
	tcpdump []byte
)

var programs = map[string][]byte{
	"pass":    pass,
	"drop":    drop,
	"tcpdump": tcpdump,
}

func main() {
	// log.Fatalf skips important defers, so put everythin in the run
	// function where it can return errors instead.
	if err := run(); err != nil {
		log.Fatalf("%v", err)
	}
}

func run() error {
	// Sanity check.
	for name, prog := range programs {
		if len(prog) == 0 {
			panic(fmt.Sprintf("the %s program failed to embed", name))
		}
	}

	flag.Parse()

	// Get a net device.
	var iface *net.Interface
	var err error
	switch {
	case *device != "" && *deviceIndex != 0:
		return fmt.Errorf("must specify exactly one of -device or -devidx")
	case *device != "":
		if iface, err = net.InterfaceByName(*device); err != nil {
			return fmt.Errorf("unknown device %q: %v", *device, err)
		}
	case *deviceIndex != 0:
		if iface, err = net.InterfaceByIndex(*deviceIndex); err != nil {
			return fmt.Errorf("unknown device with index %d: %v", *deviceIndex, err)
		}
	default:
		return fmt.Errorf("must specify -device or -devidx")
	}

	// Choose a program.
	if *program == "" {
		return fmt.Errorf("must specify -program")
	}
	progData, ok := programs[*program]
	if !ok {
		return fmt.Errorf("unknown program %q", *program)
	}

	// Load into the kernel. Note that this is usually done using bpf2go,
	// but since we haven't set up that tool we do everything manually.
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(progData))
	if err != nil {
		return fmt.Errorf("failed to load spec: %v", err)
	}

	// We need to pass a struct with a field of a specific type and tag.
	var programObject *ebpf.Program
	var sockmap *ebpf.Map
	switch *program {
	case "pass", "drop":
		var objects struct {
			Program *ebpf.Program `ebpf:"xdp_prog"`
		}
		if err := spec.LoadAndAssign(&objects, nil); err != nil {
			return fmt.Errorf("failed to load program: %v", err)
		}
		programObject = objects.Program
		defer func() {
			if err := objects.Program.Close(); err != nil {
				log.Printf("failed to close program: %v", err)
			}
		}()
	case "tcpdump":
		var objects struct {
			Program *ebpf.Program `ebpf:"xdp_prog"`
			SockMap *ebpf.Map     `ebpf:"sock_map"`
		}
		if err := spec.LoadAndAssign(&objects, nil); err != nil {
			return fmt.Errorf("failed to load program: %v", err)
		}
		programObject = objects.Program
		sockmap = objects.SockMap
		defer func() {
			if err := objects.Program.Close(); err != nil {
				log.Printf("failed to close program: %v", err)
			}
			if err := objects.SockMap.Close(); err != nil {
				log.Printf("failed to close sock map: %v", err)
			}
		}()
	default:
		return fmt.Errorf("unknown program %q", *program)
	}

	// TODO(b/240191988): It would be nice to automatically detatch
	// existing XDP programs, although this can be done with iproute2:
	//   $ ip link set dev eth1 xdp off

	// Attach the program to the XDP hook on the device. Fallback from best
	// to worst mode.
	modes := []struct {
		name string
		flag link.XDPAttachFlags
	}{
		{name: "offload", flag: link.XDPOffloadMode},
		{name: "driver", flag: link.XDPDriverMode},
		{name: "generic", flag: link.XDPGenericMode},
	}
	var attached link.Link
	for _, mode := range modes {
		attached, err = link.AttachXDP(link.XDPOptions{
			Program:   programObject,
			Interface: iface.Index,
			Flags:     mode.flag,
		})
		if err == nil {
			log.Printf("attached with mode %q", mode.name)
			break
		}
		log.Printf("failed to attach with mode %q: %v", mode.name, err)
	}
	if attached == nil {
		return fmt.Errorf("failed to attach program")
	}
	defer attached.Close()

	// tcpdump requires opening an AF_XDP socket and having a goroutine
	// listen for packets.
	if *program == "tcpdump" {
		if err := startTcpdump(iface, sockmap); err != nil {
			return fmt.Errorf("failed to create AF_XDP socket: %v", err)
		}
	}

	log.Printf("Successfully attached! Press CTRL-C to quit and remove the program from the device.")
	for {
		unix.Pause()
	}
}

func startTcpdump(iface *net.Interface, sockMap *ebpf.Map) error {
	umem, fillQueue, rxQueue, err := xdp.ReadOnlySocket(
		uint32(iface.Index), 0 /* queueID */, xdp.DefaultReadOnlyOpts())
	if err != nil {
		return fmt.Errorf("failed to create socket: %v", err)
	}

	// Insert our AF_XDP socket into the BPF map that dictates where
	// packets are redirected to.
	key := uint32(0)
	val := umem.SockFD()
	if err := sockMap.Update(&key, &val, 0 /* flags */); err != nil {
		return fmt.Errorf("failed to insert socket into BPF map: %v", err)
	}
	log.Printf("updated key %d to value %d", key, val)

	// Put as many UMEM buffers into the fill queue as possible.
	fillQueue.FillAll()

	go func() {
		for {
			pfds := []unix.PollFd{{Fd: int32(umem.SockFD()), Events: unix.POLLIN}}
			_, err := unix.Poll(pfds, -1)
			if err != nil {
				if errors.Is(err, unix.EINTR) {
					continue
				}
				panic(fmt.Sprintf("poll failed: %v", err))
			}

			// How many packets did we get?
			nReceived, rxIndex := rxQueue.Peek()
			if nReceived == 0 {
				continue
			}

			// Keep the fill queue full.
			fillQueue.FillAll()

			// Read packets one-by-one and log them.
			for i := uint32(0); i < nReceived; i++ {
				// Wrap the packet in a PacketBuffer.
				descriptor := rxQueue.Get(rxIndex + i)
				data := umem.Get(descriptor)
				pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
					Payload: bufferv2.MakeWithData(data[header.EthernetMinimumSize:]),
				})

				sniffer.LogPacket("",
					sniffer.DirectionRecv, // XDP operates only on ingress.
					header.Ethernet(data).Type(),
					pkt)

				// NOTE: the address is always 256 bytes offset
				// from a page boundary. The kernel masks the
				// address to the frame size, so this isn't a
				// problem.
				//
				// Note that this limits MTU to 4096-256 bytes.
				umem.FreeFrame(descriptor.Addr)
			}
			rxQueue.Release(nReceived)
		}
	}()

	return nil
}

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
	"errors"
	"fmt"
	"log"

	"github.com/cilium/ebpf"
	"github.com/google/subcommands"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/bufferv2"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/sniffer"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/xdp"
	"gvisor.dev/gvisor/runsc/flag"
)

//go:embed bpf/tcpdump_ebpf.o
var tcpdumpProgram []byte

// TcpdumpCommand is a subcommand for capturing incoming packets.
type TcpdumpCommand struct {
	device      string
	deviceIndex int
}

// Name implements subcommands.Command.Name.
func (*TcpdumpCommand) Name() string {
	return "tcpdump"
}

// Synopsis implements subcommands.Command.Synopsis.
func (*TcpdumpCommand) Synopsis() string {
	return "Run tcpdump-like program that blocks incoming packets."
}

// Usage implements subcommands.Command.Usage.
func (*TcpdumpCommand) Usage() string {
	return "tcpdump -device <device> or -devidx <device index>"
}

// SetFlags implements subcommands.Command.SetFlags.
func (pc *TcpdumpCommand) SetFlags(fs *flag.FlagSet) {
	fs.StringVar(&pc.device, "device", "", "which device to attach to")
	fs.IntVar(&pc.deviceIndex, "devidx", 0, "which device to attach to")
}

// Execute implements subcommands.Command.Execute.
func (pc *TcpdumpCommand) Execute(context.Context, *flag.FlagSet, ...any) subcommands.ExitStatus {
	if err := pc.execute(); err != nil {
		fmt.Printf("%v", err)
		return subcommands.ExitFailure
	}
	return subcommands.ExitSuccess
}

func (pc *TcpdumpCommand) execute() error {
	iface, err := getIface(pc.device, pc.deviceIndex)
	if err != nil {
		return fmt.Errorf("%v", err)
	}

	// Load into the kernel.
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(tcpdumpProgram))
	if err != nil {
		return fmt.Errorf("failed to load spec: %v", err)
	}

	var objects struct {
		Program *ebpf.Program `ebpf:"xdp_prog"`
		SockMap *ebpf.Map     `ebpf:"sock_map"`
	}
	if err := spec.LoadAndAssign(&objects, nil); err != nil {
		return fmt.Errorf("failed to load program: %v", err)
	}
	defer func() {
		if err := objects.Program.Close(); err != nil {
			log.Printf("failed to close program: %v", err)
		}
		if err := objects.SockMap.Close(); err != nil {
			log.Printf("failed to close sock map: %v", err)
		}
	}()

	cleanup, err := attach(objects.Program, iface)
	if err != nil {
		return fmt.Errorf("failed to attach: %v", err)
	}
	defer cleanup()

	controlBlock, err := xdp.ReadOnlySocket(
		uint32(iface.Index), 0 /* queueID */, xdp.DefaultReadOnlyOpts())
	if err != nil {
		return fmt.Errorf("failed to create socket: %v", err)
	}

	// Insert our AF_XDP socket into the BPF map that dictates where
	// packets are redirected to.
	key := uint32(0)
	val := controlBlock.UMEM.SockFD()
	if err := objects.SockMap.Update(&key, &val, 0 /* flags */); err != nil {
		return fmt.Errorf("failed to insert socket into BPF map: %v", err)
	}
	log.Printf("updated key %d to value %d", key, val)

	// Put as many UMEM buffers into the fill queue as possible.
	controlBlock.UMEM.Lock()
	controlBlock.Fill.FillAll(&controlBlock.UMEM)
	controlBlock.UMEM.Unlock()

	go func() {
		controlBlock.UMEM.Lock()
		defer controlBlock.UMEM.Unlock()
		for {
			pfds := []unix.PollFd{{Fd: int32(controlBlock.UMEM.SockFD()), Events: unix.POLLIN}}
			_, err := unix.Poll(pfds, -1)
			if err != nil {
				if errors.Is(err, unix.EINTR) {
					continue
				}
				panic(fmt.Sprintf("poll failed: %v", err))
			}

			// How many packets did we get?
			nReceived, rxIndex := controlBlock.RX.Peek()
			if nReceived == 0 {
				continue
			}

			// Keep the fill queue full.
			controlBlock.Fill.FillAll(&controlBlock.UMEM)

			// Read packets one-by-one and log them.
			for i := uint32(0); i < nReceived; i++ {
				// Wrap the packet in a PacketBuffer.
				descriptor := controlBlock.RX.Get(rxIndex + i)
				data := controlBlock.UMEM.Get(descriptor)
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
				controlBlock.UMEM.FreeFrame(descriptor.Addr)
			}
			controlBlock.RX.Release(nReceived)
		}
	}()

	waitForever()
	return nil
}

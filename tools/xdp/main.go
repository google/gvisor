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
	"context"
	_ "embed"
	"fmt"
	"log"
	"net"
	"os"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/google/subcommands"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/runsc/flag"
)

func main() {
	subcommands.Register(new(DropCommand), "")
	subcommands.Register(new(PassCommand), "")
	subcommands.Register(new(TcpdumpCommand), "")

	flag.Parse()
	ctx := context.Background()
	os.Exit(int(subcommands.Execute(ctx)))
}

func runBasicProgram(progData []byte, device string, deviceIndex int) error {
	iface, err := getIface(device, deviceIndex)
	if err != nil {
		return fmt.Errorf("%v", err)
	}

	// Load into the kernel.
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(progData))
	if err != nil {
		return fmt.Errorf("failed to load spec: %v", err)
	}

	var objects struct {
		Program *ebpf.Program `ebpf:"xdp_prog"`
	}
	if err := spec.LoadAndAssign(&objects, nil); err != nil {
		return fmt.Errorf("failed to load program: %v", err)
	}
	defer func() {
		if err := objects.Program.Close(); err != nil {
			fmt.Printf("failed to close program: %v", err)
		}
	}()

	cleanup, err := attach(objects.Program, iface)
	if err != nil {
		return fmt.Errorf("failed to attach: %v", err)
	}
	defer cleanup()

	waitForever()
	return nil
}

func getIface(device string, deviceIndex int) (*net.Interface, error) {
	switch {
	case device != "" && deviceIndex != 0:
		return nil, fmt.Errorf("device specified twice")
	case device != "":
		iface, err := net.InterfaceByName(device)
		if err != nil {
			return nil, fmt.Errorf("unknown device %q: %v", device, err)
		}
		return iface, nil
	case deviceIndex != 0:
		iface, err := net.InterfaceByIndex(deviceIndex)
		if err != nil {
			return nil, fmt.Errorf("unknown device with index %d: %v", deviceIndex, err)
		}
		return iface, nil
	default:
		return nil, fmt.Errorf("no device specified")
	}
}

func attach(program *ebpf.Program, iface *net.Interface) (func(), error) {
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
	var err error
	for _, mode := range modes {
		attached, err = link.AttachXDP(link.XDPOptions{
			Program:   program,
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
		return nil, fmt.Errorf("failed to attach program")
	}
	return func() { attached.Close() }, nil
}

func waitForever() {
	log.Printf("Successfully attached! Press CTRL-C to quit and remove the program from the device.")
	for {
		unix.Pause()
	}
}

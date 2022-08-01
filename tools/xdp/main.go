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

// The xdp_loader tool is used to load compiled XDP object files into the XDP
// hook of a net device. It is intended primarily for testing.
package main

import (
	"bytes"
	_ "embed"
	"flag"
	"log"
	"net"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

var (
	device  = flag.String("device", "", "which device to attach to")
	program = flag.String("program", "", "which program to install: one of [pass, drop]")
)

// Builtin programs selectable by users.
var (
	//go:embed bpf/pass_ebpf.o
	pass []byte

	//go:embed bpf/drop_ebpf.o
	drop []byte
)

var programs = map[string][]byte{
	"pass": pass,
	"drop": drop,
}

func main() {
	// Sanity check.
	if len(pass) == 0 {
		panic("the pass program failed to embed")
	}
	if len(drop) == 0 {
		panic("the drop program failed to embed")
	}

	flag.Parse()

	// Get a net device.
	if *device == "" {
		log.Fatalf("must specify -device")
	}
	iface, err := net.InterfaceByName(*device)
	if err != nil {
		log.Fatalf("unknown device %q: %v", *device, err)
	}

	// Choose a program.
	if *program == "" {
		log.Fatalf("must specify -program")
	}
	progData, ok := programs[*program]
	if !ok {
		log.Fatalf("unknown program %q", *program)
	}

	// Load into the kernel. Note that this is usually done using bpf2go,
	// but since we haven't set up that tool we do everything manually.
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(progData))
	if err != nil {
		log.Fatalf("failed to load spec: %v", err)
	}

	// We need to pass a struct with a field of a specific type and tag.
	var objects struct {
		Program *ebpf.Program `ebpf:"xdp_prog"`
	}
	if err := spec.LoadAndAssign(&objects, nil); err != nil {
		log.Fatalf("failed to load program: %v", err)
	}
	defer func() {
		if err := objects.Program.Close(); err != nil {
			log.Printf("failed to close program: %v", err)
		}
	}()

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
			Program:   objects.Program,
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
		log.Fatalf("failed to attach program")
	}
	defer attached.Close()

	log.Printf("Successfully attached! Press CTRL-C to quit and remove the program from the device.")
	for {
		unix.Pause()
	}
}

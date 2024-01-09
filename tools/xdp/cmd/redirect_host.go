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
	"net"
	"os"
	"path/filepath"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/google/subcommands"
	"gvisor.dev/gvisor/runsc/flag"
)

// bpffsDirName is the path at which BPFFS is expected to be mounted.
const bpffsDirPath = "/sys/fs/bpf/"

// RedirectPinDir returns the directory to which eBPF objects will be pinned
// when xdp_loader is run against iface.
func RedirectPinDir(iface string) string {
	return filepath.Join(bpffsDirPath, iface)
}

// RedirectMapPath returns the path where the eBPF map will be pinned when
// xdp_loader is run against iface.
func RedirectMapPath(iface string) string {
	return filepath.Join(RedirectPinDir(iface), "redirect_ip_map")
}

// RedirectProgramPath returns the path where the eBPF program will be pinned
// when xdp_loader is run against iface.
func RedirectProgramPath(iface string) string {
	return filepath.Join(RedirectPinDir(iface), "redirect_program")
}

// RedirectLinkPath returns the path where the eBPF link will be pinned when
// xdp_loader is run against iface.
func RedirectLinkPath(iface string) string {
	return filepath.Join(RedirectPinDir(iface), "redirect_link")
}

//go:embed bpf/redirect_host_ebpf.o
var redirectProgram []byte

// RedirectHostCommand is a subcommand for redirecting incoming packets based
// on a pinned eBPF map. It redirects all non-SSH traffic to a single AF_XDP
// socket.
type RedirectHostCommand struct {
	device      string
	deviceIndex int
	unpin       bool
}

// Name implements subcommands.Command.Name.
func (*RedirectHostCommand) Name() string {
	return "redirect"
}

// Synopsis implements subcommands.Command.Synopsis.
func (*RedirectHostCommand) Synopsis() string {
	return "Redirect incoming packets to an AF_XDP socket. Pins eBPF objects in /sys/fs/bpf/<interface name>/."
}

// Usage implements subcommands.Command.Usage.
func (*RedirectHostCommand) Usage() string {
	return "redirect {-device <device> | -device-idx <device index>} [--unpin]"
}

// SetFlags implements subcommands.Command.SetFlags.
func (rc *RedirectHostCommand) SetFlags(fs *flag.FlagSet) {
	fs.StringVar(&rc.device, "device", "", "which device to attach to")
	fs.IntVar(&rc.deviceIndex, "device-idx", 0, "which device to attach to")
	fs.BoolVar(&rc.unpin, "unpin", false, "unpin the map and program instead of pinning new ones; useful to reset state")
}

// Execute implements subcommands.Command.Execute.
func (rc *RedirectHostCommand) Execute(context.Context, *flag.FlagSet, ...any) subcommands.ExitStatus {
	if err := rc.execute(); err != nil {
		fmt.Printf("%v\n", err)
		return subcommands.ExitFailure
	}
	return subcommands.ExitSuccess
}

func (rc *RedirectHostCommand) execute() error {
	iface, err := getIface(rc.device, rc.deviceIndex)
	if err != nil {
		return fmt.Errorf("%v", err)
	}

	return installProgramAndMap(installProgramAndMapOpts{
		program:     redirectProgram,
		iface:       iface,
		unpin:       rc.unpin,
		pinDir:      RedirectPinDir(iface.Name),
		mapPath:     RedirectMapPath(iface.Name),
		programPath: RedirectProgramPath(iface.Name),
		linkPath:    RedirectLinkPath(iface.Name),
	})
}

type installProgramAndMapOpts struct {
	program     []byte
	iface       *net.Interface
	unpin       bool
	pinDir      string
	mapPath     string
	programPath string
	linkPath    string
}

func installProgramAndMap(opts installProgramAndMapOpts) error {
	// User just wants to unpin things.
	if opts.unpin {
		return unpin(opts.mapPath, opts.programPath, opts.linkPath)
	}

	// Load into the kernel.
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(opts.program))
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

	attachedLink, cleanup, err := attach(objects.Program, opts.iface)
	if err != nil {
		return fmt.Errorf("failed to attach: %v", err)
	}
	defer cleanup()

	// Create directory /sys/fs/bpf/<device name>/.
	if err := os.Mkdir(opts.pinDir, 0700); err != nil && !os.IsExist(err) {
		return fmt.Errorf("failed to create directory for pinning at %s: %v", opts.pinDir, err)
	}

	// Pin the map at /sys/fs/bpf/<device name>/ip_map.
	if err := objects.SockMap.Pin(opts.mapPath); err != nil {
		return fmt.Errorf("failed to pin map at %s", opts.mapPath)
	}
	log.Printf("Pinned map at %s", opts.mapPath)

	// Pin the program at /sys/fs/bpf/<device name>/program.
	if err := objects.Program.Pin(opts.programPath); err != nil {
		return fmt.Errorf("failed to pin program at %s", opts.programPath)
	}
	log.Printf("Pinned program at %s", opts.programPath)

	// Make everything persistent by pinning the link. Otherwise, the XDP
	// program would detach when this process exits.
	if err := attachedLink.Pin(opts.linkPath); err != nil {
		return fmt.Errorf("failed to pin link at %s", opts.linkPath)
	}
	log.Printf("Pinned link at %s", opts.linkPath)

	return nil
}

func unpin(mapPath, programPath, linkPath string) error {
	// Try to unpin both the map and program even if only one is found.
	mapErr := func() error {
		pinnedMap, err := ebpf.LoadPinnedMap(mapPath, nil)
		if err != nil {
			return fmt.Errorf("failed to load pinned map at %s for unpinning: %v", mapPath, err)
		}
		if err := pinnedMap.Unpin(); err != nil {
			return fmt.Errorf("failed to unpin map %s: %v", mapPath, err)
		}
		log.Printf("Unpinned map at %s", mapPath)
		return nil
	}()
	programErr := func() error {
		pinnedProgram, err := ebpf.LoadPinnedProgram(programPath, nil)
		if err != nil {
			return fmt.Errorf("failed to load pinned program at %s for unpinning: %v", programPath, err)
		}
		if err := pinnedProgram.Unpin(); err != nil {
			return fmt.Errorf("failed to unpin program %s: %v", programPath, err)
		}
		log.Printf("Unpinned program at %s", programPath)
		return nil
	}()
	linkErr := func() error {
		pinnedLink, err := link.LoadPinnedLink(linkPath, nil)
		if err != nil {
			return fmt.Errorf("failed to load pinned link at %s for unpinning: %v", linkPath, err)
		}
		if err := pinnedLink.Unpin(); err != nil {
			return fmt.Errorf("failed to unpin link %s: %v", linkPath, err)
		}
		log.Printf("Unpinned link at %s", linkPath)
		return nil
	}()
	return errors.Join(mapErr, programErr, linkErr)
}

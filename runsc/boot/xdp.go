// Copyright 2025 The gVisor Authors.
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

//go:build xdp
// +build xdp

package boot

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/urpc"
	"gvisor.dev/gvisor/pkg/xdp"
	"gvisor.dev/gvisor/runsc/config"
	"gvisor.dev/gvisor/runsc/sandbox/bpf"
	xdpcmd "gvisor.dev/gvisor/tools/xdp/cmd"
)

func setupXDPModeRedirectArgs(netConf *NetworkConfig) error {
	// Create an XDP socket. The sentry will mmap the rings.
	xdpSockFD, err := unix.Socket(unix.AF_XDP, unix.SOCK_RAW, 0)
	if err != nil {
		return fmt.Errorf("unable to create AF_XDP socket: %w", err)
	}
	xdpSock := os.NewFile(uintptr(xdpSockFD), "xdp-sock-fd")

	// Dup to ensure os.File doesn't close it prematurely.
	if _, err := unix.Dup(xdpSockFD); err != nil {
		return fmt.Errorf("failed to dup XDP sock: %w", err)
	}
	netConf.args.FilePayload.Files = append(args.FilePayload.Files, xdpSock)

	if err := pcapAndNAT(netConf.args, conf); err != nil {
		return err
	}

	log.Infof("Setting up network, config: %+v", netConf.args)
	return nil
}

func setupXDPModeRedirectInterface(netConf *NetworkConfig) error {
	iface := netConf.iface
	// Insert socket into eBPF map. Note that sockets are automatically
	// removed from eBPF maps when released. See net/xdp/xsk.c:xsk_release
	// and net/xdp/xsk.c:xsk_delete_from_maps.
	mapPath := xdpcmd.RedirectMapPath(iface.Name)
	pinnedMap, err := ebpf.LoadPinnedMap(mapPath, nil)
	if err != nil {
		return fmt.Errorf("failed to load pinned map %s: %w", mapPath, err)
	}
	// TODO(b/240191988): Updating of pinned maps should be sychronized and
	// check for the existence of the key.
	mapKey := uint32(0)
	mapVal := uint32(xdpSockFD)
	if err := pinnedMap.Update(&mapKey, &mapVal, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("failed to insert socket into map %s: %w", mapPath, err)
	}

	// Bind to the device.
	// TODO(b/240191988): We can't assume there's only one queue, but this
	// appears to be the case on gVNIC instances.
	if err := xdp.Bind(xdpSockFD, uint32(iface.Index), 0 /* queueID */, true /*conf.AFXDPUseNeedWakeup*/); err != nil {
		return fmt.Errorf("failed to bind to interface %q: %v", iface.Name, err)
	}

	return nil
}

func setupXDPModeTunnel(netConf *NetworkConfig) error {
	args := netConf.args
	// Setup the XDP socket on the gVisor nic.
	files, err := func() ([]*os.File, error) {
		// Join the network namespace that we will be copying.
		restore, err := joinNetNS(nsPath)
		if err != nil {
			return nil, err
		}
		defer restore()

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

		// We assume there are two interfaces in the netns: a loopback and veth.
		ifaces, err := net.Interfaces()
		if err != nil {
			return nil, fmt.Errorf("querying interfaces in ns: %w", err)
		}

		var iface *net.Interface
		for _, netIface := range ifaces {
			if netIface.Flags&net.FlagLoopback == 0 {
				iface = &netIface
				break
			}
		}
		if iface == nil {
			return nil, fmt.Errorf("unable to find non-loopback interface in the ns")
		}
		args.XDPLinks[0].InterfaceIndex = iface.Index

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
			return nil, fmt.Errorf("failed to attach BPF program to interface %q: %v", iface.Name, err)
		}

		// Insert our AF_XDP socket into the BPF map that dictates where
		// packets are redirected to.
		// TODO(b/240191988): Updating of pinned maps should be
		// sychronized and check for the existence of the key.
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
	}()
	if err != nil {
		return fmt.Errorf("failed to create AF_XDP socket for container: %w", err)
	}
	args.FilePayload.Files = append(args.FilePayload.Files, files...)

	// We're back in the parent netns. Get all interfaces.
	ifaces, err := net.Interfaces()
	if err != nil {
		return fmt.Errorf("querying interfaces: %w", err)
	}

	// TODO(b/240191988): Find a better way to identify the other end of the veth.
	var vethIface *net.Interface
	for _, iface := range ifaces {
		if strings.HasPrefix(iface.Name, "veth") {
			vethIface = &iface
			break
		}
	}
	if vethIface == nil {
		return fmt.Errorf("unable to find veth interface")
	}

	// Insert veth into host eBPF map.
	hostMapPath := xdpcmd.TunnelHostMapPath(hostIface.Name)
	pinnedHostMap, err := ebpf.LoadPinnedMap(hostMapPath, nil)
	if err != nil {
		return fmt.Errorf("failed to load pinned host map %s: %w", hostMapPath, err)
	}
	// TODO(b/240191988): Updating of pinned maps should be sychronized and
	// check for the existence of the key.
	mapKey := uint32(0)
	mapVal := uint32(vethIface.Index)
	if err := pinnedHostMap.Update(&mapKey, &mapVal, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("failed to insert veth into host map %s: %w", hostMapPath, err)
	}

	// Attach a program to the veth.
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(bpf.TunnelVethProgram))
	if err != nil {
		return fmt.Errorf("failed to load spec: %v", err)
	}

	var objects struct {
		Program *ebpf.Program `ebpf:"xdp_veth_prog"`
		DevMap  *ebpf.Map     `ebpf:"dev_map"`
	}
	if err := spec.LoadAndAssign(&objects, nil); err != nil {
		return fmt.Errorf("failed to load program: %v", err)
	}
	defer func() {
		if err := objects.Program.Close(); err != nil {
			log.Infof("failed to close program: %v", err)
		}
		if err := objects.DevMap.Close(); err != nil {
			log.Infof("failed to close sock map: %v", err)
		}
	}()

	attached, err := link.AttachXDP(link.XDPOptions{
		Program:   objects.Program,
		Interface: vethIface.Index,
		// By not setting the Flag field, the kernel will choose the
		// fastest mode. In order those are:
		// - Offloaded onto the NIC.
		// - Running directly in the driver.
		// - Generic mode, which works with any NIC/driver but lacks
		//   much of the XDP performance boost.
	})
	if err != nil {
		return fmt.Errorf("failed to attach: %w", err)
	}

	var (
		vethPinDir      = xdpcmd.RedirectPinDir(vethIface.Name)
		vethMapPath     = xdpcmd.TunnelVethMapPath(vethIface.Name)
		vethProgramPath = xdpcmd.TunnelVethProgramPath(vethIface.Name)
		vethLinkPath    = xdpcmd.TunnelVethLinkPath(vethIface.Name)
	)

	// Create directory /sys/fs/bpf/<device name>/.
	if err := os.Mkdir(vethPinDir, 0700); err != nil && !os.IsExist(err) {
		return fmt.Errorf("failed to create directory for pinning at %s: %v", vethPinDir, err)
	}

	// Pin the map at /sys/fs/bpf/<device name>/tunnel_host_map.
	if err := objects.DevMap.Pin(vethMapPath); err != nil {
		return fmt.Errorf("failed to pin map at %s", vethMapPath)
	}
	log.Infof("Pinned map at %s", vethMapPath)

	// Pin the program at /sys/fs/bpf/<device name>/tunnel_host_program.
	if err := objects.Program.Pin(vethProgramPath); err != nil {
		return fmt.Errorf("failed to pin program at %s", vethProgramPath)
	}
	log.Infof("Pinned program at %s", vethProgramPath)

	// Make everything persistent by pinning the link. Otherwise, the XDP
	// program would detach when this process exits.
	if err := attached.Pin(vethLinkPath); err != nil {
		return fmt.Errorf("failed to pin link at %s", vethLinkPath)
	}
	log.Infof("Pinned link at %s", vethLinkPath)

	// Insert host into veth eBPF map.
	// TODO(b/240191988): We should be able to use the existing map instead
	// of opening a pinned copy.
	pinnedVethMap, err := ebpf.LoadPinnedMap(vethMapPath, nil)
	if err != nil {
		return fmt.Errorf("failed to load pinned veth map %s: %w", vethMapPath, err)
	}
	// TODO(b/240191988): Updating of pinned maps should be sychronized and
	// check for the existence of the key.
	mapKey = uint32(0)
	mapVal = uint32(hostIface.Index)
	if err := pinnedVethMap.Update(&mapKey, &mapVal, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("failed to insert host into veth map %s: %w", vethMapPath, err)
	}

	if err := pcapAndNAT(&args, conf); err != nil {
		return err
	}

	log.Debugf("Setting up network, config: %+v", args)
	return nil
}

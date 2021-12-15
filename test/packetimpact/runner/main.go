// Copyright 2021 The gVisor Authors.
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

//go:build linux && go1.10
// +build linux,go1.10

// The runner binary is used as the test runner for PacketImpact tests.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/vishvananda/netlink"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/test/packetimpact/dut"
	"gvisor.dev/gvisor/test/packetimpact/internal/testing"
	netdevs "gvisor.dev/gvisor/test/packetimpact/netdevs/netlink"
	"gvisor.dev/gvisor/test/packetimpact/testbench"
)

type dutArgList []string

// String implements flag.Value.
func (l *dutArgList) String() string {
	return strings.Join(*l, " ")
}

// Set implements flag.Value.
func (l *dutArgList) Set(value string) error {
	*l = append(*l, value)
	return nil
}

func main() {
	const procSelfExe = "/proc/self/exe"
	if os.Args[0] != procSelfExe {
		// For the first time, re-execute in a new user name space and a new
		// network namespace.
		cmd := exec.Command(procSelfExe, os.Args[1:]...)
		cmd.SysProcAttr = &unix.SysProcAttr{
			Cloneflags: unix.CLONE_NEWUSER | unix.CLONE_NEWNET,
			Pdeathsig:  unix.SIGTERM,
			UidMappings: []syscall.SysProcIDMap{
				{
					ContainerID: 0,
					HostID:      os.Getuid(),
					Size:        1,
				},
			},
			GidMappings: []syscall.SysProcIDMap{
				{
					ContainerID: 0,
					HostID:      os.Getgid(),
					Size:        1,
				},
			},
		}
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			if exitStatus, ok := err.(*exec.ExitError); ok {
				os.Exit(exitStatus.ExitCode())
			} else {
				log.Fatalf("unknown failure: %s", err)
			}
		}
		return
	}

	var (
		dutBinary     string
		testBinary    string
		expectFailure bool
		numDUTs       int
		variant       string
		dutArgs       dutArgList
	)
	fs := flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
	fs.StringVar(&dutBinary, "dut_binary", "", "path to the DUT binary")
	fs.StringVar(&testBinary, "testbench_binary", "", "path to the test binary")
	fs.BoolVar(&expectFailure, "expect_failure", false, "whether the test is expected to fail")
	fs.IntVar(&numDUTs, "num_duts", 1, "number of DUTs to create")
	fs.StringVar(&variant, "variant", "", "test variant could be native, gvisor or fuchsia")
	fs.Var(&dutArgs, "dut_arg", "argument to the DUT binary")
	if err := fs.Parse(os.Args[1:]); err != nil {
		log.Fatal(err)
	}

	g, ctx := errgroup.WithContext(context.Background())

	// Create all the DUTs.
	infoCh := make(chan testbench.DUTInfo, numDUTs)
	var duts []*dutProcess
	for i := 0; i < numDUTs; i++ {
		d, err := newDUT(ctx, i, dutBinary, dutArgs)
		if err != nil {
			log.Fatal(err)
		}
		duts = append(duts, d)
		g.Go(func() error {
			info, waitFn, err := d.bootstrap(ctx)
			if err != nil {
				return err
			}
			infoCh <- info
			return waitFn()
		})
	}

	// Wait for all the DUTs to bootstrap.
	var infos []testbench.DUTInfo
	for i := 0; i < numDUTs; i++ {
		select {
		case <-ctx.Done():
			log.Fatalf("failed to bootstrap dut: %s", g.Wait())
		case info := <-infoCh:
			infos = append(infos, info)
		}
	}

	dutJSON, err := json.Marshal(&infos)
	if err != nil {
		log.Fatalf("failed to marshal json: %s", err)
	}

	for _, d := range duts {
		// When the Linux kernel receives a SYN-ACK for a SYN it didn't send, it
		// will respond with an RST. In most packetimpact tests, the SYN is sent
		// by the raw socket, the kernel knows nothing about the connection, this
		// behavior will break lots of TCP related packetimpact tests. To prevent
		// this, we can install the following iptables rules. The raw socket that
		// packetimpact tests use will still be able to see everything.
		for _, iptables := range []string{"/sbin/iptables-nft", "/sbin/ip6tables-nft"} {
			cmd := exec.Command(iptables, "-A", "INPUT", "-i", d.peerIface(), "--proto", "tcp", "-j", "DROP")
			if output, err := cmd.CombinedOutput(); err != nil {
				log.Fatalf("failed to set iptables: %s, output: %s", err, string(output))
			}
		}
		// Start packet capture.
		g.Go(func() error {
			return d.writePcap(ctx, filepath.Base(testBinary))
		})
	}

	// Start the test itself.
	testResult := make(chan error, 1)
	go func() {
		testArgs := []string{"--dut_infos_json", string(dutJSON)}
		if variant == "native" {
			testArgs = append(testArgs, "-native")
		}
		test := exec.CommandContext(ctx, testBinary, testArgs...)
		test.SysProcAttr = &unix.SysProcAttr{
			Pdeathsig: unix.SIGTERM,
		}
		test.Stderr = os.Stderr
		test.Stdout = os.Stdout
		testResult <- test.Run()
	}()

	select {
	case <-ctx.Done():
		log.Fatalf("background tasks exited early: %s", g.Wait())
	case err := <-testResult:
		switch {
		case err != nil == expectFailure:
			// Expected.
		case expectFailure:
			log.Fatalf("the test is expected to fail, but it succeeded")
		case err != nil:
			var exitStatus *exec.ExitError
			if errors.As(err, &exitStatus) {
				os.Exit(exitStatus.ExitCode())
			}
			log.Fatalf("unknown error when executing test: %s", err)
		}
	}
}

type dutProcess struct {
	cmd       *exec.Cmd
	id        int
	completeR *os.File
	dutNetNS  netNS
}

func newDUT(ctx context.Context, id int, dutBinary string, dutArgs dutArgList) (*dutProcess, error) {
	cmd := exec.CommandContext(ctx, dutBinary, append([]string{
		"--" + dut.CtrlIface, dutSide.ifaceName(ctrlLink, id),
		"--" + dut.TestIface, dutSide.ifaceName(testLink, id),
	}, dutArgs...)...)

	// Create the pipe for completion signal
	completeR, completeW, err := os.Pipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create pipe for completion signal: %w", err)
	}

	// Create a new network namespace for the DUT.
	dutNetNS, err := newNetNS()
	if err != nil {
		return nil, fmt.Errorf("failed to create a new namespace for DUT: %w", err)
	}

	// Pass these two file descriptors to the DUT.
	cmd.ExtraFiles = append(cmd.ExtraFiles, completeW)

	// Deliver SIGTERM to the child when the runner exits.
	cmd.SysProcAttr = &unix.SysProcAttr{
		Pdeathsig: unix.SIGTERM,
	}

	// Stream outputs from the DUT binary.
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	// Now create the veth pairs to connect the DUT and us.
	for _, typ := range []linkType{ctrlLink, testLink} {
		dutSideIfaceName := dutSide.ifaceName(typ, id)
		tbSideIfaceName := tbSide.ifaceName(typ, id)
		dutVeth := netlink.Veth{
			LinkAttrs: netlink.LinkAttrs{
				Name: dutSideIfaceName,
			},
			PeerName: tbSideIfaceName,
		}
		tbVeth := netlink.Veth{
			LinkAttrs: netlink.LinkAttrs{
				Name: tbSideIfaceName,
			},
			PeerName: dutSideIfaceName,
		}
		if err := netlink.LinkAdd(&dutVeth); err != nil {
			return nil, fmt.Errorf("failed to add a %s veth pair for dut-%d: %w", typ, id, err)
		}

		tbIPv4 := typ.ipv4(uint8(id), 1)
		dutIPv4 := typ.ipv4(uint8(id), 2)

		// Move the DUT end into the created namespace.
		if err := netlink.LinkSetNsFd(&dutVeth, int(dutNetNS)); err != nil {
			return nil, fmt.Errorf("failed to move %s veth end to dut-%d: %w", typ, id, err)
		}

		for _, conf := range []struct {
			ns   netNS
			addr *netlink.Addr
			veth *netlink.Veth
		}{
			{ns: currentNetNS, addr: tbIPv4, veth: &tbVeth},
			{ns: dutNetNS, addr: dutIPv4, veth: &dutVeth},
		} {
			if err := conf.ns.Do(func() error {
				// Disable the DAD so that the generated IPv6 address can be used immediately.
				if err := disableDad(conf.veth.Name); err != nil {
					return fmt.Errorf("failed to disable DAD on %s: %w", conf.veth.Name, err)
				}
				// Manually add the IPv4 address.
				if err := netlink.AddrAdd(conf.veth, conf.addr); err != nil {
					return fmt.Errorf("failed to add addr %s to %s: %w", conf.addr, conf.veth.Name, err)
				}
				// Bring the link up.
				if err := netlink.LinkSetUp(conf.veth); err != nil {
					return fmt.Errorf("failed to set %s up: %w", conf.veth.Name, err)
				}
				return nil
			}); err != nil {
				return nil, err
			}
		}
	}

	// Bring the loopback interface up in both namespaces.
	for _, ns := range []netNS{currentNetNS, dutNetNS} {
		if err := ns.Do(func() error {
			return netlink.LinkSetUp(&netlink.Device{
				LinkAttrs: netlink.LinkAttrs{
					Name: "lo",
				},
			})
		}); err != nil {
			return nil, fmt.Errorf("failed to bring loopback up: %w", err)
		}
	}

	return &dutProcess{cmd: cmd, id: id, completeR: completeR, dutNetNS: dutNetNS}, nil
}

func (d *dutProcess) bootstrap(ctx context.Context) (testbench.DUTInfo, func() error, error) {
	if err := d.dutNetNS.Do(func() error {
		return d.cmd.Start()
	}); err != nil {
		return testbench.DUTInfo{}, nil, fmt.Errorf("failed to start DUT %d: %w", d.id, err)
	}
	for _, file := range d.cmd.ExtraFiles {
		if err := file.Close(); err != nil {
			return testbench.DUTInfo{}, nil, fmt.Errorf("close(%d) = %w", file.Fd(), err)
		}
	}

	bytes, err := io.ReadAll(d.completeR)
	if err != nil {
		return testbench.DUTInfo{}, nil, fmt.Errorf("failed to read from %s complete pipe: %w", d.name(), err)
	}
	if err := d.completeR.Close(); err != nil {
		return testbench.DUTInfo{}, nil, fmt.Errorf("failed to close the read end of completion pipe: %w", err)
	}
	var dutInfo testbench.DUTInfo
	if err := json.Unmarshal(bytes, &dutInfo); err != nil {
		return testbench.DUTInfo{}, nil, fmt.Errorf("invalid response from %s: %w, received: %s", d.name(), err, string(bytes))
	}
	testIface, testIPv4, testIPv6, err := netdevs.IfaceInfo(d.peerIface())
	if err != nil {
		return testbench.DUTInfo{}, nil, fmt.Errorf("failed to gather information about the testbench: %w", err)
	}
	dutInfo.Net.LocalMAC = testIface.Attrs().HardwareAddr
	dutInfo.Net.LocalIPv4 = testIPv4.IP.To4()
	dutInfo.Net.LocalIPv6 = testIPv6.IP
	dutInfo.Net.LocalDevID = uint32(testIface.Attrs().Index)
	dutInfo.Net.LocalDevName = testIface.Attrs().Name
	return dutInfo, d.cmd.Wait, nil
}

func (d *dutProcess) name() string {
	return fmt.Sprintf("dut-%d", d.id)
}

func (d *dutProcess) peerIface() string {
	return tbSide.ifaceName(testLink, d.id)
}

// writePcap creates the packet capture while the test is running.
func (d *dutProcess) writePcap(ctx context.Context, testName string) error {
	iface := d.peerIface()
	// Create the pcap file.
	fileName, err := testing.UndeclaredOutput(fmt.Sprintf("%s_%s.pcap", testName, iface))
	if err != nil {
		return err
	}
	pcap, err := os.Create(fileName)
	if err != nil {
		return fmt.Errorf("open(%s) = %w", fileName, err)
	}
	defer func() {
		if err := pcap.Close(); err != nil {
			panic(fmt.Sprintf("close(%s) = %s", pcap.Name(), err))
		}
	}()

	// Start the packet capture.
	pcapw := pcapgo.NewWriter(pcap)
	if err := pcapw.WriteFileHeader(1600, layers.LinkTypeEthernet); err != nil {
		return fmt.Errorf("WriteFileHeader: %w", err)
	}
	handle, err := pcapgo.NewEthernetHandle(iface)
	if err != nil {
		return fmt.Errorf("pcapgo.NewEthernetHandle(%s): %w", iface, err)
	}
	source := gopacket.NewPacketSource(handle, layers.LayerTypeEthernet)
	for {
		select {
		case packet := <-source.Packets():
			if err := pcapw.WritePacket(packet.Metadata().CaptureInfo, packet.Data()); err != nil {
				return fmt.Errorf("pcapw.WritePacket(): %w", err)
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// disableDad disables DAD on the iface when assigning IPv6 addrs.
func disableDad(iface string) error {
	// DAD operation and mode on a given interface will be selected according to
	// the maximum value of conf/{all,interface}/accept_dad. So we set it to 0 on
	// both `iface` and `all`.
	for _, name := range []string{iface, "all"} {
		path := fmt.Sprintf("/proc/sys/net/ipv6/conf/%s/accept_dad", name)
		if err := os.WriteFile(path, []byte("0"), 0); err != nil {
			return err
		}
	}
	return nil
}

// netNS is a network namespace.
type netNS int

const (
	currentNetNS netNS = -1
)

// newNetNS creates a new network namespace.
func newNetNS() (netNS, error) {
	ns := currentNetNS
	err := withSavedNetNS(func() error {
		// Create the namespace via unshare(2).
		if err := unix.Unshare(unix.CLONE_NEWNET); err != nil {
			return err
		}
		// Return the created namespace.
		fd, err := openNetNSFD()
		if err != nil {
			return err
		}
		ns = netNS(fd)
		return nil
	})
	return ns, err
}

// Do calls the function in the given network namespace.
func (ns netNS) Do(f func() error) error {
	if ns == currentNetNS {
		// Simply call the function if we are already in the namespace.
		return f()
	}
	return withSavedNetNS(func() error {
		// Switch to the target namespace.
		if err := unix.Setns(int(ns), unix.CLONE_NEWNET); err != nil {
			return err
		}
		return f()
	})
}

// linkType describes if the link is for ctrl or test.
type linkType string

const (
	testLink linkType = "test"
	ctrlLink linkType = "ctrl"
)

// ipv4 creates an IPv4 address for the given network and host number.
func (l linkType) ipv4(network uint8, host uint8) *netlink.Addr {
	const (
		testNetworkNumber uint8 = 172
		ctrlNetworkNumber uint8 = 192
	)
	var leadingByte uint8
	switch l {
	case testLink:
		leadingByte = testNetworkNumber
	case ctrlLink:
		leadingByte = ctrlNetworkNumber
	default:
		panic(fmt.Sprintf("unknown link type: %s", l))
	}
	addr, err := netlink.ParseAddr(fmt.Sprintf("%d.0.%d.%d/24", leadingByte, network, host))
	if err != nil {
		panic(fmt.Sprintf("failed to parse ip net: %s", err))
	}
	return addr
}

// side describes which side of the link (tb/dut).
type side string

const (
	dutSide side = "dut"
	tbSide  side = "tb"
)

func (s side) ifaceName(typ linkType, id int) string {
	return fmt.Sprintf("%s-%d-%s", s, id, typ)
}

// withSavedNetNS saves the current namespace and restores it after calling f.
func withSavedNetNS(f func() error) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	// Save the current namespace.
	saved, err := openNetNSFD()
	if err != nil {
		return err
	}
	defer func() {
		// Resotre the namespace when we return from f.
		if err := unix.Setns(saved, unix.CLONE_NEWNET); err != nil {
			panic(fmt.Sprintf("setns(%d, CLONE_NEWNET) = %s", saved, err))
		}
		if err := unix.Close(saved); err != nil {
			panic(fmt.Sprintf("close(%d) = %s", saved, err))
		}
	}()
	return f()
}

func openNetNSFD() (int, error) {
	nsPath := fmt.Sprintf("/proc/self/task/%d/ns/net", unix.Gettid())
	return unix.Open(nsPath, unix.O_RDONLY|unix.O_CLOEXEC, 0)
}

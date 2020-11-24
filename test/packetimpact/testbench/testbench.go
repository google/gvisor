// Copyright 2020 The gVisor Authors.
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

// Package testbench has utilities to send and receive packets, and also command
// the DUT to run POSIX functions. It is the packetimpact test API.
package testbench

import (
	"flag"
	"fmt"
	"math/rand"
	"net"
	"os/exec"
	"testing"
	"time"

	"gvisor.dev/gvisor/test/packetimpact/netdevs"
)

var (
	// Native indicates that the test is being run natively.
	Native = false
	// RPCKeepalive is the gRPC keepalive.
	RPCKeepalive = 10 * time.Second
	// RPCTimeout is the gRPC timeout.
	RPCTimeout = 100 * time.Millisecond

	// dutTestNets is the pool among which the testbench can choose a DUT to work
	// with.
	dutTestNets chan *DUTTestNet

	// TODO(zeling): Remove the following variables once the test runner side is
	// ready.
	localDevice       = ""
	remoteDevice      = ""
	localIPv4         = ""
	remoteIPv4        = ""
	ipv4PrefixLength  = 0
	localIPv6         = ""
	remoteIPv6        = ""
	localInterfaceID  uint32
	remoteInterfaceID uint64
	localMAC          = ""
	remoteMAC         = ""
	posixServerIP     = ""
	posixServerPort   = 40000
)

// DUTTestNet describes the test network setup on dut and how the testbench
// should connect with an existing DUT.
type DUTTestNet struct {
	// LocalMAC is the local MAC address on the test network.
	LocalMAC net.HardwareAddr
	// RemoteMAC is the DUT's MAC address on the test network.
	RemoteMAC net.HardwareAddr
	// LocalIPv4 is the local IPv4 address on the test network.
	LocalIPv4 net.IP
	// RemoteIPv4 is the DUT's IPv4 address on the test network.
	RemoteIPv4 net.IP
	// IPv4PrefixLength is the network prefix length of the IPv4 test network.
	IPv4PrefixLength int
	// LocalIPv6 is the local IPv6 address on the test network.
	LocalIPv6 net.IP
	// RemoteIPv6 is the DUT's IPv6 address on the test network.
	RemoteIPv6 net.IP
	// LocalDevID is the ID of the local interface on the test network.
	LocalDevID uint32
	// RemoteDevID is the ID of the remote interface on the test network.
	RemoteDevID uint32
	// LocalDevName is the device that testbench uses to inject traffic.
	LocalDevName string
	// RemoteDevName is the device name on the DUT, individual tests can
	// use the name to construct tests.
	RemoteDevName string

	// The following two fields on actually on the control network instead
	// of the test network, including them for convenience.

	// POSIXServerIP is the POSIX server's IP address on the control network.
	POSIXServerIP net.IP
	// POSIXServerPort is the UDP port the POSIX server is bound to on the
	// control network.
	POSIXServerPort uint16
}

// registerFlags defines flags and associates them with the package-level
// exported variables above. It should be called by tests in their init
// functions.
func registerFlags(fs *flag.FlagSet) {
	fs.StringVar(&posixServerIP, "posix_server_ip", posixServerIP, "ip address to listen to for UDP commands")
	fs.IntVar(&posixServerPort, "posix_server_port", posixServerPort, "port to listen to for UDP commands")
	fs.StringVar(&localIPv4, "local_ipv4", localIPv4, "local IPv4 address for test packets")
	fs.StringVar(&remoteIPv4, "remote_ipv4", remoteIPv4, "remote IPv4 address for test packets")
	fs.StringVar(&remoteIPv6, "remote_ipv6", remoteIPv6, "remote IPv6 address for test packets")
	fs.StringVar(&remoteMAC, "remote_mac", remoteMAC, "remote mac address for test packets")
	fs.StringVar(&localDevice, "local_device", localDevice, "local device to inject traffic")
	fs.StringVar(&remoteDevice, "remote_device", remoteDevice, "remote device on the DUT")
	fs.Uint64Var(&remoteInterfaceID, "remote_interface_id", remoteInterfaceID, "remote interface ID for test packets")

	fs.BoolVar(&Native, "native", Native, "whether the test is running natively")
	fs.DurationVar(&RPCTimeout, "rpc_timeout", RPCTimeout, "gRPC timeout")
	fs.DurationVar(&RPCKeepalive, "rpc_keepalive", RPCKeepalive, "gRPC keepalive")
}

// Initialize initializes the testbench, it parse the flags and sets up the
// pool of test networks for testbench's later use.
func Initialize(fs *flag.FlagSet) {
	registerFlags(fs)
	flag.Parse()
	if err := genPseudoFlags(); err != nil {
		panic(err)
	}
	var dut DUTTestNet
	var err error
	dut.LocalMAC, err = net.ParseMAC(localMAC)
	if err != nil {
		panic(err)
	}
	dut.RemoteMAC, err = net.ParseMAC(remoteMAC)
	if err != nil {
		panic(err)
	}
	dut.LocalIPv4 = net.ParseIP(localIPv4).To4()
	dut.LocalIPv6 = net.ParseIP(localIPv6).To16()
	dut.RemoteIPv4 = net.ParseIP(remoteIPv4).To4()
	dut.RemoteIPv6 = net.ParseIP(remoteIPv6).To16()
	dut.LocalDevID = uint32(localInterfaceID)
	dut.RemoteDevID = uint32(remoteInterfaceID)
	dut.LocalDevName = localDevice
	dut.RemoteDevName = remoteDevice
	dut.POSIXServerIP = net.ParseIP(posixServerIP)
	dut.POSIXServerPort = uint16(posixServerPort)
	dut.IPv4PrefixLength = ipv4PrefixLength

	dutTestNets = make(chan *DUTTestNet, 1)
	dutTestNets <- &dut
}

// genPseudoFlags populates flag-like global config based on real flags.
//
// genPseudoFlags must only be called after flag.Parse.
func genPseudoFlags() error {
	out, err := exec.Command("ip", "addr", "show").CombinedOutput()
	if err != nil {
		return fmt.Errorf("listing devices: %q: %w", string(out), err)
	}
	devs, err := netdevs.ParseDevices(string(out))
	if err != nil {
		return fmt.Errorf("parsing devices: %w", err)
	}

	_, deviceInfo, err := netdevs.FindDeviceByIP(net.ParseIP(localIPv4), devs)
	if err != nil {
		return fmt.Errorf("can't find deviceInfo: %w", err)
	}

	localMAC = deviceInfo.MAC.String()
	localIPv6 = deviceInfo.IPv6Addr.String()
	localInterfaceID = deviceInfo.ID

	if deviceInfo.IPv4Net != nil {
		ipv4PrefixLength, _ = deviceInfo.IPv4Net.Mask.Size()
	} else {
		ipv4PrefixLength, _ = net.ParseIP(localIPv4).DefaultMask().Size()
	}
	return nil
}

// GenerateRandomPayload generates a random byte slice of the specified length,
// causing a fatal test failure if it is unable to do so.
func GenerateRandomPayload(t *testing.T, n int) []byte {
	t.Helper()
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		t.Fatalf("rand.Read(buf) failed: %s", err)
	}
	return buf
}

// GetDUTTestNet gets a usable DUTTestNet, the function will block until any
// becomes available.
func GetDUTTestNet() *DUTTestNet {
	return <-dutTestNets
}

// Release releases the DUTTestNet back to the pool so that some other test
// can use.
func (n *DUTTestNet) Release() {
	dutTestNets <- n
}

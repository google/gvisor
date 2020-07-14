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
	// DUTType is the type of device under test.
	DUTType = ""
	// Device is the local device on the test network.
	Device = ""

	// LocalIPv4 is the local IPv4 address on the test network.
	LocalIPv4 = ""
	// RemoteIPv4 is the DUT's IPv4 address on the test network.
	RemoteIPv4 = ""
	// IPv4PrefixLength is the network prefix length of the IPv4 test network.
	IPv4PrefixLength = 0

	// LocalIPv6 is the local IPv6 address on the test network.
	LocalIPv6 = ""
	// RemoteIPv6 is the DUT's IPv6 address on the test network.
	RemoteIPv6 = ""

	// LocalInterfaceID is the ID of the local interface on the test network.
	LocalInterfaceID uint32
	// RemoteInterfaceID is the ID of the remote interface on the test network.
	//
	// Not using uint32 because package flag does not support uint32.
	RemoteInterfaceID uint64

	// LocalMAC is the local MAC address on the test network.
	LocalMAC = ""
	// RemoteMAC is the DUT's MAC address on the test network.
	RemoteMAC = ""

	// POSIXServerIP is the POSIX server's IP address on the control network.
	POSIXServerIP = ""
	// POSIXServerPort is the UDP port the POSIX server is bound to on the
	// control network.
	POSIXServerPort = 40000

	// RPCKeepalive is the gRPC keepalive.
	RPCKeepalive = 10 * time.Second
	// RPCTimeout is the gRPC timeout.
	RPCTimeout = 100 * time.Millisecond
)

// RegisterFlags defines flags and associates them with the package-level
// exported variables above. It should be called by tests in their init
// functions.
func RegisterFlags(fs *flag.FlagSet) {
	fs.StringVar(&POSIXServerIP, "posix_server_ip", POSIXServerIP, "ip address to listen to for UDP commands")
	fs.IntVar(&POSIXServerPort, "posix_server_port", POSIXServerPort, "port to listen to for UDP commands")
	fs.DurationVar(&RPCTimeout, "rpc_timeout", RPCTimeout, "gRPC timeout")
	fs.DurationVar(&RPCKeepalive, "rpc_keepalive", RPCKeepalive, "gRPC keepalive")
	fs.StringVar(&LocalIPv4, "local_ipv4", LocalIPv4, "local IPv4 address for test packets")
	fs.StringVar(&RemoteIPv4, "remote_ipv4", RemoteIPv4, "remote IPv4 address for test packets")
	fs.StringVar(&RemoteIPv6, "remote_ipv6", RemoteIPv6, "remote IPv6 address for test packets")
	fs.StringVar(&RemoteMAC, "remote_mac", RemoteMAC, "remote mac address for test packets")
	fs.StringVar(&Device, "device", Device, "local device for test packets")
	fs.StringVar(&DUTType, "dut_type", DUTType, "type of device under test")
	fs.Uint64Var(&RemoteInterfaceID, "remote_interface_id", RemoteInterfaceID, "remote interface ID for test packets")
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

	_, deviceInfo, err := netdevs.FindDeviceByIP(net.ParseIP(LocalIPv4), devs)
	if err != nil {
		return fmt.Errorf("can't find deviceInfo: %w", err)
	}

	LocalMAC = deviceInfo.MAC.String()
	LocalIPv6 = deviceInfo.IPv6Addr.String()
	LocalInterfaceID = deviceInfo.ID

	if deviceInfo.IPv4Net != nil {
		IPv4PrefixLength, _ = deviceInfo.IPv4Net.Mask.Size()
	} else {
		IPv4PrefixLength, _ = net.ParseIP(LocalIPv4).DefaultMask().Size()
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

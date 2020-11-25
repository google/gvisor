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
	"encoding/json"
	"flag"
	"fmt"
	"math/rand"
	"net"
	"testing"
	"time"
)

var (
	// Native indicates that the test is being run natively.
	Native = false
	// RPCKeepalive is the gRPC keepalive.
	RPCKeepalive = 10 * time.Second
	// RPCTimeout is the gRPC timeout.
	RPCTimeout = 100 * time.Millisecond

	// dutTestNetsJSON is the json string that describes all the test networks to
	// duts available to use.
	dutTestNetsJSON string
	// dutTestNets is the pool among which the testbench can choose a DUT to work
	// with.
	dutTestNets chan *DUTTestNet
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
	fs.BoolVar(&Native, "native", Native, "whether the test is running natively")
	fs.DurationVar(&RPCTimeout, "rpc_timeout", RPCTimeout, "gRPC timeout")
	fs.DurationVar(&RPCKeepalive, "rpc_keepalive", RPCKeepalive, "gRPC keepalive")
	fs.StringVar(&dutTestNetsJSON, "dut_test_nets_json", dutTestNetsJSON, "path to the dut test nets json file")
}

// Initialize initializes the testbench, it parse the flags and sets up the
// pool of test networks for testbench's later use.
func Initialize(fs *flag.FlagSet) {
	registerFlags(fs)
	flag.Parse()
	if err := loadDUTTestNets(); err != nil {
		panic(err)
	}
}

// loadDUTTestNets loads available DUT test networks from the json file, it
// must be called after flag.Parse().
func loadDUTTestNets() error {
	var parsedTestNets []DUTTestNet
	if err := json.Unmarshal([]byte(dutTestNetsJSON), &parsedTestNets); err != nil {
		return fmt.Errorf("failed to unmarshal JSON: %w", err)
	}
	if got, want := len(parsedTestNets), 1; got < want {
		return fmt.Errorf("got %d DUTs, the test requires at least %d DUTs", got, want)
	}
	// Using a buffered channel as semaphore
	dutTestNets = make(chan *DUTTestNet, len(parsedTestNets))
	for i := range parsedTestNets {
		parsedTestNets[i].LocalIPv4 = parsedTestNets[i].LocalIPv4.To4()
		parsedTestNets[i].RemoteIPv4 = parsedTestNets[i].RemoteIPv4.To4()
		dutTestNets <- &parsedTestNets[i]
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

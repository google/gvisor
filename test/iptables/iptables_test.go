// Copyright 2019 The gVisor Authors.
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

package iptables

import (
	"context"
	"fmt"
	"net"
	"reflect"
	"testing"

	"gvisor.dev/gvisor/pkg/test/dockerutil"
	"gvisor.dev/gvisor/pkg/test/testutil"
)

// singleTest runs a TestCase. Each test follows a pattern:
// - Create a container.
// - Get the container's IP.
// - Send the container our IP.
// - Start a new goroutine running the local action of the test.
// - Wait for both the container and local actions to finish.
//
// Container output is logged to $TEST_UNDECLARED_OUTPUTS_DIR if it exists, or
// to stderr.
func singleTest(t *testing.T, test TestCase) {
	if _, ok := Tests[test.Name()]; !ok {
		t.Fatalf("no test found with name %q. Has it been registered?", test.Name())
	}

	ctx := context.Background()
	d := dockerutil.MakeContainer(ctx, t)
	defer d.CleanUp(ctx)

	// Create and start the container.
	opts := dockerutil.RunOpts{
		Image:  "iptables",
		CapAdd: []string{"NET_ADMIN"},
	}
	d.CopyFiles(&opts, "/runner", "test/iptables/runner/runner")
	if err := d.Spawn(ctx, opts, "/runner/runner", "-name", test.Name()); err != nil {
		t.Fatalf("docker run failed: %v", err)
	}

	// Get the container IP.
	ip, err := d.FindIP(ctx)
	if err != nil {
		t.Fatalf("failed to get container IP: %v", err)
	}

	// Give the container our IP.
	if err := sendIP(ip); err != nil {
		t.Fatalf("failed to send IP to container: %v", err)
	}

	// Run our side of the test.
	if err := test.LocalAction(ip); err != nil {
		t.Fatalf("LocalAction failed: %v", err)
	}

	// Wait for the final statement. This structure has the side effect
	// that all container logs will appear within the individual test
	// context.
	if _, err := d.WaitForOutput(ctx, TerminalStatement, TestTimeout); err != nil {
		t.Fatalf("test failed: %v", err)
	}
}

func sendIP(ip net.IP) error {
	contAddr := net.TCPAddr{
		IP:   ip,
		Port: IPExchangePort,
	}
	var conn *net.TCPConn
	// The container may not be listening when we first connect, so retry
	// upon error.
	cb := func() error {
		c, err := net.DialTCP("tcp4", nil, &contAddr)
		conn = c
		return err
	}
	if err := testutil.Poll(cb, TestTimeout); err != nil {
		return fmt.Errorf("timed out waiting to send IP, most recent error: %v", err)
	}
	if _, err := conn.Write([]byte{0}); err != nil {
		return fmt.Errorf("error writing to container: %v", err)
	}
	return nil
}

func TestFilterInputDropUDP(t *testing.T) {
	singleTest(t, FilterInputDropUDP{})
}

func TestFilterInputDropUDPPort(t *testing.T) {
	singleTest(t, FilterInputDropUDPPort{})
}

func TestFilterInputDropDifferentUDPPort(t *testing.T) {
	singleTest(t, FilterInputDropDifferentUDPPort{})
}

func TestFilterInputDropAll(t *testing.T) {
	singleTest(t, FilterInputDropAll{})
}

func TestFilterInputDropOnlyUDP(t *testing.T) {
	singleTest(t, FilterInputDropOnlyUDP{})
}

func TestFilterInputDropTCPDestPort(t *testing.T) {
	singleTest(t, FilterInputDropTCPDestPort{})
}

func TestFilterInputDropTCPSrcPort(t *testing.T) {
	singleTest(t, FilterInputDropTCPSrcPort{})
}

func TestFilterInputCreateUserChain(t *testing.T) {
	singleTest(t, FilterInputCreateUserChain{})
}

func TestFilterInputDefaultPolicyAccept(t *testing.T) {
	singleTest(t, FilterInputDefaultPolicyAccept{})
}

func TestFilterInputDefaultPolicyDrop(t *testing.T) {
	singleTest(t, FilterInputDefaultPolicyDrop{})
}

func TestFilterInputReturnUnderflow(t *testing.T) {
	singleTest(t, FilterInputReturnUnderflow{})
}

func TestFilterOutputDropTCPDestPort(t *testing.T) {
	singleTest(t, FilterOutputDropTCPDestPort{})
}

func TestFilterOutputDropTCPSrcPort(t *testing.T) {
	singleTest(t, FilterOutputDropTCPSrcPort{})
}

func TestFilterOutputAcceptTCPOwner(t *testing.T) {
	singleTest(t, FilterOutputAcceptTCPOwner{})
}

func TestFilterOutputDropTCPOwner(t *testing.T) {
	singleTest(t, FilterOutputDropTCPOwner{})
}

func TestFilterOutputAcceptUDPOwner(t *testing.T) {
	singleTest(t, FilterOutputAcceptUDPOwner{})
}

func TestFilterOutputDropUDPOwner(t *testing.T) {
	singleTest(t, FilterOutputDropUDPOwner{})
}

func TestFilterOutputOwnerFail(t *testing.T) {
	singleTest(t, FilterOutputOwnerFail{})
}

func TestFilterOutputAcceptGIDOwner(t *testing.T) {
	singleTest(t, FilterOutputAcceptGIDOwner{})
}

func TestFilterOutputDropGIDOwner(t *testing.T) {
	singleTest(t, FilterOutputDropGIDOwner{})
}

func TestFilterOutputInvertGIDOwner(t *testing.T) {
	singleTest(t, FilterOutputInvertGIDOwner{})
}

func TestFilterOutputInvertUIDOwner(t *testing.T) {
	singleTest(t, FilterOutputInvertUIDOwner{})
}

func TestFilterOutputInvertUIDAndGIDOwner(t *testing.T) {
	singleTest(t, FilterOutputInvertUIDAndGIDOwner{})
}

func TestFilterOutputInterfaceAccept(t *testing.T) {
	singleTest(t, FilterOutputInterfaceAccept{})
}

func TestFilterOutputInterfaceDrop(t *testing.T) {
	singleTest(t, FilterOutputInterfaceDrop{})
}

func TestFilterOutputInterface(t *testing.T) {
	singleTest(t, FilterOutputInterface{})
}

func TestFilterOutputInterfaceBeginsWith(t *testing.T) {
	singleTest(t, FilterOutputInterfaceBeginsWith{})
}

func TestFilterOutputInterfaceInvertDrop(t *testing.T) {
	singleTest(t, FilterOutputInterfaceInvertDrop{})
}

func TestFilterOutputInterfaceInvertAccept(t *testing.T) {
	singleTest(t, FilterOutputInterfaceInvertAccept{})
}

func TestJumpSerialize(t *testing.T) {
	singleTest(t, FilterInputSerializeJump{})
}

func TestJumpBasic(t *testing.T) {
	singleTest(t, FilterInputJumpBasic{})
}

func TestJumpReturn(t *testing.T) {
	singleTest(t, FilterInputJumpReturn{})
}

func TestJumpReturnDrop(t *testing.T) {
	singleTest(t, FilterInputJumpReturnDrop{})
}

func TestJumpBuiltin(t *testing.T) {
	singleTest(t, FilterInputJumpBuiltin{})
}

func TestJumpTwice(t *testing.T) {
	singleTest(t, FilterInputJumpTwice{})
}

func TestInputDestination(t *testing.T) {
	singleTest(t, FilterInputDestination{})
}

func TestInputInvertDestination(t *testing.T) {
	singleTest(t, FilterInputInvertDestination{})
}

func TestOutputDestination(t *testing.T) {
	singleTest(t, FilterOutputDestination{})
}

func TestOutputInvertDestination(t *testing.T) {
	singleTest(t, FilterOutputInvertDestination{})
}

func TestNATPreRedirectUDPPort(t *testing.T) {
	singleTest(t, NATPreRedirectUDPPort{})
}

func TestNATPreRedirectTCPPort(t *testing.T) {
	singleTest(t, NATPreRedirectTCPPort{})
}

func TestNATOutRedirectUDPPort(t *testing.T) {
	singleTest(t, NATOutRedirectUDPPort{})
}

func TestNATOutRedirectTCPPort(t *testing.T) {
	singleTest(t, NATOutRedirectTCPPort{})
}

func TestNATDropUDP(t *testing.T) {
	singleTest(t, NATDropUDP{})
}

func TestNATAcceptAll(t *testing.T) {
	singleTest(t, NATAcceptAll{})
}

func TestNATOutRedirectIP(t *testing.T) {
	singleTest(t, NATOutRedirectIP{})
}

func TestNATOutDontRedirectIP(t *testing.T) {
	singleTest(t, NATOutDontRedirectIP{})
}

func TestNATOutRedirectInvert(t *testing.T) {
	singleTest(t, NATOutRedirectInvert{})
}

func TestNATPreRedirectIP(t *testing.T) {
	singleTest(t, NATPreRedirectIP{})
}

func TestNATPreDontRedirectIP(t *testing.T) {
	singleTest(t, NATPreDontRedirectIP{})
}

func TestNATPreRedirectInvert(t *testing.T) {
	singleTest(t, NATPreRedirectInvert{})
}

func TestNATRedirectRequiresProtocol(t *testing.T) {
	singleTest(t, NATRedirectRequiresProtocol{})
}

func TestNATLoopbackSkipsPrerouting(t *testing.T) {
	singleTest(t, NATLoopbackSkipsPrerouting{})
}

func TestInputSource(t *testing.T) {
	singleTest(t, FilterInputSource{})
}

func TestInputInvertSource(t *testing.T) {
	singleTest(t, FilterInputInvertSource{})
}

func TestFilterAddrs(t *testing.T) {
	tcs := []struct {
		ipv6  bool
		addrs []string
		want  []string
	}{
		{
			ipv6:  false,
			addrs: []string{"192.168.0.1", "192.168.0.2/24", "::1", "::2/128"},
			want:  []string{"192.168.0.1", "192.168.0.2"},
		},
		{
			ipv6:  true,
			addrs: []string{"192.168.0.1", "192.168.0.2/24", "::1", "::2/128"},
			want:  []string{"::1", "::2"},
		},
	}

	for _, tc := range tcs {
		if got := filterAddrs(tc.addrs, tc.ipv6); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%v with IPv6 %t: got %v, but wanted %v", tc.addrs, tc.ipv6, got, tc.want)
		}
	}
}

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
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"time"

	"gvisor.dev/gvisor/pkg/test/testutil"
)

const iptablesBinary = "iptables"
const localIP = "127.0.0.1"

// filterTable calls `iptables -t filter` with the given args.
func filterTable(args ...string) error {
	return tableCmd("filter", args)
}

// natTable calls `iptables -t nat` with the given args.
func natTable(args ...string) error {
	return tableCmd("nat", args)
}

func tableCmd(table string, args []string) error {
	args = append([]string{"-t", table}, args...)
	cmd := exec.Command(iptablesBinary, args...)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("error running iptables with args %v\nerror: %v\noutput: %s", args, err, string(out))
	}
	return nil
}

// filterTableRules is like filterTable, but runs multiple iptables commands.
func filterTableRules(argsList [][]string) error {
	return tableRules("filter", argsList)
}

// natTableRules is like natTable, but runs multiple iptables commands.
func natTableRules(argsList [][]string) error {
	return tableRules("nat", argsList)
}

func tableRules(table string, argsList [][]string) error {
	for _, args := range argsList {
		if err := tableCmd(table, args); err != nil {
			return err
		}
	}
	return nil
}

// listenUDP listens on a UDP port and returns the value of net.Conn.Read() for
// the first read on that port.
func listenUDP(port int, timeout time.Duration) error {
	localAddr := net.UDPAddr{
		Port: port,
	}
	conn, err := net.ListenUDP(network, &localAddr)
	if err != nil {
		return err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))
	_, err = conn.Read([]byte{0})
	return err
}

// sendUDPLoop sends 1 byte UDP packets repeatedly to the IP and port specified
// over a duration.
func sendUDPLoop(ip net.IP, port int, duration time.Duration) error {
	// Send packets for a few seconds.
	remote := net.UDPAddr{
		IP:   ip,
		Port: port,
	}
	conn, err := net.DialUDP(network, nil, &remote)
	if err != nil {
		return err
	}
	defer conn.Close()

	to := time.After(duration)
	for timedOut := false; !timedOut; {
		// This may return an error (connection refused) if the remote
		// hasn't started listening yet or they're dropping our
		// packets. So we ignore Write errors and depend on the remote
		// to report a failure if it doesn't get a packet it needs.
		conn.Write([]byte{0})
		select {
		case <-to:
			timedOut = true
		default:
			time.Sleep(200 * time.Millisecond)
		}
	}

	return nil
}

// listenTCP listens for connections on a TCP port.
func listenTCP(port int, timeout time.Duration) error {
	localAddr := net.TCPAddr{
		Port: port,
	}

	// Starts listening on port.
	lConn, err := net.ListenTCP("tcp4", &localAddr)
	if err != nil {
		return err
	}
	defer lConn.Close()

	// Accept connections on port.
	lConn.SetDeadline(time.Now().Add(timeout))
	conn, err := lConn.AcceptTCP()
	if err != nil {
		return err
	}
	conn.Close()
	return nil
}

// connectTCP connects to the given IP and port from an ephemeral local address.
func connectTCP(ip net.IP, port int, timeout time.Duration) error {
	contAddr := net.TCPAddr{
		IP:   ip,
		Port: port,
	}
	// The container may not be listening when we first connect, so retry
	// upon error.
	callback := func() error {
		conn, err := net.DialTimeout("tcp", contAddr.String(), timeout)
		if conn != nil {
			conn.Close()
		}
		return err
	}
	if err := testutil.Poll(callback, timeout); err != nil {
		return fmt.Errorf("timed out waiting to connect IP on port %v, most recent error: %v", port, err)
	}

	return nil
}

// localAddrs returns a list of local network interface addresses. When ipv6 is
// true, only IPv6 addresses are returned. Otherwise only IPv4 addresses are
// returned.
func localAddrs(ipv6 bool) ([]string, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}
	addrStrs := make([]string, 0, len(addrs))
	for _, addr := range addrs {
		addrStrs = append(addrStrs, addr.String())
	}
	return filterAddrs(addrStrs, ipv6), nil
}

func filterAddrs(addrs []string, ipv6 bool) []string {
	addrStrs := make([]string, 0, len(addrs))
	for _, addr := range addrs {
		// Add only IPv4 or only IPv6 addresses.
		parts := strings.Split(addr, "/")
		if isIPv6 := net.ParseIP(parts[0]).To4() == nil; isIPv6 == ipv6 {
			addrStrs = append(addrStrs, parts[0])
		}
	}
	return addrStrs
}

// getInterfaceName returns the name of the interface other than loopback.
func getInterfaceName() (string, bool) {
	iface, ok := getNonLoopbackInterface()
	if !ok {
		return "", false
	}
	return iface.Name, true
}

func getInterfaceAddr() ([]byte, error) {
	iface, ok := getNonLoopbackInterface()
	if !ok {
		return []byte{}, errors.New("no non-loopback interface found")
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return []byte{}, err
	}
	if len(addrs) != 1 {
		return []byte{}, fmt.Errorf("wanted exactly 1 non-loopback interface, but found %d", len(addrs))
	}
	// Get the address as a string, cut off the mask, and make sure it's a
	// 4-byte slice.
	return net.ParseIP(strings.Split(addrs[0].String(), "/")[0]).To4(), nil
}

func getNonLoopbackInterface() (net.Interface, bool) {
	if interfaces, err := net.Interfaces(); err == nil {
		for _, intf := range interfaces {
			if intf.Name != "lo" {
				return intf, true
			}
		}
	}
	return net.Interface{}, false
}

func htons(x uint16) uint16 {
	buf := make([]byte, 2)
	binary.BigEndian.PutUint16(buf, x)
	return binary.LittleEndian.Uint16(buf)
}

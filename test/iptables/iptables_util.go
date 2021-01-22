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
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"time"

	"gvisor.dev/gvisor/pkg/test/testutil"
)

// filterTable calls `ip{6}tables -t filter` with the given args.
func filterTable(ipv6 bool, args ...string) error {
	return tableCmd(ipv6, "filter", args)
}

// natTable calls `ip{6}tables -t nat` with the given args.
func natTable(ipv6 bool, args ...string) error {
	return tableCmd(ipv6, "nat", args)
}

func tableCmd(ipv6 bool, table string, args []string) error {
	args = append([]string{"-t", table}, args...)
	binary := "iptables"
	if ipv6 {
		binary = "ip6tables"
	}
	cmd := exec.Command(binary, args...)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("error running iptables with args %v\nerror: %v\noutput: %s", args, err, string(out))
	}
	return nil
}

// filterTableRules is like filterTable, but runs multiple iptables commands.
func filterTableRules(ipv6 bool, argsList [][]string) error {
	return tableRules(ipv6, "filter", argsList)
}

// natTableRules is like natTable, but runs multiple iptables commands.
func natTableRules(ipv6 bool, argsList [][]string) error {
	return tableRules(ipv6, "nat", argsList)
}

func tableRules(ipv6 bool, table string, argsList [][]string) error {
	for _, args := range argsList {
		if err := tableCmd(ipv6, table, args); err != nil {
			return err
		}
	}
	return nil
}

// listenUDP listens on a UDP port and returns the value of net.Conn.Read() for
// the first read on that port.
func listenUDP(ctx context.Context, port int) error {
	localAddr := net.UDPAddr{
		Port: port,
	}
	conn, err := net.ListenUDP("udp", &localAddr)
	if err != nil {
		return err
	}
	defer conn.Close()

	ch := make(chan error)
	go func() {
		_, err = conn.Read([]byte{0})
		ch <- err
	}()

	select {
	case err := <-ch:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// sendUDPLoop sends 1 byte UDP packets repeatedly to the IP and port specified
// over a duration.
func sendUDPLoop(ctx context.Context, ip net.IP, port int) error {
	remote := net.UDPAddr{
		IP:   ip,
		Port: port,
	}
	conn, err := net.DialUDP("udp", nil, &remote)
	if err != nil {
		return err
	}
	defer conn.Close()

	for {
		// This may return an error (connection refused) if the remote
		// hasn't started listening yet or they're dropping our
		// packets. So we ignore Write errors and depend on the remote
		// to report a failure if it doesn't get a packet it needs.
		conn.Write([]byte{0})
		select {
		case <-ctx.Done():
			// Being cancelled or timing out isn't an error, as we
			// cannot tell with UDP whether we succeeded.
			return nil
		// Continue looping.
		case <-time.After(200 * time.Millisecond):
		}
	}
}

// listenTCP listens for connections on a TCP port.
func listenTCP(ctx context.Context, port int) error {
	localAddr := net.TCPAddr{
		Port: port,
	}

	// Starts listening on port.
	lConn, err := net.ListenTCP("tcp", &localAddr)
	if err != nil {
		return err
	}
	defer lConn.Close()

	// Accept connections on port.
	ch := make(chan error)
	go func() {
		conn, err := lConn.AcceptTCP()
		ch <- err
		conn.Close()
	}()

	select {
	case err := <-ch:
		return err
	case <-ctx.Done():
		return fmt.Errorf("timed out waiting for a connection at %#v: %w", localAddr, ctx.Err())
	}
}

// connectTCP connects to the given IP and port from an ephemeral local address.
func connectTCP(ctx context.Context, ip net.IP, port int) error {
	contAddr := net.TCPAddr{
		IP:   ip,
		Port: port,
	}
	// The container may not be listening when we first connect, so retry
	// upon error.
	callback := func() error {
		var d net.Dialer
		conn, err := d.DialContext(ctx, "tcp", contAddr.String())
		if conn != nil {
			conn.Close()
		}
		return err
	}
	if err := testutil.PollContext(ctx, callback); err != nil {
		return fmt.Errorf("timed out waiting to connect IP on port %v, most recent error: %w", port, err)
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
		// Add only IPv4 or only IPv6 addresses.
		parts := strings.Split(addr.String(), "/")
		if len(parts) != 2 {
			return nil, fmt.Errorf("bad interface address: %q", addr.String())
		}
		if isIPv6 := net.ParseIP(parts[0]).To4() == nil; isIPv6 == ipv6 {
			addrStrs = append(addrStrs, addr.String())
		}
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

func getInterfaceAddrs(ipv6 bool) ([]net.IP, error) {
	iface, ok := getNonLoopbackInterface()
	if !ok {
		return nil, errors.New("no non-loopback interface found")
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, err
	}

	// Get only IPv4 or IPv6 addresses.
	ips := make([]net.IP, 0, len(addrs))
	for _, addr := range addrs {
		parts := strings.Split(addr.String(), "/")
		var ip net.IP
		// To16() returns IPv4 addresses as IPv4-mapped IPv6 addresses.
		// So we check whether To4() returns nil to test whether the
		// address is v4 or v6.
		if v4 := net.ParseIP(parts[0]).To4(); ipv6 && v4 == nil {
			ip = net.ParseIP(parts[0]).To16()
		} else {
			ip = v4
		}
		if ip != nil {
			ips = append(ips, ip)
		}
	}
	return ips, nil
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

func localIP(ipv6 bool) string {
	if ipv6 {
		return "::1"
	}
	return "127.0.0.1"
}

func nowhereIP(ipv6 bool) string {
	if ipv6 {
		return "2001:db8::1"
	}
	return "192.0.2.1"
}

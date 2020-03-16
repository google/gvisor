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
	"fmt"
	"net"
	"os/exec"
	"time"

	"gvisor.dev/gvisor/runsc/testutil"
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
		conn, err := net.DialTCP("tcp4", nil, &contAddr)
		if conn != nil {
			conn.Close()
		}
		return err
	}
	if err := testutil.Poll(callback, timeout); err != nil {
		return fmt.Errorf("timed out waiting to connect IP, most recent error: %v", err)
	}

	return nil
}

// localAddrs returns a list of local network interface addresses.
func localAddrs() ([]string, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}
	addrStrs := make([]string, 0, len(addrs))
	for _, addr := range addrs {
		addrStrs = append(addrStrs, addr.String())
	}
	return addrStrs, nil
}

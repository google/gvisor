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

//go:build linux
// +build linux

// Package linux provides utilities specific to bringing up linux DUTs.
package linux

import (
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/test/packetimpact/dut"
	netdevs "gvisor.dev/gvisor/test/packetimpact/netdevs/netlink"
	"gvisor.dev/gvisor/test/packetimpact/testbench"
)

const (
	// PosixServerPath is the path to the posix_server.
	PosixServerPath = "test/packetimpact/dut/posix_server"
)

func uname() (*testbench.DUTUname, error) {
	var u unix.Utsname
	if err := unix.Uname(&u); err != nil {
		return nil, err
	}
	return &testbench.DUTUname{
		Machine:       unix.ByteSliceToString(u.Machine[:]),
		KernelName:    unix.ByteSliceToString(u.Sysname[:]),
		KernelRelease: unix.ByteSliceToString(u.Release[:]),
		KernelVersion: unix.ByteSliceToString(u.Version[:]),
		// PacketImpact identifies native Linux DUTs by GNU uname's -o value.
		OperatingSystem: "GNU/Linux",
	}, nil
}

// DUTInfo gatthers information about the linux DUT.
func DUTInfo(ifaces dut.Ifaces) (testbench.DUTInfo, error) {
	_, ctrlIPv4, _, err := netdevs.IfaceInfo(ifaces.Ctrl)
	if err != nil {
		return testbench.DUTInfo{}, err
	}
	testLink, testIPv4, testIPv6, err := netdevs.IfaceInfo(ifaces.Test)
	if err != nil {
		return testbench.DUTInfo{}, err
	}
	dutUname, err := uname()
	if err != nil {
		return testbench.DUTInfo{}, err
	}

	prefix, _ := testIPv4.Mask.Size()

	return testbench.DUTInfo{
		Net: &testbench.DUTTestNet{
			RemoteIPv6:       testIPv6.IP,
			RemoteIPv4:       testIPv4.IP.To4(),
			IPv4PrefixLength: prefix,
			RemoteDevID:      uint32(testLink.Attrs().Index),
			RemoteDevName:    ifaces.Test,
			POSIXServerIP:    ctrlIPv4.IP.To4(),
			POSIXServerPort:  dut.PosixServerPort,
			RemoteMAC:        testLink.Attrs().HardwareAddr,
		},
		Uname: dutUname,
	}, nil
}

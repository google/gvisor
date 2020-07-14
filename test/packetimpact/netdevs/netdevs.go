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

// Package netdevs contains utilities for working with network devices.
package netdevs

import (
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

// A DeviceInfo represents a network device.
type DeviceInfo struct {
	ID       uint32
	MAC      net.HardwareAddr
	IPv4Addr net.IP
	IPv4Net  *net.IPNet
	IPv6Addr net.IP
	IPv6Net  *net.IPNet
}

var (
	deviceLine = regexp.MustCompile(`^\s*(\d+): (\w+)`)
	linkLine   = regexp.MustCompile(`^\s*link/\w+ ([0-9a-fA-F:]+)`)
	inetLine   = regexp.MustCompile(`^\s*inet ([0-9./]+)`)
	inet6Line  = regexp.MustCompile(`^\s*inet6 ([0-9a-fA-Z:/]+)`)
)

// ParseDevices parses the output from `ip addr show` into a map from device
// name to information about the device.
//
// Note: if multiple IPv6 addresses are assigned to a device, the last address
// displayed by `ip addr show` will be used. This is fine for packetimpact
// because we will always only have at most one IPv6 address assigned to each
// device.
func ParseDevices(cmdOutput string) (map[string]DeviceInfo, error) {
	var currentDevice string
	var currentInfo DeviceInfo
	deviceInfos := make(map[string]DeviceInfo)
	for _, line := range strings.Split(cmdOutput, "\n") {
		if m := deviceLine.FindStringSubmatch(line); m != nil {
			if currentDevice != "" {
				deviceInfos[currentDevice] = currentInfo
			}
			id, err := strconv.ParseUint(m[1], 10, 32)
			if err != nil {
				return nil, fmt.Errorf("parsing device ID %s: %w", m[1], err)
			}
			currentInfo = DeviceInfo{ID: uint32(id)}
			currentDevice = m[2]
		} else if m := linkLine.FindStringSubmatch(line); m != nil {
			mac, err := net.ParseMAC(m[1])
			if err != nil {
				return nil, err
			}
			currentInfo.MAC = mac
		} else if m := inetLine.FindStringSubmatch(line); m != nil {
			ipv4Addr, ipv4Net, err := net.ParseCIDR(m[1])
			if err != nil {
				return nil, err
			}
			currentInfo.IPv4Addr = ipv4Addr
			currentInfo.IPv4Net = ipv4Net
		} else if m := inet6Line.FindStringSubmatch(line); m != nil {
			ipv6Addr, ipv6Net, err := net.ParseCIDR(m[1])
			if err != nil {
				return nil, err
			}
			currentInfo.IPv6Addr = ipv6Addr
			currentInfo.IPv6Net = ipv6Net
		}
	}
	if currentDevice != "" {
		deviceInfos[currentDevice] = currentInfo
	}
	return deviceInfos, nil
}

// MACToIP converts the MAC address to an IPv6 link local address as described
// in RFC 4291 page 20: https://tools.ietf.org/html/rfc4291#page-20
func MACToIP(mac net.HardwareAddr) net.IP {
	addr := make([]byte, header.IPv6AddressSize)
	addr[0] = 0xfe
	addr[1] = 0x80
	header.EthernetAdddressToModifiedEUI64IntoBuf(tcpip.LinkAddress(mac), addr[8:])
	return net.IP(addr)
}

// FindDeviceByIP finds a DeviceInfo and device name from an IP address in the
// output of ParseDevices.
func FindDeviceByIP(ip net.IP, devices map[string]DeviceInfo) (string, DeviceInfo, error) {
	for dev, info := range devices {
		if info.IPv4Addr.Equal(ip) {
			return dev, info, nil
		}
	}
	return "", DeviceInfo{}, fmt.Errorf("can't find %s on any interface", ip)
}

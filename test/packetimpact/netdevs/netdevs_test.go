// Copyright 2020 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package netdevs

import (
	"fmt"
	"net"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func mustParseMAC(s string) net.HardwareAddr {
	mac, err := net.ParseMAC(s)
	if err != nil {
		panic(fmt.Sprintf("failed to parse test MAC %q: %s", s, err))
	}
	return mac
}

func TestParseDevices(t *testing.T) {
	for _, v := range []struct {
		desc      string
		cmdOutput string
		want      map[string]DeviceInfo
	}{
		{
			desc: "v4 and v6",
			cmdOutput: `
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
  link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
  inet 127.0.0.1/8 scope host lo
    valid_lft forever preferred_lft forever
  inet6 ::1/128 scope host
    valid_lft forever preferred_lft forever
2613: eth0@if2614: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default
  link/ether 02:42:c0:a8:09:02 brd ff:ff:ff:ff:ff:ff link-netnsid 0
  inet 192.168.9.2/24 brd 192.168.9.255 scope global eth0
    valid_lft forever preferred_lft forever
  inet6 fe80::42:c0ff:fea8:902/64 scope link tentative
    valid_lft forever preferred_lft forever
2615: eth2@if2616: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default
  link/ether 02:42:df:f5:e1:0a brd ff:ff:ff:ff:ff:ff link-netnsid 0
  inet 223.245.225.10/24 brd 223.245.225.255 scope global eth2
    valid_lft forever preferred_lft forever
  inet6 fe80::42:dfff:fef5:e10a/64 scope link tentative
    valid_lft forever preferred_lft forever
2617: eth1@if2618: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default
  link/ether 02:42:da:33:13:0a brd ff:ff:ff:ff:ff:ff link-netnsid 0
  inet 218.51.19.10/24 brd 218.51.19.255 scope global eth1
    valid_lft forever preferred_lft forever
  inet6 fe80::42:daff:fe33:130a/64 scope link tentative
    valid_lft forever preferred_lft forever`,
			want: map[string]DeviceInfo{
				"lo": {
					ID:       1,
					MAC:      mustParseMAC("00:00:00:00:00:00"),
					IPv4Addr: net.IPv4(127, 0, 0, 1),
					IPv4Net: &net.IPNet{
						IP:   net.IPv4(127, 0, 0, 0),
						Mask: net.CIDRMask(8, 32),
					},
					IPv6Addr: net.ParseIP("::1"),
					IPv6Net: &net.IPNet{
						IP:   net.ParseIP("::1"),
						Mask: net.CIDRMask(128, 128),
					},
				},
				"eth0": {
					ID:       2613,
					MAC:      mustParseMAC("02:42:c0:a8:09:02"),
					IPv4Addr: net.IPv4(192, 168, 9, 2),
					IPv4Net: &net.IPNet{
						IP:   net.IPv4(192, 168, 9, 0),
						Mask: net.CIDRMask(24, 32),
					},
					IPv6Addr: net.ParseIP("fe80::42:c0ff:fea8:902"),
					IPv6Net: &net.IPNet{
						IP:   net.ParseIP("fe80::"),
						Mask: net.CIDRMask(64, 128),
					},
				},
				"eth1": {
					ID:       2617,
					MAC:      mustParseMAC("02:42:da:33:13:0a"),
					IPv4Addr: net.IPv4(218, 51, 19, 10),
					IPv4Net: &net.IPNet{
						IP:   net.IPv4(218, 51, 19, 0),
						Mask: net.CIDRMask(24, 32),
					},
					IPv6Addr: net.ParseIP("fe80::42:daff:fe33:130a"),
					IPv6Net: &net.IPNet{
						IP:   net.ParseIP("fe80::"),
						Mask: net.CIDRMask(64, 128),
					},
				},
				"eth2": {
					ID:       2615,
					MAC:      mustParseMAC("02:42:df:f5:e1:0a"),
					IPv4Addr: net.IPv4(223, 245, 225, 10),
					IPv4Net: &net.IPNet{
						IP:   net.IPv4(223, 245, 225, 0),
						Mask: net.CIDRMask(24, 32),
					},
					IPv6Addr: net.ParseIP("fe80::42:dfff:fef5:e10a"),
					IPv6Net: &net.IPNet{
						IP:   net.ParseIP("fe80::"),
						Mask: net.CIDRMask(64, 128),
					},
				},
			},
		},
		{
			desc: "v4 only",
			cmdOutput: `
2613: eth0@if2614: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default
  link/ether 02:42:c0:a8:09:02 brd ff:ff:ff:ff:ff:ff link-netnsid 0
  inet 192.168.9.2/24 brd 192.168.9.255 scope global eth0
    valid_lft forever preferred_lft forever`,
			want: map[string]DeviceInfo{
				"eth0": {
					ID:       2613,
					MAC:      mustParseMAC("02:42:c0:a8:09:02"),
					IPv4Addr: net.IPv4(192, 168, 9, 2),
					IPv4Net: &net.IPNet{
						IP:   net.IPv4(192, 168, 9, 0),
						Mask: net.CIDRMask(24, 32),
					},
				},
			},
		},
		{
			desc: "v6 only",
			cmdOutput: `
2615: eth2@if2616: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default
  link/ether 02:42:df:f5:e1:0a brd ff:ff:ff:ff:ff:ff link-netnsid 0
  inet6 fe80::42:dfff:fef5:e10a/64 scope link tentative
    valid_lft forever preferred_lft forever`,
			want: map[string]DeviceInfo{
				"eth2": {
					ID:       2615,
					MAC:      mustParseMAC("02:42:df:f5:e1:0a"),
					IPv6Addr: net.ParseIP("fe80::42:dfff:fef5:e10a"),
					IPv6Net: &net.IPNet{
						IP:   net.ParseIP("fe80::"),
						Mask: net.CIDRMask(64, 128),
					},
				},
			},
		},
	} {
		t.Run(v.desc, func(t *testing.T) {
			got, err := ParseDevices(v.cmdOutput)
			if err != nil {
				t.Errorf("ParseDevices(\n%s\n) got unexpected error: %s", v.cmdOutput, err)
			}
			if diff := cmp.Diff(v.want, got); diff != "" {
				t.Errorf("ParseDevices(\n%s\n) got output diff (-want, +got):\n%s", v.cmdOutput, diff)
			}
		})
	}
}

func TestParseDevicesErrors(t *testing.T) {
	for _, v := range []struct {
		desc      string
		cmdOutput string
	}{
		{
			desc: "invalid MAC addr",
			cmdOutput: `
2617: eth1@if2618: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default
	link/ether 02:42:da:33:13:0a:ffffffff brd ff:ff:ff:ff:ff:ff link-netnsid 0
  inet 218.51.19.10/24 brd 218.51.19.255 scope global eth1
    valid_lft forever preferred_lft forever
  inet6 fe80::42:daff:fe33:130a/64 scope link tentative
    valid_lft forever preferred_lft forever`,
		},
		{
			desc: "invalid v4 addr",
			cmdOutput: `
2617: eth1@if2618: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default
  link/ether 02:42:da:33:13:0a brd ff:ff:ff:ff:ff:ff link-netnsid 0
  inet 1234.4321.424242.0/24 brd 218.51.19.255 scope global eth1
    valid_lft forever preferred_lft forever
  inet6 fe80::42:daff:fe33:130a/64 scope link tentative
    valid_lft forever preferred_lft forever`,
		},
		{
			desc: "invalid v6 addr",
			cmdOutput: `
2617: eth1@if2618: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default
  link/ether 02:42:da:33:13:0a brd ff:ff:ff:ff:ff:ff link-netnsid 0
  inet 218.51.19.10/24 brd 218.51.19.255 scope global eth1
    valid_lft forever preferred_lft forever
		inet6 fe80:ffffffff::42:daff:fe33:130a/64 scope link tentative
    valid_lft forever preferred_lft forever`,
		},
		{
			desc: "invalid CIDR missing prefixlen",
			cmdOutput: `
2617: eth1@if2618: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default
  link/ether 02:42:da:33:13:0a brd ff:ff:ff:ff:ff:ff link-netnsid 0
  inet 218.51.19.10 brd 218.51.19.255 scope global eth1
    valid_lft forever preferred_lft forever
  inet6 fe80::42:daff:fe33:130a scope link tentative
    valid_lft forever preferred_lft forever`,
		},
	} {
		t.Run(v.desc, func(t *testing.T) {
			if _, err := ParseDevices(v.cmdOutput); err == nil {
				t.Errorf("ParseDevices(\n%s\n) succeeded unexpectedly, want error", v.cmdOutput)
			}
		})
	}
}

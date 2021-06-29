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

package netstack

import (
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/tcpip/link/tun"
)

// TUNFlagsToLinux converts a tun.Flags to Linux TUN flags.
func TUNFlagsToLinux(flags tun.Flags) uint16 {
	ret := uint16(linux.IFF_NOFILTER)
	if flags.TAP {
		ret |= linux.IFF_TAP
	}
	if flags.TUN {
		ret |= linux.IFF_TUN
	}
	if flags.NoPacketInfo {
		ret |= linux.IFF_NO_PI
	}
	return ret
}

// LinuxToTUNFlags converts Linux TUN flags to a tun.Flags.
func LinuxToTUNFlags(flags uint16) (tun.Flags, error) {
	// Linux adds IFF_NOFILTER (the same value as IFF_NO_PI unfortunately)
	// when there is no sk_filter. See __tun_chr_ioctl() in
	// net/drivers/tun.c.
	if flags&^uint16(linux.IFF_TUN|linux.IFF_TAP|linux.IFF_NO_PI|linux.IFF_ONE_QUEUE) != 0 {
		return tun.Flags{}, linuxerr.EINVAL
	}
	return tun.Flags{
		TUN:          flags&linux.IFF_TUN != 0,
		TAP:          flags&linux.IFF_TAP != 0,
		NoPacketInfo: flags&linux.IFF_NO_PI != 0,
	}, nil
}

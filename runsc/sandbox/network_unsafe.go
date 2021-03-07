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

package sandbox

import (
	"unsafe"

	"golang.org/x/sys/unix"
)

type ethtoolValue struct {
	cmd uint32
	val uint32
}

type ifreq struct {
	ifrName [unix.IFNAMSIZ]byte
	ifrData *ethtoolValue
}

const (
	_ETHTOOL_GGSO = 0x00000023
)

func isGSOEnabled(fd int, intf string) (bool, error) {
	val := ethtoolValue{
		cmd: _ETHTOOL_GGSO,
	}

	var name [unix.IFNAMSIZ]byte
	copy(name[:], []byte(intf))

	ifr := ifreq{
		ifrName: name,
		ifrData: &val,
	}

	if _, _, err := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), unix.SIOCETHTOOL, uintptr(unsafe.Pointer(&ifr))); err != 0 {
		return false, err
	}

	return val.val != 0, nil
}

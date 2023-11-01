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
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
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

func writeNATBlob() (*os.File, error) {
	// Open a socket to use with iptables.
	iptSock, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_ICMP)
	if err != nil {
		return nil, fmt.Errorf("failed to open socket for iptables: %v", err)
	}
	defer unix.Close(iptSock)

	// Get the iptables info.
	var NATName [linux.XT_TABLE_MAXNAMELEN]byte
	copy(NATName[:], []byte("nat\x00"))
	natInfo := linux.IPTGetinfo{Name: NATName}
	natInfoLen := int32(unsafe.Sizeof(linux.IPTGetinfo{}))
	_, _, errno := unix.Syscall6(unix.SYS_GETSOCKOPT,
		uintptr(iptSock),
		unix.SOL_IP,
		linux.IPT_SO_GET_INFO,
		uintptr(unsafe.Pointer(&natInfo)),
		uintptr(unsafe.Pointer(&natInfoLen)),
		0)
	if errno != 0 {
		return nil, fmt.Errorf("failed to call IPT_SO_GET_INFO: %v", err)
	}

	// Get the iptables entries.
	entries := linux.IPTGetEntries{Name: NATName, Size: natInfo.Size}
	entriesBufLen := uint32(unsafe.Sizeof(entries)) + natInfo.Size
	entriesBuf := make([]byte, entriesBufLen)
	entries.MarshalUnsafe(entriesBuf[:unsafe.Sizeof(entries)])
	_, _, errno = unix.Syscall6(unix.SYS_GETSOCKOPT,
		uintptr(iptSock),
		unix.SOL_IP,
		linux.IPT_SO_GET_ENTRIES,
		uintptr(unsafe.Pointer(&entriesBuf[0])),
		uintptr(unsafe.Pointer(&entriesBufLen)),
		0)
	if errno != 0 {
		return nil, fmt.Errorf("failed to call IPT_SO_GET_ENTRIES: %v", errno)
	}
	var gotEntries linux.IPTGetEntries
	gotEntries.UnmarshalUnsafe(entriesBuf[:unsafe.Sizeof(entries)])

	// Construct an IPTReplace that can be used to set rules.
	replace := linux.IPTReplace{
		Name:       NATName,
		ValidHooks: natInfo.ValidHooks,
		NumEntries: natInfo.NumEntries,
		Size:       natInfo.Size,
		HookEntry:  natInfo.HookEntry,
		Underflow:  natInfo.Underflow,
		// We don't implement counters yet.
		NumCounters: 0,
		Counters:    0,
	}

	// Marshal into a blob.
	replaceBuf := make([]byte, unsafe.Sizeof(replace)+uintptr(natInfo.Size))
	replace.MarshalUnsafe(replaceBuf[:unsafe.Sizeof(replace)])
	if n := copy(replaceBuf[unsafe.Sizeof(replace):], entriesBuf[unsafe.Sizeof(entries):]); uint32(n) != natInfo.Size {
		panic(fmt.Sprintf("failed to populate entry table: copied %d bytes, but wanted to copy %d", n, natInfo.Size))
	}

	// Write blob to a pipe.
	reader, writer, err := os.Pipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create iptables blob pipe: %v", err)
	}
	defer writer.Close()
	if n, err := writer.Write(replaceBuf); n != len(replaceBuf) || err != nil {
		return nil, fmt.Errorf("failed to write iptables blob: wrote %d bytes (%d expected) and got error: %v", n, len(replaceBuf), err)
	}
	return reader, nil
}

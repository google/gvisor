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

package hostinet

import (
	"runtime"
	"unsafe"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/sentry/inet"
)

func queryInterfaceFeatures(interfaces map[int32]inet.Interface) error {
	fd, err := queryFD()
	if err != nil {
		return err
	}
	defer unix.Close(fd)

	for idx, nic := range interfaces {
		var ifr linux.IFReq
		copy(ifr.IFName[:], nic.Name)
		var gfeatures linux.EthtoolGFeatures
		// Each feature block is sufficient to query 32 features, the linux
		// kernel today supports upto 64 features per device. Technically it
		// can support more in the future but this is sufficient for our use
		// right now.
		const (
			numFeatureBlocks = 2
			ifrDataSz        = unsafe.Sizeof(linux.EthtoolGFeatures{}) + numFeatureBlocks*unsafe.Sizeof(linux.EthtoolGetFeaturesBlock{})
		)
		featureBlocks := make([]linux.EthtoolGetFeaturesBlock, numFeatureBlocks)
		b := make([]byte, ifrDataSz)
		gfeatures.Cmd = uint32(linux.ETHTOOL_GFEATURES)
		gfeatures.Size = numFeatureBlocks
		gfeatures.MarshalBytes(b)
		next := b[unsafe.Sizeof(linux.EthtoolGFeatures{}):]
		for i := 0; i < numFeatureBlocks; i++ {
			featureBlocks[i].MarshalBytes(next)
			next = next[unsafe.Sizeof(linux.EthtoolGetFeaturesBlock{}):]
		}

		// Technically the next two lines are not safe as Go GC can technically move
		// b to a new location and the pointer value stored in ifr.Data could point
		// to random memory. But the reality today is that Go GC is not a moving GC
		// so this is essentially safe as of today.
		//
		// TODO(b/209014118): Use Pin API when available in Go runtime to make this
		//                    safe.
		dataPtr := unsafe.Pointer(&b[0])
		hostarch.ByteOrder.PutUint64(ifr.Data[:8], uint64(uintptr(dataPtr)))

		if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), unix.SIOCETHTOOL, uintptr(unsafe.Pointer(&ifr))); errno != 0 {
			return errno
		}

		// Unmarshall the features back.
		gfeatures.UnmarshalBytes(b)
		next = b[unsafe.Sizeof(linux.EthtoolGFeatures{}):]
		for i := 0; i < int(gfeatures.Size); i++ {
			featureBlocks[i].UnmarshalBytes(next)
			next = next[unsafe.Sizeof(linux.EthtoolGetFeaturesBlock{}):]
		}
		// Store the queried features.
		iface := interfaces[idx]
		iface.Features = make([]linux.EthtoolGetFeaturesBlock, gfeatures.Size)
		copy(iface.Features, featureBlocks)
		interfaces[idx] = iface

		// This ensures b is not garbage collected before this point to ensure that
		// the slice is not collected before the syscall returns and we copy out the
		// data.
		runtime.KeepAlive(b)
	}
	return nil
}

func queryFD() (int, error) {
	// Try both AF_INET and AF_INET6 in case only one is supported.
	var fd int
	var err error
	for _, family := range []int{unix.AF_INET6, unix.AF_INET} {
		fd, err = unix.Socket(family, unix.SOCK_STREAM, 0)
		if err == nil {
			return fd, err
		}
	}
	return fd, err
}

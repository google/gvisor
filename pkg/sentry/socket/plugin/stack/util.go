// Copyright 2023 The gVisor Authors.
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

package stack

import (
	"net"
	"syscall"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/abi/linux/errno"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/safemem"
	"gvisor.dev/gvisor/pkg/sentry/inet"
	"gvisor.dev/gvisor/pkg/sentry/socket"
	"gvisor.dev/gvisor/pkg/sentry/socket/plugin/cgo"
	"gvisor.dev/gvisor/pkg/syserr"
)

func int2err(from int64) *syserr.Error {
	if from >= 0 {
		return nil
	}

	if (-from) == errno.EAGAIN {
		return syserr.ErrWouldBlock
	}

	return syserr.FromHost(syscall.Errno(-from))
}

func translateReturn(ret int64) (uint64, error) {
	if ret < 0 {
		return 0, int2err(ret).ToError()
	} else if ret == 0 {
		return 0, nil
	} else {
		return uint64(ret), nil
	}
}

func copyAddrOut(ifr *linux.IFReq, ifaceAddr *inet.InterfaceAddr) {
	hostarch.ByteOrder.PutUint16(ifr.Data[0:2], uint16(ifaceAddr.Family))
	hostarch.ByteOrder.PutUint16(ifr.Data[2:4], 0) // port
	if ifaceAddr.Family == linux.AF_INET {
		copy(ifr.Data[4:8], net.IP(ifaceAddr.Addr).To4()[:4])
	} else {
		copy(ifr.Data[8:24], ifaceAddr.Addr[:16])
	}
}

func iovecsFromBlockSeq(bs safemem.BlockSeq, rw *pluginStackRW) []syscall.Iovec {
	var iovs []syscall.Iovec
	if rw != nil {
		// Reuse the old buffer and set length to zero.
		iovs = rw.iovs[:0]
	}
	for ; !bs.IsEmpty(); bs = bs.Tail() {
		b := bs.Head()
		iovs = append(iovs, syscall.Iovec{
			Base: &b.ToSlice()[0],
			Len:  uint64(b.Len()),
		})
	}
	return iovs
}

func buildControlMessage(controlData []byte) *socket.ControlMessages {
	controlMessages := socket.ControlMessages{}
	if len(controlData) >= 28 {
		timebytes := controlData[12:]
		timeval := (*linux.Timeval)(cgo.GetPtr(timebytes))
		m := socket.IPControlMessages{
			HasTimestamp: true,
			Timestamp:    timeval.ToTime(),
		}
		controlMessages.IP = m
	}
	return &controlMessages
}

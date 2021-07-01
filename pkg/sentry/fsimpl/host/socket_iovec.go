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

package host

import (
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/sentry/hostfd"
)

// copyToMulti copies as many bytes from src to dst as possible.
func copyToMulti(dst [][]byte, src []byte) {
	for _, d := range dst {
		done := copy(d, src)
		src = src[done:]
		if len(src) == 0 {
			break
		}
	}
}

// copyFromMulti copies as many bytes from src to dst as possible.
func copyFromMulti(dst []byte, src [][]byte) {
	for _, s := range src {
		done := copy(dst, s)
		dst = dst[done:]
		if len(dst) == 0 {
			break
		}
	}
}

// buildIovec builds an iovec slice from the given []byte slice.
//
// If truncate, truncate bufs > maxlen. Otherwise, immediately return an error.
//
// If length < the total length of bufs, err indicates why, even when returning
// a truncated iovec.
//
// If intermediate != nil, iovecs references intermediate rather than bufs and
// the caller must copy to/from bufs as necessary.
func buildIovec(bufs [][]byte, maxlen int64, truncate bool) (length int64, iovecs []unix.Iovec, intermediate []byte, err error) {
	var iovsRequired int
	for _, b := range bufs {
		length += int64(len(b))
		if len(b) > 0 {
			iovsRequired++
		}
	}

	stopLen := length
	if length > maxlen {
		if truncate {
			stopLen = maxlen
			err = linuxerr.EAGAIN
		} else {
			return 0, nil, nil, linuxerr.EMSGSIZE
		}
	}

	if iovsRequired > hostfd.MaxSendRecvMsgIov {
		// The kernel will reject our call if we pass this many iovs.
		// Use a single intermediate buffer instead.
		b := make([]byte, stopLen)

		return stopLen, []unix.Iovec{{
			Base: &b[0],
			Len:  uint64(stopLen),
		}}, b, err
	}

	var total int64
	iovecs = make([]unix.Iovec, 0, iovsRequired)
	for i := range bufs {
		l := len(bufs[i])
		if l == 0 {
			continue
		}

		stop := int64(l)
		if total+stop > stopLen {
			stop = stopLen - total
		}

		iovecs = append(iovecs, unix.Iovec{
			Base: &bufs[i][0],
			Len:  uint64(stop),
		})

		total += stop
		if total >= stopLen {
			break
		}
	}

	return total, iovecs, nil, err
}

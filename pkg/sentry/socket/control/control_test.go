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

// Package control provides internal representations of socket control
// messages.
package control

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/binary"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/sentry/socket"
)

func TestParse(t *testing.T) {
	// Craft the control message to parse.
	length := linux.SizeOfControlMessageHeader + linux.SizeOfTimeval
	hdr := linux.ControlMessageHeader{
		Length: uint64(length),
		Level:  linux.SOL_SOCKET,
		Type:   linux.SO_TIMESTAMP,
	}
	buf := make([]byte, 0, length)
	buf = binary.Marshal(buf, hostarch.ByteOrder, &hdr)
	ts := linux.Timeval{
		Sec:  2401,
		Usec: 343,
	}
	buf = binary.Marshal(buf, hostarch.ByteOrder, &ts)

	cmsg, err := Parse(nil, nil, buf, 8 /* width */)
	if err != nil {
		t.Fatalf("Parse(_, _, %+v, _): %v", cmsg, err)
	}

	want := socket.ControlMessages{
		IP: socket.IPControlMessages{
			HasTimestamp: true,
			Timestamp:    ts.ToTime(),
		},
	}
	if diff := cmp.Diff(want, cmsg); diff != "" {
		t.Errorf("unexpected message parsed, (-want, +got):\n%s", diff)
	}
}

func TestParseRightsNegativeLength(t *testing.T) {
	// Craft the control message to parse.
	length := uint64(linux.SizeOfControlMessageHeader) + 128
	hdr := linux.ControlMessageHeader{
		Length: uint64(0xffffffff8f000000),
		Level:  linux.SOL_SOCKET,
		Type:   linux.SCM_RIGHTS,
	}
	hdrBuf := make([]byte, 0, length)
	hdrBuf = binary.Marshal(hdrBuf, hostarch.ByteOrder, &hdr)

	buf := make([]byte, length)
	copy(buf, hdrBuf)
	cmsg, err := Parse(nil, nil, buf, 8 /* width */)
	if err != linuxerr.EINVAL {
		t.Fatalf("Parse(_, _, %+v, _): %v", cmsg, err)
	}

}

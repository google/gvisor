// Copyright 2018 The gVisor Authors.
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

package fs

import (
	"bytes"
	"fmt"

	"gvisor.dev/gvisor/pkg/sentry/context"
	"gvisor.dev/gvisor/pkg/sentry/usermem"
)

// inotifyEventBaseSize is the base size of linux's struct inotify_event. This
// must be a power 2 for rounding below.
const inotifyEventBaseSize = 16

// Event represents a struct inotify_event from linux.
//
// +stateify savable
type Event struct {
	eventEntry

	wd     int32
	mask   uint32
	cookie uint32

	// len is computed based on the name field is set automatically by
	// Event.setName. It should be 0 when no name is set; otherwise it is the
	// length of the name slice.
	len uint32

	// The name field has special padding requirements and should only be set by
	// calling Event.setName.
	name []byte
}

func newEvent(wd int32, name string, events, cookie uint32) *Event {
	e := &Event{
		wd:     wd,
		mask:   events,
		cookie: cookie,
	}
	if name != "" {
		e.setName(name)
	}
	return e
}

// paddedBytes converts a go string to a null-terminated c-string, padded with
// null bytes to a total size of 'l'. 'l' must be large enough for all the bytes
// in the 's' plus at least one null byte.
func paddedBytes(s string, l uint32) []byte {
	if l < uint32(len(s)+1) {
		panic("Converting string to byte array results in truncation, this can lead to buffer-overflow due to the missing null-byte!")
	}
	b := make([]byte, l)
	copy(b, s)

	// b was zero-value initialized during make(), so the rest of the slice is
	// already filled with null bytes.

	return b
}

// setName sets the optional name for this event.
func (e *Event) setName(name string) {
	// We need to pad the name such that the entire event length ends up a
	// multiple of inotifyEventBaseSize.
	unpaddedLen := len(name) + 1
	// Round up to nearest multiple of inotifyEventBaseSize.
	e.len = uint32((unpaddedLen + inotifyEventBaseSize - 1) & ^(inotifyEventBaseSize - 1))
	// Make sure we haven't overflowed and wrapped around when rounding.
	if unpaddedLen > int(e.len) {
		panic("Overflow when rounding inotify event size, the 'name' field was too big.")
	}
	e.name = paddedBytes(name, e.len)
}

func (e *Event) sizeOf() int {
	s := inotifyEventBaseSize + int(e.len)
	if s < inotifyEventBaseSize {
		panic("overflow")
	}
	return s
}

// CopyTo serializes this event to dst. buf is used as a scratch buffer to
// construct the output. We use a buffer allocated ahead of time for
// performance. buf must be at least inotifyEventBaseSize bytes.
func (e *Event) CopyTo(ctx context.Context, buf []byte, dst usermem.IOSequence) (int64, error) {
	usermem.ByteOrder.PutUint32(buf[0:], uint32(e.wd))
	usermem.ByteOrder.PutUint32(buf[4:], e.mask)
	usermem.ByteOrder.PutUint32(buf[8:], e.cookie)
	usermem.ByteOrder.PutUint32(buf[12:], e.len)

	writeLen := 0

	n, err := dst.CopyOut(ctx, buf)
	if err != nil {
		return 0, err
	}
	writeLen += n
	dst = dst.DropFirst(n)

	if e.len > 0 {
		n, err = dst.CopyOut(ctx, e.name)
		if err != nil {
			return 0, err
		}
		writeLen += n
	}

	// Santiy check.
	if writeLen != e.sizeOf() {
		panic(fmt.Sprintf("Serialized unexpected amount of data for an event, expected %v, wrote %v.", e.sizeOf(), writeLen))
	}

	return int64(writeLen), nil
}

func (e *Event) equals(other *Event) bool {
	return e.wd == other.wd &&
		e.mask == other.mask &&
		e.cookie == other.cookie &&
		e.len == other.len &&
		bytes.Equal(e.name, other.name)
}

// Copyright 2026 The gVisor Authors.
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

package header

import (
	"testing"

	"gvisor.dev/gvisor/pkg/buffer"
)

// TestIPv6ExtHdrOffsetNoOverflow is a regression test for an integer overflow
// in the extension-header offset accounting.
//
// nextOffset was advanced by `(length+1)*ipv6ExtHdrLenBytesPerUnit` evaluated
// in the uint8 domain, which wraps for any Hdr Ext Len >= 31. The wrapped,
// too-small value corrupts HeaderOffset()/ParseOffset(), which are used to
// locate the transport header (link/fdbased/processors.go) and to report the
// ICMP Parameter-Problem pointer.
//
// Here we place a Destination Options header with Hdr Ext Len = 31 (a 256-byte
// header, the smallest value that triggers the wrap) followed by a second
// Destination Options header, and assert that HeaderOffset() for the second
// header reflects the true position.
func TestIPv6ExtHdrOffsetNoOverflow(t *testing.T) {
	const (
		hdrExtLen  = 31             // 8-octet units, not counting the first 8.
		firstBytes = (hdrExtLen + 1) * 8 // 256 bytes total for the first header.
	)

	// First header: NextHeader = Destination Options (points at header #2),
	// Hdr Ext Len = 31, followed by 254 bytes of padding to reach 256 bytes.
	payload := make([]byte, 0, firstBytes+8)
	payload = append(payload, uint8(IPv6DestinationOptionsExtHdrIdentifier), hdrExtLen)
	payload = append(payload, make([]byte, firstBytes-2)...)
	// Second header: NextHeader = No Next Header, Hdr Ext Len = 0, plus 6 bytes.
	payload = append(payload, uint8(IPv6NoNextHeaderIdentifier), 0)
	payload = append(payload, make([]byte, 6)...)

	it := MakeIPv6PayloadIterator(IPv6DestinationOptionsExtHdrIdentifier, buffer.MakeWithData(payload))
	defer it.Release()

	// Consume the first (long) Destination Options header.
	if _, done, err := it.Next(); err != nil || done {
		t.Fatalf("first Next() = (done %t, err %v), want a header", done, err)
	}
	// Consume the second header; HeaderOffset() now reports the start of the
	// second header, i.e. IPv6FixedHeaderSize + firstBytes.
	if _, done, err := it.Next(); err != nil || done {
		t.Fatalf("second Next() = (done %t, err %v), want a header", done, err)
	}

	want := uint32(IPv6FixedHeaderSize + firstBytes) // 40 + 256 = 296
	if got := it.HeaderOffset(); got != want {
		t.Errorf("HeaderOffset() = %d, want %d (uint8 overflow would yield %d)", got, want, IPv6FixedHeaderSize)
	}
}

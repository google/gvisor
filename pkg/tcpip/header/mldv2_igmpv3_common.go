// Copyright 2022 The gVisor Authors.
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
	"bytes"
	"fmt"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
)

func mldv2AndIGMPv3QuerierQueryCodeToInterval(code uint8) time.Duration {
	// MLDv2: As per RFC 3810 section 5.1.19,
	//
	//   The Querier's Query Interval Code field specifies the [Query
	//   Interval] used by the Querier.  The actual interval, called the
	//   Querier's Query Interval (QQI), is represented in units of seconds,
	//   and is derived from the Querier's Query Interval Code as follows:
	//
	//   If QQIC < 128, QQI = QQIC
	//
	//   If QQIC >= 128, QQIC represents a floating-point value as follows:
	//
	//       0 1 2 3 4 5 6 7
	//      +-+-+-+-+-+-+-+-+
	//      |1| exp | mant  |
	//      +-+-+-+-+-+-+-+-+
	//
	//   QQI = (mant | 0x10) << (exp + 3)
	//
	//   Multicast routers that are not the current Querier adopt the QQI
	//   value from the most recently received Query as their own [Query
	//   Interval] value, unless that most recently received QQI was zero, in
	//   which case the receiving routers use the default [Query Interval]
	//   value specified in section 9.2.
	//
	// IGMPv3: As per RFC 3376 section 4.1.7,
	//
	//   The Querier's Query Interval Code field specifies the [Query
	//   Interval] used by the querier.  The actual interval, called the
	//   Querier's Query Interval (QQI), is represented in units of seconds
	//   and is derived from the Querier's Query Interval Code as follows:
	//
	//   If QQIC < 128, QQI = QQIC
	//
	//   If QQIC >= 128, QQIC represents a floating-point value as follows:
	//
	//       0 1 2 3 4 5 6 7
	//      +-+-+-+-+-+-+-+-+
	//      |1| exp | mant  |
	//      +-+-+-+-+-+-+-+-+
	//
	//   QQI = (mant | 0x10) << (exp + 3)
	//
	//   Multicast routers that are not the current querier adopt the QQI
	//   value from the most recently received Query as their own [Query
	//   Interval] value, unless that most recently received QQI was zero, in
	//   which case the receiving routers use the default [Query Interval]
	//   value specified in section 8.2.
	interval := time.Duration(code)
	if interval < 128 {
		return interval * time.Second
	}

	const expMask = 0b111
	const mantBits = 4
	mant := interval & ((1 << mantBits) - 1)
	exp := (interval >> mantBits) & expMask
	return (mant | 0x10) << (exp + 3) * time.Second
}

// MakeAddressIterator returns an AddressIterator.
func MakeAddressIterator(addressSize int, buf *bytes.Buffer) AddressIterator {
	return AddressIterator{addressSize: addressSize, buf: buf}
}

// AddressIterator is an iterator over IPv6 addresses.
type AddressIterator struct {
	addressSize int
	buf         *bytes.Buffer
}

// Done indicates that the iterator has been exhausted/has no more elements.
func (it *AddressIterator) Done() bool {
	return it.buf.Len() == 0
}

// Next returns the next address in the iterator.
//
// Returns false if the iterator has been exhausted.
func (it *AddressIterator) Next() (tcpip.Address, bool) {
	if it.Done() {
		var emptyAddress tcpip.Address
		return emptyAddress, false
	}

	b := it.buf.Next(it.addressSize)
	if len(b) != it.addressSize {
		panic(fmt.Sprintf("got len(buf.Next(%d)) = %d, want = %d", it.addressSize, len(b), it.addressSize))
	}

	return tcpip.AddrFromSlice(b), true
}

func makeAddressIterator(b []byte, expectedAddresses uint16, addressSize int) (AddressIterator, bool) {
	expectedLen := int(expectedAddresses) * addressSize
	if len(b) < expectedLen {
		return AddressIterator{}, false
	}
	return MakeAddressIterator(addressSize, bytes.NewBuffer(b[:expectedLen])), true
}

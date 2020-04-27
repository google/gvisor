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

package header

import (
	"bytes"
	"errors"
	"io"
	"testing"

	"github.com/google/go-cmp/cmp"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
)

// Equal returns true of a and b are equivalent.
//
// Note, Equal will return true if a and b hold the same Identifier value and
// contain the same bytes in Buf, even if the bytes are split across views
// differently.
//
// Needed to use cmp.Equal on IPv6RawPayloadHeader as it contains unexported
// fields.
func (a IPv6RawPayloadHeader) Equal(b IPv6RawPayloadHeader) bool {
	return a.Identifier == b.Identifier && bytes.Equal(a.Buf.ToView(), b.Buf.ToView())
}

// Equal returns true of a and b are equivalent.
//
// Note, Equal will return true if a and b hold equivalent ipv6OptionsExtHdrs.
//
// Needed to use cmp.Equal on IPv6RawPayloadHeader as it contains unexported
// fields.
func (a IPv6HopByHopOptionsExtHdr) Equal(b IPv6HopByHopOptionsExtHdr) bool {
	return bytes.Equal(a.ipv6OptionsExtHdr, b.ipv6OptionsExtHdr)
}

// Equal returns true of a and b are equivalent.
//
// Note, Equal will return true if a and b hold equivalent ipv6OptionsExtHdrs.
//
// Needed to use cmp.Equal on IPv6RawPayloadHeader as it contains unexported
// fields.
func (a IPv6DestinationOptionsExtHdr) Equal(b IPv6DestinationOptionsExtHdr) bool {
	return bytes.Equal(a.ipv6OptionsExtHdr, b.ipv6OptionsExtHdr)
}

func TestIPv6UnknownExtHdrOption(t *testing.T) {
	tests := []struct {
		name                  string
		identifier            IPv6ExtHdrOptionIndentifier
		expectedUnknownAction IPv6OptionUnknownAction
	}{
		{
			name:                  "Skip with zero LSBs",
			identifier:            0,
			expectedUnknownAction: IPv6OptionUnknownActionSkip,
		},
		{
			name:                  "Discard with zero LSBs",
			identifier:            64,
			expectedUnknownAction: IPv6OptionUnknownActionDiscard,
		},
		{
			name:                  "Discard and ICMP with zero LSBs",
			identifier:            128,
			expectedUnknownAction: IPv6OptionUnknownActionDiscardSendICMP,
		},
		{
			name:                  "Discard and ICMP for non multicast destination with zero LSBs",
			identifier:            192,
			expectedUnknownAction: IPv6OptionUnknownActionDiscardSendICMPNoMulticastDest,
		},
		{
			name:                  "Skip with non-zero LSBs",
			identifier:            63,
			expectedUnknownAction: IPv6OptionUnknownActionSkip,
		},
		{
			name:                  "Discard with non-zero LSBs",
			identifier:            127,
			expectedUnknownAction: IPv6OptionUnknownActionDiscard,
		},
		{
			name:                  "Discard and ICMP with non-zero LSBs",
			identifier:            191,
			expectedUnknownAction: IPv6OptionUnknownActionDiscardSendICMP,
		},
		{
			name:                  "Discard and ICMP for non multicast destination with non-zero LSBs",
			identifier:            255,
			expectedUnknownAction: IPv6OptionUnknownActionDiscardSendICMPNoMulticastDest,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			opt := &IPv6UnknownExtHdrOption{Identifier: test.identifier, Data: []byte{1, 2, 3, 4}}
			if a := opt.UnknownAction(); a != test.expectedUnknownAction {
				t.Fatalf("got UnknownAction() = %d, want = %d", a, test.expectedUnknownAction)
			}
		})
	}

}

func TestIPv6OptionsExtHdrIterErr(t *testing.T) {
	tests := []struct {
		name  string
		bytes []byte
		err   error
	}{
		{
			name:  "Single unknown with zero length",
			bytes: []byte{255, 0},
		},
		{
			name:  "Single unknown with non-zero length",
			bytes: []byte{255, 3, 1, 2, 3},
		},
		{
			name: "Two options",
			bytes: []byte{
				255, 0,
				254, 1, 1,
			},
		},
		{
			name: "Three options",
			bytes: []byte{
				255, 0,
				254, 1, 1,
				253, 4, 2, 3, 4, 5,
			},
		},
		{
			name:  "Single unknown only identifier",
			bytes: []byte{255},
			err:   io.ErrUnexpectedEOF,
		},
		{
			name:  "Single unknown too small with length = 1",
			bytes: []byte{255, 1},
			err:   io.ErrUnexpectedEOF,
		},
		{
			name:  "Single unknown too small with length = 2",
			bytes: []byte{255, 2, 1},
			err:   io.ErrUnexpectedEOF,
		},
		{
			name: "Valid first with second unknown only identifier",
			bytes: []byte{
				255, 0,
				254,
			},
			err: io.ErrUnexpectedEOF,
		},
		{
			name: "Valid first with second unknown missing data",
			bytes: []byte{
				255, 0,
				254, 1,
			},
			err: io.ErrUnexpectedEOF,
		},
		{
			name: "Valid first with second unknown too small",
			bytes: []byte{
				255, 0,
				254, 2, 1,
			},
			err: io.ErrUnexpectedEOF,
		},
		{
			name:  "One Pad1",
			bytes: []byte{0},
		},
		{
			name:  "Multiple Pad1",
			bytes: []byte{0, 0, 0},
		},
		{
			name: "Multiple PadN",
			bytes: []byte{
				// Pad3
				1, 1, 1,

				// Pad5
				1, 3, 1, 2, 3,
			},
		},
		{
			name:  "Pad5 too small middle of data buffer",
			bytes: []byte{1, 3, 1, 2},
			err:   io.ErrUnexpectedEOF,
		},
		{
			name:  "Pad5 no data",
			bytes: []byte{1, 3},
			err:   io.ErrUnexpectedEOF,
		},
	}

	check := func(t *testing.T, it IPv6OptionsExtHdrOptionsIterator, expectedErr error) {
		for i := 0; ; i++ {
			_, done, err := it.Next()
			if err != nil {
				// If we encountered a non-nil error while iterating, make sure it is
				// is the same error as expectedErr.
				if !errors.Is(err, expectedErr) {
					t.Fatalf("got %d-th Next() = %v, want = %v", i, err, expectedErr)
				}

				return
			}
			if done {
				// If we are done (without an error), make sure that we did not expect
				// an error.
				if expectedErr != nil {
					t.Fatalf("expected error when iterating; want = %s", expectedErr)
				}

				return
			}
		}
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Run("Hop By Hop", func(t *testing.T) {
				extHdr := IPv6HopByHopOptionsExtHdr{ipv6OptionsExtHdr: test.bytes}
				check(t, extHdr.Iter(), test.err)
			})

			t.Run("Destination", func(t *testing.T) {
				extHdr := IPv6DestinationOptionsExtHdr{ipv6OptionsExtHdr: test.bytes}
				check(t, extHdr.Iter(), test.err)
			})
		})
	}
}

func TestIPv6OptionsExtHdrIter(t *testing.T) {
	tests := []struct {
		name     string
		bytes    []byte
		expected []IPv6ExtHdrOption
	}{
		{
			name:  "Single unknown with zero length",
			bytes: []byte{255, 0},
			expected: []IPv6ExtHdrOption{
				&IPv6UnknownExtHdrOption{Identifier: 255, Data: []byte{}},
			},
		},
		{
			name:  "Single unknown with non-zero length",
			bytes: []byte{255, 3, 1, 2, 3},
			expected: []IPv6ExtHdrOption{
				&IPv6UnknownExtHdrOption{Identifier: 255, Data: []byte{1, 2, 3}},
			},
		},
		{
			name:  "Single Pad1",
			bytes: []byte{0},
		},
		{
			name:  "Two Pad1",
			bytes: []byte{0, 0},
		},
		{
			name:  "Single Pad3",
			bytes: []byte{1, 1, 1},
		},
		{
			name:  "Single Pad5",
			bytes: []byte{1, 3, 1, 2, 3},
		},
		{
			name: "Multiple Pad",
			bytes: []byte{
				// Pad1
				0,

				// Pad2
				1, 0,

				// Pad3
				1, 1, 1,

				// Pad4
				1, 2, 1, 2,

				// Pad5
				1, 3, 1, 2, 3,
			},
		},
		{
			name: "Multiple options",
			bytes: []byte{
				// Pad1
				0,

				// Unknown
				255, 0,

				// Pad2
				1, 0,

				// Unknown
				254, 1, 1,

				// Pad3
				1, 1, 1,

				// Unknown
				253, 4, 2, 3, 4, 5,

				// Pad4
				1, 2, 1, 2,
			},
			expected: []IPv6ExtHdrOption{
				&IPv6UnknownExtHdrOption{Identifier: 255, Data: []byte{}},
				&IPv6UnknownExtHdrOption{Identifier: 254, Data: []byte{1}},
				&IPv6UnknownExtHdrOption{Identifier: 253, Data: []byte{2, 3, 4, 5}},
			},
		},
	}

	checkIter := func(t *testing.T, it IPv6OptionsExtHdrOptionsIterator, expected []IPv6ExtHdrOption) {
		for i, e := range expected {
			opt, done, err := it.Next()
			if err != nil {
				t.Errorf("(i=%d) Next(): %s", i, err)
			}
			if done {
				t.Errorf("(i=%d) unexpectedly done iterating", i)
			}
			if diff := cmp.Diff(e, opt); diff != "" {
				t.Errorf("(i=%d) got option mismatch (-want +got):\n%s", i, diff)
			}

			if t.Failed() {
				t.FailNow()
			}
		}

		opt, done, err := it.Next()
		if err != nil {
			t.Errorf("(last) Next(): %s", err)
		}
		if !done {
			t.Errorf("(last) iterator unexpectedly not done")
		}
		if opt != nil {
			t.Errorf("(last) got Next() = %T, want = nil", opt)
		}
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Run("Hop By Hop", func(t *testing.T) {
				extHdr := IPv6HopByHopOptionsExtHdr{ipv6OptionsExtHdr: test.bytes}
				checkIter(t, extHdr.Iter(), test.expected)
			})

			t.Run("Destination", func(t *testing.T) {
				extHdr := IPv6DestinationOptionsExtHdr{ipv6OptionsExtHdr: test.bytes}
				checkIter(t, extHdr.Iter(), test.expected)
			})
		})
	}
}

func TestIPv6RoutingExtHdr(t *testing.T) {
	tests := []struct {
		name         string
		bytes        []byte
		segmentsLeft uint8
	}{
		{
			name:         "Zeroes",
			bytes:        []byte{0, 0, 0, 0, 0, 0},
			segmentsLeft: 0,
		},
		{
			name:         "Ones",
			bytes:        []byte{1, 1, 1, 1, 1, 1},
			segmentsLeft: 1,
		},
		{
			name:         "Mixed",
			bytes:        []byte{1, 2, 3, 4, 5, 6},
			segmentsLeft: 2,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			extHdr := IPv6RoutingExtHdr(test.bytes)
			if got := extHdr.SegmentsLeft(); got != test.segmentsLeft {
				t.Errorf("got SegmentsLeft() = %d, want = %d", got, test.segmentsLeft)
			}
		})
	}
}

func TestIPv6FragmentExtHdr(t *testing.T) {
	tests := []struct {
		name           string
		bytes          [6]byte
		fragmentOffset uint16
		more           bool
		id             uint32
	}{
		{
			name:           "Zeroes",
			bytes:          [6]byte{0, 0, 0, 0, 0, 0},
			fragmentOffset: 0,
			more:           false,
			id:             0,
		},
		{
			name:           "Ones",
			bytes:          [6]byte{0, 9, 0, 0, 0, 1},
			fragmentOffset: 1,
			more:           true,
			id:             1,
		},
		{
			name:           "Mixed",
			bytes:          [6]byte{68, 9, 128, 4, 2, 1},
			fragmentOffset: 2177,
			more:           true,
			id:             2147746305,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			extHdr := IPv6FragmentExtHdr(test.bytes)
			if got := extHdr.FragmentOffset(); got != test.fragmentOffset {
				t.Errorf("got FragmentOffset() = %d, want = %d", got, test.fragmentOffset)
			}
			if got := extHdr.More(); got != test.more {
				t.Errorf("got More() = %t, want = %t", got, test.more)
			}
			if got := extHdr.ID(); got != test.id {
				t.Errorf("got ID() = %d, want = %d", got, test.id)
			}
		})
	}
}

func makeVectorisedViewFromByteBuffers(bs ...[]byte) buffer.VectorisedView {
	size := 0
	var vs []buffer.View

	for _, b := range bs {
		vs = append(vs, buffer.View(b))
		size += len(b)
	}

	return buffer.NewVectorisedView(size, vs)
}

func TestIPv6ExtHdrIterErr(t *testing.T) {
	tests := []struct {
		name         string
		firstNextHdr IPv6ExtensionHeaderIdentifier
		payload      buffer.VectorisedView
		err          error
	}{
		{
			name:         "Upper layer only without data",
			firstNextHdr: 255,
		},
		{
			name:         "Upper layer only with data",
			firstNextHdr: 255,
			payload:      makeVectorisedViewFromByteBuffers([]byte{1, 2, 3, 4}),
		},
		{
			name:         "No next header",
			firstNextHdr: IPv6NoNextHeaderIdentifier,
		},
		{
			name:         "No next header with data",
			firstNextHdr: IPv6NoNextHeaderIdentifier,
			payload:      makeVectorisedViewFromByteBuffers([]byte{1, 2, 3, 4}),
		},
		{
			name:         "Valid single hop by hop",
			firstNextHdr: IPv6HopByHopOptionsExtHdrIdentifier,
			payload:      makeVectorisedViewFromByteBuffers([]byte{255, 0, 1, 4, 1, 2, 3, 4}),
		},
		{
			name:         "Hop by hop too small",
			firstNextHdr: IPv6HopByHopOptionsExtHdrIdentifier,
			payload:      makeVectorisedViewFromByteBuffers([]byte{255, 0, 1, 4, 1, 2, 3}),
			err:          io.ErrUnexpectedEOF,
		},
		{
			name:         "Valid single fragment",
			firstNextHdr: IPv6FragmentExtHdrIdentifier,
			payload:      makeVectorisedViewFromByteBuffers([]byte{255, 0, 68, 9, 128, 4, 2, 1}),
		},
		{
			name:         "Fragment too small",
			firstNextHdr: IPv6FragmentExtHdrIdentifier,
			payload:      makeVectorisedViewFromByteBuffers([]byte{255, 0, 68, 9, 128, 4, 2}),
			err:          io.ErrUnexpectedEOF,
		},
		{
			name:         "Valid single destination",
			firstNextHdr: IPv6DestinationOptionsExtHdrIdentifier,
			payload:      makeVectorisedViewFromByteBuffers([]byte{255, 0, 1, 4, 1, 2, 3, 4}),
		},
		{
			name:         "Destination too small",
			firstNextHdr: IPv6DestinationOptionsExtHdrIdentifier,
			payload:      makeVectorisedViewFromByteBuffers([]byte{255, 0, 1, 4, 1, 2, 3}),
			err:          io.ErrUnexpectedEOF,
		},
		{
			name:         "Valid single routing",
			firstNextHdr: IPv6RoutingExtHdrIdentifier,
			payload:      makeVectorisedViewFromByteBuffers([]byte{255, 0, 1, 2, 3, 4, 5, 6}),
		},
		{
			name:         "Valid single routing across views",
			firstNextHdr: IPv6RoutingExtHdrIdentifier,
			payload:      makeVectorisedViewFromByteBuffers([]byte{255, 0, 1, 2}, []byte{3, 4, 5, 6}),
		},
		{
			name:         "Routing too small with zero length field",
			firstNextHdr: IPv6RoutingExtHdrIdentifier,
			payload:      makeVectorisedViewFromByteBuffers([]byte{255, 0, 1, 2, 3, 4, 5}),
			err:          io.ErrUnexpectedEOF,
		},
		{
			name:         "Valid routing with non-zero length field",
			firstNextHdr: IPv6RoutingExtHdrIdentifier,
			payload:      makeVectorisedViewFromByteBuffers([]byte{255, 1, 1, 2, 3, 4, 5, 6, 1, 2, 3, 4, 5, 6, 7, 8}),
		},
		{
			name:         "Valid routing with non-zero length field across views",
			firstNextHdr: IPv6RoutingExtHdrIdentifier,
			payload:      makeVectorisedViewFromByteBuffers([]byte{255, 1, 1, 2, 3, 4, 5, 6}, []byte{1, 2, 3, 4, 5, 6, 7, 8}),
		},
		{
			name:         "Routing too small with non-zero length field",
			firstNextHdr: IPv6RoutingExtHdrIdentifier,
			payload:      makeVectorisedViewFromByteBuffers([]byte{255, 1, 1, 2, 3, 4, 5, 6, 1, 2, 3, 4, 5, 6, 7}),
			err:          io.ErrUnexpectedEOF,
		},
		{
			name:         "Routing too small with non-zero length field across views",
			firstNextHdr: IPv6RoutingExtHdrIdentifier,
			payload:      makeVectorisedViewFromByteBuffers([]byte{255, 1, 1, 2, 3, 4, 5, 6}, []byte{1, 2, 3, 4, 5, 6, 7}),
			err:          io.ErrUnexpectedEOF,
		},
		{
			name:         "Mixed",
			firstNextHdr: IPv6HopByHopOptionsExtHdrIdentifier,
			payload: makeVectorisedViewFromByteBuffers([]byte{
				// Hop By Hop Options extension header.
				uint8(IPv6FragmentExtHdrIdentifier), 0, 1, 4, 1, 2, 3, 4,

				// (Atomic) Fragment extension header.
				//
				// Reserved bits are 1 which should not affect anything.
				uint8(IPv6RoutingExtHdrIdentifier), 255, 0, 6, 128, 4, 2, 1,

				// Routing extension header.
				uint8(IPv6DestinationOptionsExtHdrIdentifier), 0, 1, 2, 3, 4, 5, 6,

				// Destination Options extension header.
				255, 0, 255, 4, 1, 2, 3, 4,

				// Upper layer data.
				1, 2, 3, 4,
			}),
		},
		{
			name:         "Mixed without upper layer data",
			firstNextHdr: IPv6HopByHopOptionsExtHdrIdentifier,
			payload: makeVectorisedViewFromByteBuffers([]byte{
				// Hop By Hop Options extension header.
				uint8(IPv6FragmentExtHdrIdentifier), 0, 1, 4, 1, 2, 3, 4,

				// (Atomic) Fragment extension header.
				//
				// Reserved bits are 1 which should not affect anything.
				uint8(IPv6RoutingExtHdrIdentifier), 255, 0, 6, 128, 4, 2, 1,

				// Routing extension header.
				uint8(IPv6DestinationOptionsExtHdrIdentifier), 0, 1, 2, 3, 4, 5, 6,

				// Destination Options extension header.
				255, 0, 255, 4, 1, 2, 3, 4,
			}),
		},
		{
			name:         "Mixed without upper layer data but last ext hdr too small",
			firstNextHdr: IPv6HopByHopOptionsExtHdrIdentifier,
			payload: makeVectorisedViewFromByteBuffers([]byte{
				// Hop By Hop Options extension header.
				uint8(IPv6FragmentExtHdrIdentifier), 0, 1, 4, 1, 2, 3, 4,

				// (Atomic) Fragment extension header.
				//
				// Reserved bits are 1 which should not affect anything.
				uint8(IPv6RoutingExtHdrIdentifier), 255, 0, 6, 128, 4, 2, 1,

				// Routing extension header.
				uint8(IPv6DestinationOptionsExtHdrIdentifier), 0, 1, 2, 3, 4, 5, 6,

				// Destination Options extension header.
				255, 0, 255, 4, 1, 2, 3,
			}),
			err: io.ErrUnexpectedEOF,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			it := MakeIPv6PayloadIterator(test.firstNextHdr, test.payload)

			for i := 0; ; i++ {
				_, done, err := it.Next()
				if err != nil {
					// If we encountered a non-nil error while iterating, make sure it is
					// is the same error as test.err.
					if !errors.Is(err, test.err) {
						t.Fatalf("got %d-th Next() = %v, want = %v", i, err, test.err)
					}

					return
				}
				if done {
					// If we are done (without an error), make sure that we did not expect
					// an error.
					if test.err != nil {
						t.Fatalf("expected error when iterating; want = %s", test.err)
					}

					return
				}
			}
		})
	}
}

func TestIPv6ExtHdrIter(t *testing.T) {
	routingExtHdrWithUpperLayerData := buffer.View([]byte{255, 0, 1, 2, 3, 4, 5, 6, 1, 2, 3, 4})
	upperLayerData := buffer.View([]byte{1, 2, 3, 4})
	tests := []struct {
		name         string
		firstNextHdr IPv6ExtensionHeaderIdentifier
		payload      buffer.VectorisedView
		expected     []IPv6PayloadHeader
	}{
		// With a non-atomic fragment that is not the first fragment, the payload
		// after the fragment will not be parsed because the payload is expected to
		// only hold upper layer data.
		{
			name:         "hopbyhop - fragment (not first) - routing - upper",
			firstNextHdr: IPv6HopByHopOptionsExtHdrIdentifier,
			payload: makeVectorisedViewFromByteBuffers([]byte{
				// Hop By Hop extension header.
				uint8(IPv6FragmentExtHdrIdentifier), 0, 1, 4, 1, 2, 3, 4,

				// Fragment extension header.
				//
				// More = 1, Fragment Offset = 2117, ID = 2147746305
				uint8(IPv6RoutingExtHdrIdentifier), 0, 68, 9, 128, 4, 2, 1,

				// Routing extension header.
				//
				// Even though we have a routing ext header here, it should be
				// be interpretted as raw bytes as only the first fragment is expected
				// to hold headers.
				255, 0, 1, 2, 3, 4, 5, 6,

				// Upper layer data.
				1, 2, 3, 4,
			}),
			expected: []IPv6PayloadHeader{
				IPv6HopByHopOptionsExtHdr{ipv6OptionsExtHdr: []byte{1, 4, 1, 2, 3, 4}},
				IPv6FragmentExtHdr([6]byte{68, 9, 128, 4, 2, 1}),
				IPv6RawPayloadHeader{
					Identifier: IPv6RoutingExtHdrIdentifier,
					Buf:        routingExtHdrWithUpperLayerData.ToVectorisedView(),
				},
			},
		},
		{
			name:         "hopbyhop - fragment (first) - routing - upper",
			firstNextHdr: IPv6HopByHopOptionsExtHdrIdentifier,
			payload: makeVectorisedViewFromByteBuffers([]byte{
				// Hop By Hop extension header.
				uint8(IPv6FragmentExtHdrIdentifier), 0, 1, 4, 1, 2, 3, 4,

				// Fragment extension header.
				//
				// More = 1, Fragment Offset = 0, ID = 2147746305
				uint8(IPv6RoutingExtHdrIdentifier), 0, 0, 1, 128, 4, 2, 1,

				// Routing extension header.
				255, 0, 1, 2, 3, 4, 5, 6,

				// Upper layer data.
				1, 2, 3, 4,
			}),
			expected: []IPv6PayloadHeader{
				IPv6HopByHopOptionsExtHdr{ipv6OptionsExtHdr: []byte{1, 4, 1, 2, 3, 4}},
				IPv6FragmentExtHdr([6]byte{0, 1, 128, 4, 2, 1}),
				IPv6RoutingExtHdr([]byte{1, 2, 3, 4, 5, 6}),
				IPv6RawPayloadHeader{
					Identifier: 255,
					Buf:        upperLayerData.ToVectorisedView(),
				},
			},
		},
		{
			name:         "fragment - routing - upper (across views)",
			firstNextHdr: IPv6FragmentExtHdrIdentifier,
			payload: makeVectorisedViewFromByteBuffers([]byte{
				// Fragment extension header.
				uint8(IPv6RoutingExtHdrIdentifier), 0, 68, 9, 128, 4, 2, 1,

				// Routing extension header.
				255, 0, 1, 2}, []byte{3, 4, 5, 6,

				// Upper layer data.
				1, 2, 3, 4,
			}),
			expected: []IPv6PayloadHeader{
				IPv6FragmentExtHdr([6]byte{68, 9, 128, 4, 2, 1}),
				IPv6RawPayloadHeader{
					Identifier: IPv6RoutingExtHdrIdentifier,
					Buf:        routingExtHdrWithUpperLayerData.ToVectorisedView(),
				},
			},
		},

		// If we have an atomic fragment, the payload following the fragment
		// extension header should be parsed normally.
		{
			name:         "atomic fragment - routing - destination - upper",
			firstNextHdr: IPv6FragmentExtHdrIdentifier,
			payload: makeVectorisedViewFromByteBuffers([]byte{
				// Fragment extension header.
				//
				// Reserved bits are 1 which should not affect anything.
				uint8(IPv6RoutingExtHdrIdentifier), 255, 0, 6, 128, 4, 2, 1,

				// Routing extension header.
				uint8(IPv6DestinationOptionsExtHdrIdentifier), 0, 1, 2, 3, 4, 5, 6,

				// Destination Options extension header.
				255, 0, 1, 4, 1, 2, 3, 4,

				// Upper layer data.
				1, 2, 3, 4,
			}),
			expected: []IPv6PayloadHeader{
				IPv6FragmentExtHdr([6]byte{0, 6, 128, 4, 2, 1}),
				IPv6RoutingExtHdr([]byte{1, 2, 3, 4, 5, 6}),
				IPv6DestinationOptionsExtHdr{ipv6OptionsExtHdr: []byte{1, 4, 1, 2, 3, 4}},
				IPv6RawPayloadHeader{
					Identifier: 255,
					Buf:        upperLayerData.ToVectorisedView(),
				},
			},
		},
		{
			name:         "atomic fragment - routing - upper (across views)",
			firstNextHdr: IPv6FragmentExtHdrIdentifier,
			payload: makeVectorisedViewFromByteBuffers([]byte{
				// Fragment extension header.
				//
				// Reserved bits are 1 which should not affect anything.
				uint8(IPv6RoutingExtHdrIdentifier), 255, 0, 6}, []byte{128, 4, 2, 1,

				// Routing extension header.
				255, 0, 1, 2}, []byte{3, 4, 5, 6,

				// Upper layer data.
				1, 2}, []byte{3, 4}),
			expected: []IPv6PayloadHeader{
				IPv6FragmentExtHdr([6]byte{0, 6, 128, 4, 2, 1}),
				IPv6RoutingExtHdr([]byte{1, 2, 3, 4, 5, 6}),
				IPv6RawPayloadHeader{
					Identifier: 255,
					Buf:        makeVectorisedViewFromByteBuffers(upperLayerData[:2], upperLayerData[2:]),
				},
			},
		},
		{
			name:         "atomic fragment - destination - no next header",
			firstNextHdr: IPv6FragmentExtHdrIdentifier,
			payload: makeVectorisedViewFromByteBuffers([]byte{
				// Fragment extension header.
				//
				// Res (Reserved) bits are 1 which should not affect anything.
				uint8(IPv6DestinationOptionsExtHdrIdentifier), 0, 0, 6, 128, 4, 2, 1,

				// Destination Options extension header.
				uint8(IPv6NoNextHeaderIdentifier), 0, 1, 4, 1, 2, 3, 4,

				// Random data.
				1, 2, 3, 4,
			}),
			expected: []IPv6PayloadHeader{
				IPv6FragmentExtHdr([6]byte{0, 6, 128, 4, 2, 1}),
				IPv6DestinationOptionsExtHdr{ipv6OptionsExtHdr: []byte{1, 4, 1, 2, 3, 4}},
			},
		},
		{
			name:         "routing - atomic fragment - no next header",
			firstNextHdr: IPv6RoutingExtHdrIdentifier,
			payload: makeVectorisedViewFromByteBuffers([]byte{
				// Routing extension header.
				uint8(IPv6FragmentExtHdrIdentifier), 0, 1, 2, 3, 4, 5, 6,

				// Fragment extension header.
				//
				// Reserved bits are 1 which should not affect anything.
				uint8(IPv6NoNextHeaderIdentifier), 0, 0, 6, 128, 4, 2, 1,

				// Random data.
				1, 2, 3, 4,
			}),
			expected: []IPv6PayloadHeader{
				IPv6RoutingExtHdr([]byte{1, 2, 3, 4, 5, 6}),
				IPv6FragmentExtHdr([6]byte{0, 6, 128, 4, 2, 1}),
			},
		},
		{
			name:         "routing - atomic fragment - no next header (across views)",
			firstNextHdr: IPv6RoutingExtHdrIdentifier,
			payload: makeVectorisedViewFromByteBuffers([]byte{
				// Routing extension header.
				uint8(IPv6FragmentExtHdrIdentifier), 0, 1, 2, 3, 4, 5, 6,

				// Fragment extension header.
				//
				// Reserved bits are 1 which should not affect anything.
				uint8(IPv6NoNextHeaderIdentifier), 255, 0, 6}, []byte{128, 4, 2, 1,

				// Random data.
				1, 2, 3, 4,
			}),
			expected: []IPv6PayloadHeader{
				IPv6RoutingExtHdr([]byte{1, 2, 3, 4, 5, 6}),
				IPv6FragmentExtHdr([6]byte{0, 6, 128, 4, 2, 1}),
			},
		},
		{
			name:         "hopbyhop - routing - fragment - no next header",
			firstNextHdr: IPv6HopByHopOptionsExtHdrIdentifier,
			payload: makeVectorisedViewFromByteBuffers([]byte{
				// Hop By Hop Options extension header.
				uint8(IPv6RoutingExtHdrIdentifier), 0, 1, 4, 1, 2, 3, 4,

				// Routing extension header.
				uint8(IPv6FragmentExtHdrIdentifier), 0, 1, 2, 3, 4, 5, 6,

				// Fragment extension header.
				//
				// Fragment Offset = 32; Res = 6.
				uint8(IPv6NoNextHeaderIdentifier), 0, 1, 6, 128, 4, 2, 1,

				// Random data.
				1, 2, 3, 4,
			}),
			expected: []IPv6PayloadHeader{
				IPv6HopByHopOptionsExtHdr{ipv6OptionsExtHdr: []byte{1, 4, 1, 2, 3, 4}},
				IPv6RoutingExtHdr([]byte{1, 2, 3, 4, 5, 6}),
				IPv6FragmentExtHdr([6]byte{1, 6, 128, 4, 2, 1}),
				IPv6RawPayloadHeader{
					Identifier: IPv6NoNextHeaderIdentifier,
					Buf:        upperLayerData.ToVectorisedView(),
				},
			},
		},

		// Test the raw payload for common transport layer protocol numbers.
		{
			name:         "TCP raw payload",
			firstNextHdr: IPv6ExtensionHeaderIdentifier(TCPProtocolNumber),
			payload:      makeVectorisedViewFromByteBuffers(upperLayerData),
			expected: []IPv6PayloadHeader{IPv6RawPayloadHeader{
				Identifier: IPv6ExtensionHeaderIdentifier(TCPProtocolNumber),
				Buf:        upperLayerData.ToVectorisedView(),
			}},
		},
		{
			name:         "UDP raw payload",
			firstNextHdr: IPv6ExtensionHeaderIdentifier(UDPProtocolNumber),
			payload:      makeVectorisedViewFromByteBuffers(upperLayerData),
			expected: []IPv6PayloadHeader{IPv6RawPayloadHeader{
				Identifier: IPv6ExtensionHeaderIdentifier(UDPProtocolNumber),
				Buf:        upperLayerData.ToVectorisedView(),
			}},
		},
		{
			name:         "ICMPv4 raw payload",
			firstNextHdr: IPv6ExtensionHeaderIdentifier(ICMPv4ProtocolNumber),
			payload:      makeVectorisedViewFromByteBuffers(upperLayerData),
			expected: []IPv6PayloadHeader{IPv6RawPayloadHeader{
				Identifier: IPv6ExtensionHeaderIdentifier(ICMPv4ProtocolNumber),
				Buf:        upperLayerData.ToVectorisedView(),
			}},
		},
		{
			name:         "ICMPv6 raw payload",
			firstNextHdr: IPv6ExtensionHeaderIdentifier(ICMPv6ProtocolNumber),
			payload:      makeVectorisedViewFromByteBuffers(upperLayerData),
			expected: []IPv6PayloadHeader{IPv6RawPayloadHeader{
				Identifier: IPv6ExtensionHeaderIdentifier(ICMPv6ProtocolNumber),
				Buf:        upperLayerData.ToVectorisedView(),
			}},
		},
		{
			name:         "Unknwon next header raw payload",
			firstNextHdr: 255,
			payload:      makeVectorisedViewFromByteBuffers(upperLayerData),
			expected: []IPv6PayloadHeader{IPv6RawPayloadHeader{
				Identifier: 255,
				Buf:        upperLayerData.ToVectorisedView(),
			}},
		},
		{
			name:         "Unknwon next header raw payload (across views)",
			firstNextHdr: 255,
			payload:      makeVectorisedViewFromByteBuffers(upperLayerData[:2], upperLayerData[2:]),
			expected: []IPv6PayloadHeader{IPv6RawPayloadHeader{
				Identifier: 255,
				Buf:        makeVectorisedViewFromByteBuffers(upperLayerData[:2], upperLayerData[2:]),
			}},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			it := MakeIPv6PayloadIterator(test.firstNextHdr, test.payload)

			for i, e := range test.expected {
				extHdr, done, err := it.Next()
				if err != nil {
					t.Errorf("(i=%d) Next(): %s", i, err)
				}
				if done {
					t.Errorf("(i=%d) unexpectedly done iterating", i)
				}
				if diff := cmp.Diff(e, extHdr); diff != "" {
					t.Errorf("(i=%d) got ext hdr mismatch (-want +got):\n%s", i, diff)
				}

				if t.Failed() {
					t.FailNow()
				}
			}

			extHdr, done, err := it.Next()
			if err != nil {
				t.Errorf("(last) Next(): %s", err)
			}
			if !done {
				t.Errorf("(last) iterator unexpectedly not done")
			}
			if extHdr != nil {
				t.Errorf("(last) got Next() = %T, want = nil", extHdr)
			}
		})
	}
}

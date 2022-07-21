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
	"gvisor.dev/gvisor/pkg/bufferv2"
	"gvisor.dev/gvisor/pkg/tcpip"
)

var (
	bufferTransformer = cmp.Transformer("buffer", func(b bufferv2.Buffer) []byte {
		return b.Flatten()
	})
	viewTransformer = cmp.Transformer("view", func(v bufferv2.View) []byte {
		return v.AsSlice()
	})
)

// Equal returns true of a and b are equivalent.
//
// Note, Equal will return true if a and b hold the same Identifier value and
// contain the same bytes in Buf, even if the bytes are split across views
// differently.
//
// Needed to use cmp.Equal on IPv6RawPayloadHeader as it contains unexported
// fields.
func (i IPv6RawPayloadHeader) Equal(b IPv6RawPayloadHeader) bool {
	return i.Identifier == b.Identifier && bytes.Equal(i.Buf.Flatten(), b.Buf.Flatten())
}

// Equal returns true of a and b are equivalent.
//
// Note, Equal will return true if a and b hold equivalent ipv6OptionsExtHdrs.
//
// Needed to use cmp.Equal on IPv6RawPayloadHeader as it contains unexported
// fields.
func (a IPv6HopByHopOptionsExtHdr) Equal(b IPv6HopByHopOptionsExtHdr) bool {
	return bytes.Equal(a.ipv6OptionsExtHdr.buf.AsSlice(), b.ipv6OptionsExtHdr.buf.AsSlice())
}

// Equal returns true of a and b are equivalent.
//
// Note, Equal will return true if a and b hold equivalent ipv6OptionsExtHdrs.
//
// Needed to use cmp.Equal on IPv6RawPayloadHeader as it contains unexported
// fields.
func (a IPv6DestinationOptionsExtHdr) Equal(b IPv6DestinationOptionsExtHdr) bool {
	return bytes.Equal(a.ipv6OptionsExtHdr.buf.AsSlice(), b.ipv6OptionsExtHdr.buf.AsSlice())
}

func TestIPv6UnknownExtHdrOption(t *testing.T) {
	tests := []struct {
		name                  string
		identifier            IPv6ExtHdrOptionIdentifier
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
			opt := &IPv6UnknownExtHdrOption{Identifier: test.identifier, Data: bufferv2.NewViewWithData([]byte{1, 2, 3, 4})}
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
		{
			name:  "Router alert without data",
			bytes: []byte{byte(ipv6RouterAlertHopByHopOptionIdentifier), 0},
			err:   ErrMalformedIPv6ExtHdrOption,
		},
		{
			name:  "Router alert with partial data",
			bytes: []byte{byte(ipv6RouterAlertHopByHopOptionIdentifier), 1, 1},
			err:   ErrMalformedIPv6ExtHdrOption,
		},
		{
			name:  "Router alert with partial data and Pad1",
			bytes: []byte{byte(ipv6RouterAlertHopByHopOptionIdentifier), 1, 1, 0},
			err:   ErrMalformedIPv6ExtHdrOption,
		},
		{
			name:  "Router alert with extra data",
			bytes: []byte{byte(ipv6RouterAlertHopByHopOptionIdentifier), 3, 1, 2, 3},
			err:   ErrMalformedIPv6ExtHdrOption,
		},
		{
			name:  "Router alert with missing data",
			bytes: []byte{byte(ipv6RouterAlertHopByHopOptionIdentifier), 1},
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
				extHdr := IPv6HopByHopOptionsExtHdr{ipv6OptionsExtHdr{bufferv2.NewViewWithData(test.bytes)}}
				check(t, extHdr.Iter(), test.err)
			})

			t.Run("Destination", func(t *testing.T) {
				extHdr := IPv6DestinationOptionsExtHdr{ipv6OptionsExtHdr{bufferv2.NewViewWithData(test.bytes)}}
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
				&IPv6UnknownExtHdrOption{Identifier: 255, Data: bufferv2.NewViewWithData([]byte{})},
			},
		},
		{
			name:  "Single unknown with non-zero length",
			bytes: []byte{255, 3, 1, 2, 3},
			expected: []IPv6ExtHdrOption{
				&IPv6UnknownExtHdrOption{Identifier: 255, Data: bufferv2.NewViewWithData([]byte{1, 2, 3})},
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
				&IPv6UnknownExtHdrOption{Identifier: 255, Data: bufferv2.NewViewWithData([]byte{})},
				&IPv6UnknownExtHdrOption{Identifier: 254, Data: bufferv2.NewViewWithData([]byte{1})},
				&IPv6UnknownExtHdrOption{Identifier: 253, Data: bufferv2.NewViewWithData([]byte{2, 3, 4, 5})},
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
			if diff := cmp.Diff(e, opt, viewTransformer, bufferTransformer); diff != "" {
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
				extHdr := IPv6HopByHopOptionsExtHdr{ipv6OptionsExtHdr{bufferv2.NewViewWithData(test.bytes)}}
				checkIter(t, extHdr.Iter(), test.expected)
			})

			t.Run("Destination", func(t *testing.T) {
				extHdr := IPv6DestinationOptionsExtHdr{ipv6OptionsExtHdr{bufferv2.NewViewWithData(test.bytes)}}
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
			extHdr := IPv6RoutingExtHdr{bufferv2.NewViewWithData(test.bytes)}
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

func makeBufferFromByteBuffers(bs ...[]byte) bufferv2.Buffer {
	buf := bufferv2.Buffer{}
	for _, b := range bs {
		buf.Append(bufferv2.NewViewWithData(b))
	}
	return buf
}

func TestIPv6ExtHdrIterErr(t *testing.T) {
	tests := []struct {
		name         string
		firstNextHdr IPv6ExtensionHeaderIdentifier
		payload      bufferv2.Buffer
		err          error
	}{
		{
			name:         "Upper layer only without data",
			firstNextHdr: 255,
		},
		{
			name:         "Upper layer only with data",
			firstNextHdr: 255,
			payload:      bufferv2.MakeWithData([]byte{1, 2, 3, 4}),
		},
		{
			name:         "No next header",
			firstNextHdr: IPv6NoNextHeaderIdentifier,
		},
		{
			name:         "No next header with data",
			firstNextHdr: IPv6NoNextHeaderIdentifier,
			payload:      bufferv2.MakeWithData([]byte{1, 2, 3, 4}),
		},
		{
			name:         "Valid single hop by hop",
			firstNextHdr: IPv6HopByHopOptionsExtHdrIdentifier,
			payload:      bufferv2.MakeWithData([]byte{255, 0, 1, 4, 1, 2, 3, 4}),
		},
		{
			name:         "Hop by hop too small",
			firstNextHdr: IPv6HopByHopOptionsExtHdrIdentifier,
			payload:      bufferv2.MakeWithData([]byte{255, 0, 1, 4, 1, 2, 3}),
			err:          io.ErrUnexpectedEOF,
		},
		{
			name:         "Valid single fragment",
			firstNextHdr: IPv6FragmentExtHdrIdentifier,
			payload:      bufferv2.MakeWithData([]byte{255, 0, 68, 9, 128, 4, 2, 1}),
		},
		{
			name:         "Fragment too small",
			firstNextHdr: IPv6FragmentExtHdrIdentifier,
			payload:      bufferv2.MakeWithData([]byte{255, 0, 68, 9, 128, 4, 2}),
			err:          io.ErrUnexpectedEOF,
		},
		{
			name:         "Valid single destination",
			firstNextHdr: IPv6DestinationOptionsExtHdrIdentifier,
			payload:      bufferv2.MakeWithData([]byte{255, 0, 1, 4, 1, 2, 3, 4}),
		},
		{
			name:         "Destination too small",
			firstNextHdr: IPv6DestinationOptionsExtHdrIdentifier,
			payload:      bufferv2.MakeWithData([]byte{255, 0, 1, 4, 1, 2, 3}),
			err:          io.ErrUnexpectedEOF,
		},
		{
			name:         "Valid single routing",
			firstNextHdr: IPv6RoutingExtHdrIdentifier,
			payload:      bufferv2.MakeWithData([]byte{255, 0, 1, 2, 3, 4, 5, 6}),
		},
		{
			name:         "Valid single routing across views",
			firstNextHdr: IPv6RoutingExtHdrIdentifier,
			payload:      makeBufferFromByteBuffers([]byte{255, 0, 1, 2}, []byte{3, 4, 5, 6}),
		},
		{
			name:         "Routing too small with zero length field",
			firstNextHdr: IPv6RoutingExtHdrIdentifier,
			payload:      bufferv2.MakeWithData([]byte{255, 0, 1, 2, 3, 4, 5}),
			err:          io.ErrUnexpectedEOF,
		},
		{
			name:         "Valid routing with non-zero length field",
			firstNextHdr: IPv6RoutingExtHdrIdentifier,
			payload:      bufferv2.MakeWithData([]byte{255, 1, 1, 2, 3, 4, 5, 6, 1, 2, 3, 4, 5, 6, 7, 8}),
		},
		{
			name:         "Valid routing with non-zero length field across views",
			firstNextHdr: IPv6RoutingExtHdrIdentifier,
			payload:      makeBufferFromByteBuffers([]byte{255, 1, 1, 2, 3, 4, 5, 6}, []byte{1, 2, 3, 4, 5, 6, 7, 8}),
		},
		{
			name:         "Routing too small with non-zero length field",
			firstNextHdr: IPv6RoutingExtHdrIdentifier,
			payload:      bufferv2.MakeWithData([]byte{255, 1, 1, 2, 3, 4, 5, 6, 1, 2, 3, 4, 5, 6, 7}),
			err:          io.ErrUnexpectedEOF,
		},
		{
			name:         "Routing too small with non-zero length field across views",
			firstNextHdr: IPv6RoutingExtHdrIdentifier,
			payload:      makeBufferFromByteBuffers([]byte{255, 1, 1, 2, 3, 4, 5, 6}, []byte{1, 2, 3, 4, 5, 6, 7}),
			err:          io.ErrUnexpectedEOF,
		},
		{
			name:         "Mixed",
			firstNextHdr: IPv6HopByHopOptionsExtHdrIdentifier,
			payload: bufferv2.MakeWithData([]byte{
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
			payload: bufferv2.MakeWithData([]byte{
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
			payload: bufferv2.MakeWithData([]byte{
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
	routingExtHdrWithUpperLayerData := []byte{255, 0, 1, 2, 3, 4, 5, 6, 1, 2, 3, 4}
	upperLayerData := []byte{1, 2, 3, 4}
	tests := []struct {
		name         string
		firstNextHdr IPv6ExtensionHeaderIdentifier
		payload      bufferv2.Buffer
		expected     []IPv6PayloadHeader
	}{
		// With a non-atomic fragment that is not the first fragment, the payload
		// after the fragment will not be parsed because the payload is expected to
		// only hold upper layer data.
		{
			name:         "hopbyhop - fragment (not first) - routing - upper",
			firstNextHdr: IPv6HopByHopOptionsExtHdrIdentifier,
			payload: bufferv2.MakeWithData([]byte{
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
				IPv6HopByHopOptionsExtHdr{ipv6OptionsExtHdr{bufferv2.NewViewWithData([]byte{1, 4, 1, 2, 3, 4})}},
				IPv6FragmentExtHdr([6]byte{68, 9, 128, 4, 2, 1}),
				IPv6RawPayloadHeader{
					Identifier: IPv6RoutingExtHdrIdentifier,
					Buf:        bufferv2.MakeWithData(routingExtHdrWithUpperLayerData),
				},
			},
		},
		{
			name:         "hopbyhop - fragment (first) - routing - upper",
			firstNextHdr: IPv6HopByHopOptionsExtHdrIdentifier,
			payload: bufferv2.MakeWithData([]byte{
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
				IPv6HopByHopOptionsExtHdr{ipv6OptionsExtHdr{bufferv2.NewViewWithData([]byte{1, 4, 1, 2, 3, 4})}},
				IPv6FragmentExtHdr([6]byte{0, 1, 128, 4, 2, 1}),
				IPv6RoutingExtHdr{bufferv2.NewViewWithData([]byte{1, 2, 3, 4, 5, 6})},
				IPv6RawPayloadHeader{
					Identifier: 255,
					Buf:        bufferv2.MakeWithData(upperLayerData),
				},
			},
		},
		{
			name:         "fragment - routing - upper (across views)",
			firstNextHdr: IPv6FragmentExtHdrIdentifier,
			payload: makeBufferFromByteBuffers([]byte{
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
					Buf:        bufferv2.MakeWithData(routingExtHdrWithUpperLayerData),
				},
			},
		},

		// If we have an atomic fragment, the payload following the fragment
		// extension header should be parsed normally.
		{
			name:         "atomic fragment - routing - destination - upper",
			firstNextHdr: IPv6FragmentExtHdrIdentifier,
			payload: bufferv2.MakeWithData([]byte{
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
				IPv6RoutingExtHdr{bufferv2.NewViewWithData([]byte{1, 2, 3, 4, 5, 6})},
				IPv6DestinationOptionsExtHdr{ipv6OptionsExtHdr{bufferv2.NewViewWithData([]byte{1, 4, 1, 2, 3, 4})}},
				IPv6RawPayloadHeader{
					Identifier: 255,
					Buf:        bufferv2.MakeWithData(upperLayerData),
				},
			},
		},
		{
			name:         "atomic fragment - routing - upper (across views)",
			firstNextHdr: IPv6FragmentExtHdrIdentifier,
			payload: makeBufferFromByteBuffers([]byte{
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
				IPv6RoutingExtHdr{bufferv2.NewViewWithData([]byte{1, 2, 3, 4, 5, 6})},
				IPv6RawPayloadHeader{
					Identifier: 255,
					Buf:        makeBufferFromByteBuffers(upperLayerData[:2], upperLayerData[2:]),
				},
			},
		},
		{
			name:         "atomic fragment - destination - no next header",
			firstNextHdr: IPv6FragmentExtHdrIdentifier,
			payload: bufferv2.MakeWithData([]byte{
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
				IPv6DestinationOptionsExtHdr{ipv6OptionsExtHdr{bufferv2.NewViewWithData([]byte{1, 4, 1, 2, 3, 4})}},
			},
		},
		{
			name:         "routing - atomic fragment - no next header",
			firstNextHdr: IPv6RoutingExtHdrIdentifier,
			payload: bufferv2.MakeWithData([]byte{
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
				IPv6RoutingExtHdr{bufferv2.NewViewWithData([]byte{1, 2, 3, 4, 5, 6})},
				IPv6FragmentExtHdr([6]byte{0, 6, 128, 4, 2, 1}),
			},
		},
		{
			name:         "routing - atomic fragment - no next header (across views)",
			firstNextHdr: IPv6RoutingExtHdrIdentifier,
			payload: makeBufferFromByteBuffers([]byte{
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
				IPv6RoutingExtHdr{bufferv2.NewViewWithData([]byte{1, 2, 3, 4, 5, 6})},
				IPv6FragmentExtHdr([6]byte{0, 6, 128, 4, 2, 1}),
			},
		},
		{
			name:         "hopbyhop - routing - fragment - no next header",
			firstNextHdr: IPv6HopByHopOptionsExtHdrIdentifier,
			payload: bufferv2.MakeWithData([]byte{
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
				IPv6HopByHopOptionsExtHdr{ipv6OptionsExtHdr{bufferv2.NewViewWithData([]byte{1, 4, 1, 2, 3, 4})}},
				IPv6RoutingExtHdr{bufferv2.NewViewWithData([]byte{1, 2, 3, 4, 5, 6})},
				IPv6FragmentExtHdr([6]byte{1, 6, 128, 4, 2, 1}),
				IPv6RawPayloadHeader{
					Identifier: IPv6NoNextHeaderIdentifier,
					Buf:        bufferv2.MakeWithData(upperLayerData),
				},
			},
		},

		// Test the raw payload for common transport layer protocol numbers.
		{
			name:         "TCP raw payload",
			firstNextHdr: IPv6ExtensionHeaderIdentifier(TCPProtocolNumber),
			payload:      bufferv2.MakeWithData(upperLayerData),
			expected: []IPv6PayloadHeader{IPv6RawPayloadHeader{
				Identifier: IPv6ExtensionHeaderIdentifier(TCPProtocolNumber),
				Buf:        bufferv2.MakeWithData(upperLayerData),
			}},
		},
		{
			name:         "UDP raw payload",
			firstNextHdr: IPv6ExtensionHeaderIdentifier(UDPProtocolNumber),
			payload:      bufferv2.MakeWithData(upperLayerData),
			expected: []IPv6PayloadHeader{IPv6RawPayloadHeader{
				Identifier: IPv6ExtensionHeaderIdentifier(UDPProtocolNumber),
				Buf:        bufferv2.MakeWithData(upperLayerData),
			}},
		},
		{
			name:         "ICMPv4 raw payload",
			firstNextHdr: IPv6ExtensionHeaderIdentifier(ICMPv4ProtocolNumber),
			payload:      bufferv2.MakeWithData(upperLayerData),
			expected: []IPv6PayloadHeader{IPv6RawPayloadHeader{
				Identifier: IPv6ExtensionHeaderIdentifier(ICMPv4ProtocolNumber),
				Buf:        bufferv2.MakeWithData(upperLayerData),
			}},
		},
		{
			name:         "ICMPv6 raw payload",
			firstNextHdr: IPv6ExtensionHeaderIdentifier(ICMPv6ProtocolNumber),
			payload:      bufferv2.MakeWithData(upperLayerData),
			expected: []IPv6PayloadHeader{IPv6RawPayloadHeader{
				Identifier: IPv6ExtensionHeaderIdentifier(ICMPv6ProtocolNumber),
				Buf:        bufferv2.MakeWithData(upperLayerData),
			}},
		},
		{
			name:         "Unknwon next header raw payload",
			firstNextHdr: 255,
			payload:      bufferv2.MakeWithData(upperLayerData),
			expected: []IPv6PayloadHeader{IPv6RawPayloadHeader{
				Identifier: 255,
				Buf:        bufferv2.MakeWithData(upperLayerData),
			}},
		},
		{
			name:         "Unknwon next header raw payload (across views)",
			firstNextHdr: 255,
			payload:      makeBufferFromByteBuffers(upperLayerData[:2], upperLayerData[2:]),
			expected: []IPv6PayloadHeader{IPv6RawPayloadHeader{
				Identifier: 255,
				Buf:        makeBufferFromByteBuffers(upperLayerData[:2], upperLayerData[2:]),
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
				if diff := cmp.Diff(e, extHdr, viewTransformer, bufferTransformer); diff != "" {
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

var _ IPv6SerializableHopByHopOption = (*dummyHbHOptionSerializer)(nil)

// dummyHbHOptionSerializer provides a generic implementation of
// IPv6SerializableHopByHopOption for use in tests.
type dummyHbHOptionSerializer struct {
	id          IPv6ExtHdrOptionIdentifier
	payload     *bufferv2.View
	align       int
	alignOffset int
}

// identifier implements IPv6SerializableHopByHopOption.
func (s *dummyHbHOptionSerializer) identifier() IPv6ExtHdrOptionIdentifier {
	return s.id
}

// length implements IPv6SerializableHopByHopOption.
func (s *dummyHbHOptionSerializer) length() uint8 {
	return uint8(s.payload.Size())
}

// alignment implements IPv6SerializableHopByHopOption.
func (s *dummyHbHOptionSerializer) alignment() (int, int) {
	align := 1
	if s.align != 0 {
		align = s.align
	}
	return align, s.alignOffset
}

// serializeInto implements IPv6SerializableHopByHopOption.
func (s *dummyHbHOptionSerializer) serializeInto(b []byte) uint8 {
	return uint8(copy(b, s.payload.AsSlice()))
}

func TestIPv6HopByHopSerializer(t *testing.T) {
	validateDummies := func(t *testing.T, serializable IPv6SerializableHopByHopOption, deserialized IPv6ExtHdrOption) {
		t.Helper()
		dummy, ok := serializable.(*dummyHbHOptionSerializer)
		if !ok {
			t.Fatalf("got serializable = %T, want = *dummyHbHOptionSerializer", serializable)
		}
		unknown, ok := deserialized.(*IPv6UnknownExtHdrOption)
		if !ok {
			t.Fatalf("got deserialized = %T, want = %T", deserialized, &IPv6UnknownExtHdrOption{})
		}
		if dummy.id != unknown.Identifier {
			t.Errorf("got deserialized identifier = %d, want = %d", unknown.Identifier, dummy.id)
		}
		if diff := cmp.Diff(dummy.payload, unknown.Data, viewTransformer, bufferTransformer); diff != "" {
			t.Errorf("option payload deserialization mismatch (-want +got):\n%s", diff)
		}
	}
	tests := []struct {
		name       string
		nextHeader uint8
		options    []IPv6SerializableHopByHopOption
		expect     []byte
		validate   func(*testing.T, IPv6SerializableHopByHopOption, IPv6ExtHdrOption)
	}{
		{
			name:       "single option",
			nextHeader: 13,
			options: []IPv6SerializableHopByHopOption{
				&dummyHbHOptionSerializer{
					id:      15,
					payload: bufferv2.NewViewWithData([]byte{9, 8, 7, 6}),
				},
			},
			expect:   []byte{13, 0, 15, 4, 9, 8, 7, 6},
			validate: validateDummies,
		},
		{
			name:       "short option padN zero",
			nextHeader: 88,
			options: []IPv6SerializableHopByHopOption{
				&dummyHbHOptionSerializer{
					id:      22,
					payload: bufferv2.NewViewWithData([]byte{4, 5}),
				},
			},
			expect:   []byte{88, 0, 22, 2, 4, 5, 1, 0},
			validate: validateDummies,
		},
		{
			name:       "short option pad1",
			nextHeader: 11,
			options: []IPv6SerializableHopByHopOption{
				&dummyHbHOptionSerializer{
					id:      33,
					payload: bufferv2.NewViewWithData([]byte{1, 2, 3}),
				},
			},
			expect:   []byte{11, 0, 33, 3, 1, 2, 3, 0},
			validate: validateDummies,
		},
		{
			name:       "long option padN",
			nextHeader: 55,
			options: []IPv6SerializableHopByHopOption{
				&dummyHbHOptionSerializer{
					id:      77,
					payload: bufferv2.NewViewWithData([]byte{1, 2, 3, 4, 5, 6, 7, 8}),
				},
			},
			expect:   []byte{55, 1, 77, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 0, 0},
			validate: validateDummies,
		},
		{
			name:       "two options",
			nextHeader: 33,
			options: []IPv6SerializableHopByHopOption{
				&dummyHbHOptionSerializer{
					id:      11,
					payload: bufferv2.NewViewWithData([]byte{1, 2, 3}),
				},
				&dummyHbHOptionSerializer{
					id:      22,
					payload: bufferv2.NewViewWithData([]byte{4, 5, 6}),
				},
			},
			expect:   []byte{33, 1, 11, 3, 1, 2, 3, 22, 3, 4, 5, 6, 1, 2, 0, 0},
			validate: validateDummies,
		},
		{
			name:       "two options align 2n",
			nextHeader: 33,
			options: []IPv6SerializableHopByHopOption{
				&dummyHbHOptionSerializer{
					id:      11,
					payload: bufferv2.NewViewWithData([]byte{1, 2, 3}),
				},
				&dummyHbHOptionSerializer{
					id:      22,
					payload: bufferv2.NewViewWithData([]byte{4, 5, 6}),
					align:   2,
				},
			},
			expect:   []byte{33, 1, 11, 3, 1, 2, 3, 0, 22, 3, 4, 5, 6, 1, 1, 0},
			validate: validateDummies,
		},
		{
			name:       "two options align 8n+1",
			nextHeader: 33,
			options: []IPv6SerializableHopByHopOption{
				&dummyHbHOptionSerializer{
					id:      11,
					payload: bufferv2.NewViewWithData([]byte{1, 2}),
				},
				&dummyHbHOptionSerializer{
					id:          22,
					payload:     bufferv2.NewViewWithData([]byte{4, 5, 6}),
					align:       8,
					alignOffset: 1,
				},
			},
			expect:   []byte{33, 1, 11, 2, 1, 2, 1, 1, 0, 22, 3, 4, 5, 6, 1, 0},
			validate: validateDummies,
		},
		{
			name:       "no options",
			nextHeader: 33,
			options:    []IPv6SerializableHopByHopOption{},
			expect:     []byte{33, 0, 1, 4, 0, 0, 0, 0},
		},
		{
			name:       "Router Alert",
			nextHeader: 33,
			options:    []IPv6SerializableHopByHopOption{&IPv6RouterAlertOption{Value: IPv6RouterAlertMLD}},
			expect:     []byte{33, 0, 5, 2, 0, 0, 1, 0},
			validate: func(t *testing.T, _ IPv6SerializableHopByHopOption, deserialized IPv6ExtHdrOption) {
				t.Helper()
				routerAlert, ok := deserialized.(*IPv6RouterAlertOption)
				if !ok {
					t.Fatalf("got deserialized = %T, want = *IPv6RouterAlertOption", deserialized)
				}
				if routerAlert.Value != IPv6RouterAlertMLD {
					t.Errorf("got routerAlert.Value = %d, want = %d", routerAlert.Value, IPv6RouterAlertMLD)
				}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s := IPv6SerializableHopByHopExtHdr(test.options)
			length := s.length()
			if length != len(test.expect) {
				t.Fatalf("got s.length() = %d, want = %d", length, len(test.expect))
			}
			b := make([]byte, length)
			for i := range b {
				// Fill the buffer with ones to ensure all padding is correctly set.
				b[i] = 0xFF
			}
			if got := s.serializeInto(test.nextHeader, b); got != length {
				t.Fatalf("got s.serializeInto(..) = %d, want = %d", got, length)
			}
			if diff := cmp.Diff(test.expect, b); diff != "" {
				t.Fatalf("serialization mismatch (-want +got):\n%s", diff)
			}

			// Deserialize the options and verify them.
			optLen := (b[ipv6HopByHopExtHdrLengthOffset] + ipv6HopByHopExtHdrUnaccountedLenWords) * ipv6ExtHdrLenBytesPerUnit
			iter := ipv6OptionsExtHdr{bufferv2.NewViewWithData(b[ipv6HopByHopExtHdrOptionsOffset:optLen])}.Iter()
			for _, testOpt := range test.options {
				opt, done, err := iter.Next()
				if err != nil {
					t.Fatalf("iter.Next(): %s", err)
				}
				if done {
					t.Fatalf("got iter.Next() = (%T, %t, _), want = (_, false, _)", opt, done)
				}
				test.validate(t, testOpt, opt)
			}
			opt, done, err := iter.Next()
			if err != nil {
				t.Fatalf("iter.Next(): %s", err)
			}
			if !done {
				t.Fatalf("got iter.Next() = (%T, %t, _), want = (_, true, _)", opt, done)
			}
		})
	}
}

var _ IPv6SerializableExtHdr = (*dummyIPv6ExtHdrSerializer)(nil)

// dummyIPv6ExtHdrSerializer provides a generic implementation of
// IPv6SerializableExtHdr for use in tests.
//
// The dummy header always carries the nextHeader value in the first byte.
type dummyIPv6ExtHdrSerializer struct {
	id             IPv6ExtensionHeaderIdentifier
	headerContents []byte
}

// identifier implements IPv6SerializableExtHdr.
func (s *dummyIPv6ExtHdrSerializer) identifier() IPv6ExtensionHeaderIdentifier {
	return s.id
}

// length implements IPv6SerializableExtHdr.
func (s *dummyIPv6ExtHdrSerializer) length() int {
	return len(s.headerContents) + 1
}

// serializeInto implements IPv6SerializableExtHdr.
func (s *dummyIPv6ExtHdrSerializer) serializeInto(nextHeader uint8, b []byte) int {
	b[0] = nextHeader
	return copy(b[1:], s.headerContents) + 1
}

func TestIPv6ExtHdrSerializer(t *testing.T) {
	tests := []struct {
		name             string
		headers          []IPv6SerializableExtHdr
		nextHeader       tcpip.TransportProtocolNumber
		expectSerialized []byte
		expectNextHeader uint8
	}{
		{
			name: "one header",
			headers: []IPv6SerializableExtHdr{
				&dummyIPv6ExtHdrSerializer{
					id:             15,
					headerContents: []byte{1, 2, 3, 4},
				},
			},
			nextHeader:       TCPProtocolNumber,
			expectSerialized: []byte{byte(TCPProtocolNumber), 1, 2, 3, 4},
			expectNextHeader: 15,
		},
		{
			name: "two headers",
			headers: []IPv6SerializableExtHdr{
				&dummyIPv6ExtHdrSerializer{
					id:             22,
					headerContents: []byte{1, 2, 3},
				},
				&dummyIPv6ExtHdrSerializer{
					id:             23,
					headerContents: []byte{4, 5, 6},
				},
			},
			nextHeader: ICMPv6ProtocolNumber,
			expectSerialized: []byte{
				23, 1, 2, 3,
				byte(ICMPv6ProtocolNumber), 4, 5, 6,
			},
			expectNextHeader: 22,
		},
		{
			name:             "no headers",
			headers:          []IPv6SerializableExtHdr{},
			nextHeader:       UDPProtocolNumber,
			expectSerialized: []byte{},
			expectNextHeader: byte(UDPProtocolNumber),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s := IPv6ExtHdrSerializer(test.headers)
			l := s.Length()
			if got, want := l, len(test.expectSerialized); got != want {
				t.Fatalf("got serialized length = %d, want = %d", got, want)
			}
			b := make([]byte, l)
			for i := range b {
				// Fill the buffer with garbage to make sure we're writing to all bytes.
				b[i] = 0xFF
			}
			nextHeader, serializedLen := s.Serialize(test.nextHeader, b)
			if serializedLen != len(test.expectSerialized) || nextHeader != test.expectNextHeader {
				t.Errorf(
					"got s.Serialize(..) = (%d, %d), want = (%d, %d)",
					nextHeader,
					serializedLen,
					test.expectNextHeader,
					len(test.expectSerialized),
				)
			}
			if diff := cmp.Diff(test.expectSerialized, b); diff != "" {
				t.Errorf("serialization mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

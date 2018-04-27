// Copyright 2016 The Netstack Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package header

const (
	typeHLen   = 0
	encapProto = 1
)

// GUEFields contains the fields of a GUE packet. It is used to describe the
// fields of a packet that needs to be encoded.
type GUEFields struct {
	// Type is the "type" field of the GUE header.
	Type uint8

	// Control is the "control" field of the GUE header.
	Control bool

	// HeaderLength is the "header length" field of the GUE header. It must
	// be at least 4 octets, and a multiple of 4 as well.
	HeaderLength uint8

	// Protocol is the "protocol" field of the GUE header. This is one of
	// the IPPROTO_* values.
	Protocol uint8
}

// GUE represents a Generic UDP Encapsulation header stored in a byte array, the
// fields are described in https://tools.ietf.org/html/draft-ietf-nvo3-gue-01.
type GUE []byte

const (
	// GUEMinimumSize is the minimum size of a valid GUE packet.
	GUEMinimumSize = 4
)

// TypeAndControl returns the GUE packet type (top 3 bits of the first byte,
// which includes the control bit).
func (b GUE) TypeAndControl() uint8 {
	return b[typeHLen] >> 5
}

// HeaderLength returns the total length of the GUE header.
func (b GUE) HeaderLength() uint8 {
	return 4 + 4*(b[typeHLen]&0x1f)
}

// Protocol returns the protocol field of the GUE header.
func (b GUE) Protocol() uint8 {
	return b[encapProto]
}

// Encode encodes all the fields of the GUE header.
func (b GUE) Encode(i *GUEFields) {
	ctl := uint8(0)
	if i.Control {
		ctl = 1 << 5
	}
	b[typeHLen] = ctl | i.Type<<6 | (i.HeaderLength-4)/4
	b[encapProto] = i.Protocol
}

// Copyright 2016 The Netstack Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package header_test

import (
	"testing"

	"gvisor.googlesource.com/gvisor/pkg/tcpip/header"
)

func TestIPv4(t *testing.T) {
	b := header.IPv4(make([]byte, header.IPv4MinimumSize))
	b.Encode(&header.IPv4Fields{})

	const want = header.IPv4Version
	if v := header.IPVersion(b); v != want {
		t.Fatalf("Bad version, want %v, got %v", want, v)
	}
}

func TestIPv6(t *testing.T) {
	b := header.IPv6(make([]byte, header.IPv6MinimumSize))
	b.Encode(&header.IPv6Fields{})

	const want = header.IPv6Version
	if v := header.IPVersion(b); v != want {
		t.Fatalf("Bad version, want %v, got %v", want, v)
	}
}

func TestOtherVersion(t *testing.T) {
	const want = header.IPv4Version + header.IPv6Version
	b := make([]byte, 1)
	b[0] = want << 4

	if v := header.IPVersion(b); v != want {
		t.Fatalf("Bad version, want %v, got %v", want, v)
	}
}

func TestTooShort(t *testing.T) {
	b := make([]byte, 1)
	b[0] = (header.IPv4Version + header.IPv6Version) << 4

	// Get the version of a zero-length slice.
	const want = -1
	if v := header.IPVersion(b[:0]); v != want {
		t.Fatalf("Bad version, want %v, got %v", want, v)
	}

	// Get the version of a nil slice.
	if v := header.IPVersion(nil); v != want {
		t.Fatalf("Bad version, want %v, got %v", want, v)
	}
}

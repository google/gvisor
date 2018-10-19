// Copyright 2018 Google LLC
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

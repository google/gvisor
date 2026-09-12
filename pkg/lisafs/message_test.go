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

package lisafs

import (
	"math"
	"strings"
	"testing"
)

func TestSizedStringLengthBoundaries(t *testing.T) {
	// 1. Normal string below 65535.
	small := SizedString("hello world")
	if want := 2 + len(small); small.SizeBytes() != want {
		t.Errorf("small.SizeBytes() = %d, want %d", small.SizeBytes(), want)
	}

	// 2. Exact uint16 boundary (65535 bytes).
	str65535 := SizedString(strings.Repeat("A", math.MaxUint16))
	if want := 2 + math.MaxUint16; str65535.SizeBytes() != want {
		t.Errorf("str65535.SizeBytes() = %d, want %d", str65535.SizeBytes(), want)
	}
	buf65535 := make([]byte, str65535.SizeBytes())
	str65535.MarshalBytes(buf65535)
	var unmarshaled65535 SizedString
	remain, ok := unmarshaled65535.CheckedUnmarshal(buf65535)
	if !ok || len(remain) != 0 || len(unmarshaled65535) != math.MaxUint16 {
		t.Errorf("unmarshaled65535 failed: ok=%v, len=%d, want=%d", ok, len(unmarshaled65535), math.MaxUint16)
	}

	// 3. Exact 65536 bytes (XATTR_SIZE_MAX).
	// Must be clamped to math.MaxUint16 and must NOT wrap to 0.
	str65536 := SizedString(strings.Repeat("B", 65536))
	if want := 2 + math.MaxUint16; str65536.SizeBytes() != want {
		t.Errorf("str65536.SizeBytes() = %d, want %d (must not wrap)", str65536.SizeBytes(), want)
	}
	buf65536 := make([]byte, str65536.SizeBytes())
	str65536.MarshalBytes(buf65536)
	var unmarshaled65536 SizedString
	remain, ok = unmarshaled65536.CheckedUnmarshal(buf65536)
	if !ok || len(remain) != 0 {
		t.Errorf("unmarshaled65536 CheckedUnmarshal failed: ok=%v, remain=%d", ok, len(remain))
	}
	if len(unmarshaled65536) == 0 {
		t.Errorf("str65536 wrapped to empty string (len=0)!")
	}
	if len(unmarshaled65536) != math.MaxUint16 {
		t.Errorf("len(unmarshaled65536) = %d, want %d", len(unmarshaled65536), math.MaxUint16)
	}
}

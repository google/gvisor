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

package hostarch

import (
	"runtime"
	"testing"
)

func TestEndianString(t *testing.T) {
	got := EndianString()
	switch runtime.GOARCH {
	case "386", "amd64", "arm", "arm64", "mipsle", "mips64le", "ppc64le", "riscv64", "wasm":
		if got != "little" {
			t.Errorf("got %s, want little", got)
		}
	case "armbe", "arm64be", "mips", "mips64", "ppc64", "s390x":
		if got != "big" {
			t.Errorf("got %s, want big", got)
		}
	default:
		// Unknown GOARCH, unknown endianness; at least EndianString() didn't
		// panic.
		t.Logf("GOARCH %v is %s-endian", runtime.GOARCH, got)
	}
}

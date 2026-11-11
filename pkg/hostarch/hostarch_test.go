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

func TestCheckHostPageSize(t *testing.T) {
	if err := CheckHostPageSize(); err != nil {
		t.Errorf("CheckHostPageSize() = %v, want nil", err)
	}
}

func TestCheckPageSize(t *testing.T) {
	const (
		size4K  = 4 << 10
		size16K = 16 << 10
		size64K = 64 << 10
	)
	// arm64 supports 4K and 64K pages, and x86 only 4K pages.
	supports64K := runtime.GOARCH == "arm64"
	for _, test := range []struct {
		hostPageSize int
		pageSize     int
		wantErr      bool
	}{
		{hostPageSize: size4K, pageSize: size4K, wantErr: false},
		{hostPageSize: size64K, pageSize: size64K, wantErr: !supports64K},
		// The host page size differs from the page size in use.
		{hostPageSize: size4K, pageSize: size64K, wantErr: true},
		{hostPageSize: size64K, pageSize: size4K, wantErr: true},
		// Unsupported page sizes.
		{hostPageSize: size16K, pageSize: size16K, wantErr: true},
		{hostPageSize: 0, pageSize: 0, wantErr: true},
		{hostPageSize: size4K + 1, pageSize: size4K + 1, wantErr: true},
	} {
		if err := checkPageSize(test.hostPageSize, test.pageSize); (err != nil) != test.wantErr {
			t.Errorf("checkPageSize(%d, %d) = %v, want error: %t", test.hostPageSize, test.pageSize, err, test.wantErr)
		}
	}
}

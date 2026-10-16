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

//go:build arm64

package sysmsg

import (
	"fmt"
	"testing"
	"unsafe"

	"gvisor.dev/gvisor/pkg/hostarch"
)

func TestThreadMemLayout(t *testing.T) {
	for _, test := range []struct {
		pageSize uintptr
		want     threadMemLayout
	}{
		{
			// These match the layout that was used by 4K-only builds.
			pageSize: 4 << 10,
			want: threadMemLayout{
				memSize:                  32 << 10,
				guardSize:                4 << 10,
				privateStackOffset:       4 << 10,
				privateStackSize:         8 << 10,
				sharedStackSize:          16 << 10,
				sharedStackOffset:        16 << 10,
				msgOffsetFromSharedStack: 12 << 10,
			},
		},
		{
			// These match the layout that was used by 64K-only builds.
			pageSize: 64 << 10,
			want: threadMemLayout{
				memSize:                  320 << 10,
				guardSize:                64 << 10,
				privateStackOffset:       64 << 10,
				privateStackSize:         64 << 10,
				sharedStackSize:          128 << 10,
				sharedStackOffset:        192 << 10,
				msgOffsetFromSharedStack: 64 << 10,
			},
		},
	} {
		t.Run(fmt.Sprintf("%dK", test.pageSize>>10), func(t *testing.T) {
			l := newThreadMemLayout(test.pageSize)
			if l != test.want {
				t.Errorf("newThreadMemLayout(%#x) = %+v, want %+v", test.pageSize, l, test.want)
			}
			// All regions must be page-aligned, and there must be a guard page
			// between the private and the shared stacks.
			for _, v := range []uintptr{l.memSize, l.guardSize, l.privateStackOffset, l.privateStackSize, l.sharedStackSize, l.sharedStackOffset} {
				if v%test.pageSize != 0 {
					t.Errorf("layout %+v is not page-aligned", l)
				}
			}
			if l.privateStackOffset+l.privateStackSize+test.pageSize > l.sharedStackOffset {
				t.Errorf("layout %+v has no guard page between the private and shared stacks", l)
			}
			// Msg must fit in the last page of the shared stack region, as
			// expected by the stub (see sysmsg.h:MSG_OFFSET_FROM_START).
			if got, want := l.sharedStackOffset+l.msgOffsetFromSharedStack, l.memSize-test.pageSize; got != want {
				t.Errorf("Msg offset from start = %#x, want %#x", got, want)
			}
			if unsafe.Sizeof(Msg{}) > test.pageSize {
				t.Errorf("Msg (%d bytes) doesn't fit in a page", unsafe.Sizeof(Msg{}))
			}
		})
	}
}

func TestHostThreadMemLayout(t *testing.T) {
	if got, want := layout, newThreadMemLayout(hostarch.PageSize); got != want {
		t.Errorf("layout = %+v, want %+v", got, want)
	}
	if PerThreadMemSize != layout.memSize || MsgOffsetFromSharedStack != layout.msgOffsetFromSharedStack || PerThreadSharedStackOffset != layout.sharedStackOffset {
		t.Errorf("exported layout doesn't match layout %+v", layout)
	}
}

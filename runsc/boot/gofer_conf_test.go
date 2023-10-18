// Copyright 2023 The gVisor Authors.
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

package boot

import (
	"testing"
)

func TestGoferConf(t *testing.T) {
	tcs := []struct {
		ovl          GoferMountConf
		wantOverlay  bool
		wantHostFile bool
		wantLisafs   bool
	}{{
		ovl:          VanillaGofer,
		wantOverlay:  false,
		wantHostFile: false,
		wantLisafs:   true,
	}, {
		ovl:          MemoryOverlay,
		wantOverlay:  true,
		wantHostFile: false,
		wantLisafs:   true,
	}, {
		ovl:          SelfOverlay,
		wantOverlay:  true,
		wantHostFile: true,
		wantLisafs:   true,
	}, {
		ovl:          AnonOverlay,
		wantOverlay:  true,
		wantHostFile: true,
		wantLisafs:   true,
	}, {
		ovl:          SelfTmpfs,
		wantOverlay:  false,
		wantHostFile: true,
		wantLisafs:   false,
	}}
	for _, tc := range tcs {
		if got := tc.ovl.ShouldUseOverlayfs(); got != tc.wantOverlay {
			t.Errorf("gofer conf = %d, ShouldUseOverlayfs() = %t, want = %t", tc.ovl, got, tc.wantOverlay)
		}
		if got := tc.ovl.IsFilestorePresent(); got != tc.wantHostFile {
			t.Errorf("gofer conf = %d, IsFilestorePresent() = %t, want = %t", tc.ovl, got, tc.wantHostFile)
		}
		if got := tc.ovl.ShouldUseLisafs(); got != tc.wantLisafs {
			t.Errorf("gofer conf = %d, ShouldUseLisafs() = %t, want = %t", tc.ovl, got, tc.wantLisafs)
		}
	}
}

func TestGoferConfFlags(t *testing.T) {
	want := GoferMountConfFlags{VanillaGofer, MemoryOverlay, SelfOverlay, AnonOverlay, SelfTmpfs}
	var got GoferMountConfFlags
	got.Set(want.String())
	if len(got) != len(want) {
		t.Fatalf("gofer conf flags is incorrect length: want = %d, got = %d", len(want), len(got))
	}
	for i := range want {
		if want[i] != got[i] {
			t.Errorf("gofer conf is incorrect: want = %d, got = %d", want[i], got[i])
		}
	}
}

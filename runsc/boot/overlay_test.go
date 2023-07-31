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

func TestOverlayMedium(t *testing.T) {
	tcs := []struct {
		ovl          OverlayMedium
		wantEnabled  bool
		wantHostFile bool
	}{{
		ovl:          NoOverlay,
		wantEnabled:  false,
		wantHostFile: false,
	}, {
		ovl:          MemoryMedium,
		wantEnabled:  true,
		wantHostFile: false,
	}, {
		ovl:          SelfMedium,
		wantEnabled:  true,
		wantHostFile: true,
	}, {
		ovl:          AnonDirMedium,
		wantEnabled:  true,
		wantHostFile: true,
	}}
	for _, tc := range tcs {
		if got := tc.ovl.IsEnabled(); got != tc.wantEnabled {
			t.Errorf("overlay medium = %d, IsEnabled() = %t, want = %t", tc.ovl, got, tc.wantEnabled)
		}
		if got := tc.ovl.IsBackedByHostFile(); got != tc.wantHostFile {
			t.Errorf("overlay medium = %d, IsBackedByHostFile() = %t, want = %t", tc.ovl, got, tc.wantHostFile)
		}
	}
}

func TestOverlayMediumFlags(t *testing.T) {
	want := OverlayMediumFlags{MemoryMedium, SelfMedium, AnonDirMedium, NoOverlay}
	var got OverlayMediumFlags
	got.Set(want.String())
	if len(got) != len(want) {
		t.Fatalf("overlay medium flags is incorrect length: want = %d, got = %d", len(want), len(got))
	}
	for i := range want {
		if want[i] != got[i] {
			t.Errorf("overlay medium is incorrect: want = %d, got = %d", want[i], got[i])
		}
	}
}

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
		cfg          GoferMountConf
		wantOverlay  bool
		wantHostFile bool
		wantLisafs   bool
		wantTmpfs    bool
		wantErofs    bool
		wantValid    bool
	}{{
		cfg: GoferMountConf{Lower: NoneLower, Upper: NoOverlay},
		// This is not a valid config.
		wantValid: false,
	}, {
		cfg:          GoferMountConf{Lower: NoneLower, Upper: MemoryOverlay},
		wantOverlay:  false,
		wantHostFile: false,
		wantLisafs:   false,
		wantTmpfs:    true,
		wantErofs:    false,
		wantValid:    true,
	}, {
		cfg:          GoferMountConf{Lower: NoneLower, Upper: SelfOverlay},
		wantOverlay:  false,
		wantHostFile: true,
		wantLisafs:   false,
		wantTmpfs:    true,
		wantErofs:    false,
		wantValid:    true,
	}, {
		cfg:          GoferMountConf{Lower: NoneLower, Upper: AnonOverlay},
		wantOverlay:  false,
		wantHostFile: true,
		wantLisafs:   false,
		wantTmpfs:    true,
		wantErofs:    false,
		wantValid:    true,
	}, {
		cfg:          GoferMountConf{Lower: Lisafs, Upper: NoOverlay},
		wantOverlay:  false,
		wantHostFile: false,
		wantLisafs:   true,
		wantTmpfs:    false,
		wantErofs:    false,
		wantValid:    true,
	}, {
		cfg:          GoferMountConf{Lower: Lisafs, Upper: MemoryOverlay},
		wantOverlay:  true,
		wantHostFile: false,
		wantLisafs:   true,
		wantTmpfs:    false,
		wantErofs:    false,
		wantValid:    true,
	}, {
		cfg:          GoferMountConf{Lower: Lisafs, Upper: SelfOverlay},
		wantOverlay:  true,
		wantHostFile: true,
		wantLisafs:   true,
		wantTmpfs:    false,
		wantErofs:    false,
		wantValid:    true,
	}, {
		cfg:          GoferMountConf{Lower: Lisafs, Upper: AnonOverlay},
		wantOverlay:  true,
		wantHostFile: true,
		wantLisafs:   true,
		wantTmpfs:    false,
		wantErofs:    false,
		wantValid:    true,
	}, {
		cfg:          GoferMountConf{Lower: Erofs, Upper: NoOverlay},
		wantOverlay:  false,
		wantHostFile: false,
		wantLisafs:   false,
		wantTmpfs:    false,
		wantErofs:    true,
		wantValid:    true,
	}, {
		cfg:          GoferMountConf{Lower: Erofs, Upper: MemoryOverlay},
		wantOverlay:  true,
		wantHostFile: false,
		wantLisafs:   false,
		wantTmpfs:    false,
		wantErofs:    true,
		wantValid:    true,
	}, {
		cfg:          GoferMountConf{Lower: Erofs, Upper: SelfOverlay},
		wantOverlay:  true,
		wantHostFile: true,
		wantLisafs:   false,
		wantTmpfs:    false,
		wantErofs:    true,
		wantValid:    true,
	}, {
		cfg:          GoferMountConf{Lower: Erofs, Upper: AnonOverlay},
		wantOverlay:  true,
		wantHostFile: true,
		wantLisafs:   false,
		wantTmpfs:    false,
		wantErofs:    true,
		wantValid:    true,
	}, {
		cfg: GoferMountConf{Lower: LowerMax, Upper: UpperMax},
		// This is not a valid config.
		wantValid: false,
	}}
	for _, tc := range tcs {
		if got := tc.cfg.valid(); got != tc.wantValid {
			t.Errorf("gofer conf = %+v, valid() = %t, want = %t", tc.cfg, got, tc.wantValid)
		}
		if !tc.wantValid {
			// Skip the following tests, if this is not a valid config.
			continue
		}
		if got := tc.cfg.ShouldUseOverlayfs(); got != tc.wantOverlay {
			t.Errorf("gofer conf = %+v, ShouldUseOverlayfs() = %t, want = %t", tc.cfg, got, tc.wantOverlay)
		}
		if got := tc.cfg.IsFilestorePresent(); got != tc.wantHostFile {
			t.Errorf("gofer conf = %+v, IsFilestorePresent() = %t, want = %t", tc.cfg, got, tc.wantHostFile)
		}
		if got := tc.cfg.ShouldUseLisafs(); got != tc.wantLisafs {
			t.Errorf("gofer conf = %+v, ShouldUseLisafs() = %t, want = %t", tc.cfg, got, tc.wantLisafs)
		}
		if got := tc.cfg.ShouldUseTmpfs(); got != tc.wantTmpfs {
			t.Errorf("gofer conf = %+v, ShouldUseTmpfs() = %t, want = %t", tc.cfg, got, tc.wantTmpfs)
		}
		if got := tc.cfg.ShouldUseErofs(); got != tc.wantErofs {
			t.Errorf("gofer conf = %+v, ShouldUseErofs() = %t, want = %t", tc.cfg, got, tc.wantErofs)
		}
	}
}

func TestGoferConfFlags(t *testing.T) {
	want := GoferMountConfFlags{
		{Lower: NoneLower, Upper: MemoryOverlay},
		{Lower: NoneLower, Upper: SelfOverlay},
		{Lower: NoneLower, Upper: AnonOverlay},
		{Lower: Lisafs, Upper: NoOverlay},
		{Lower: Lisafs, Upper: MemoryOverlay},
		{Lower: Lisafs, Upper: SelfOverlay},
		{Lower: Lisafs, Upper: AnonOverlay},
		{Lower: Erofs, Upper: NoOverlay},
		{Lower: Erofs, Upper: MemoryOverlay},
		{Lower: Erofs, Upper: SelfOverlay},
		{Lower: Erofs, Upper: AnonOverlay},
	}
	var got GoferMountConfFlags
	got.Set(want.String())
	if len(got) != len(want) {
		t.Fatalf("gofer conf flags is incorrect length: want = %d, got = %d", len(want), len(got))
	}
	for i := range want {
		if want[i] != got[i] {
			t.Errorf("gofer conf is incorrect: want = %s, got = %s", want[i], got[i])
		}
	}
}

func TestGoferMountConfSetGet(t *testing.T) {
	t.Run("Without size", func(t *testing.T) {
		conf := GoferMountConf{}
		err := conf.Set("lisafs:anon")
		if err != nil {
			t.Fatalf("Expect success: %v", err)
		}
		s := conf.String()
		if s != "lisafs:anon" {
			t.Fatalf("Expected lisafs:anon, got %s", s)
		}
	})
	t.Run("With size", func(t *testing.T) {
		conf := GoferMountConf{}
		err := conf.Set("lisafs:anon:size=1719")
		if err != nil {
			t.Fatalf("Expect success: %v", err)
		}
		s := conf.String()
		if s != "lisafs:anon:size=1719" {
			t.Fatalf("Expected lisafs:anon:size=1719, got %s", s)
		}
	})
}

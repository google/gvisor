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

package filter

import (
	"testing"

	"golang.org/x/sys/unix"
)

func TestRulesLisaFSFilters(t *testing.T) {
	for _, tc := range []struct {
		name         string
		directFS     bool
		lisafsNeeded bool
		wantAllowed  bool
	}{
		{
			name:        "directfs disabled",
			wantAllowed: true,
		},
		{
			name:        "directfs enabled",
			directFS:    true,
			wantAllowed: false,
		},
		{
			name:         "directfs enabled with lisafs mount",
			directFS:     true,
			lisafsNeeded: true,
			wantAllowed:  true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rules := Rules(Options{
				DirectFS:     tc.directFS,
				LisafsNeeded: tc.lisafsNeeded,
			})
			// SYS_FGETXATTR is part of lisafsFilters but not the base gofer
			// rules, so it proves whether the LisaFS filter block was merged.
			if got := rules.Has(unix.SYS_FGETXATTR); got != tc.wantAllowed {
				t.Errorf("Rules().Has(SYS_FGETXATTR) = %t, want %t", got, tc.wantAllowed)
			}
		})
	}
}

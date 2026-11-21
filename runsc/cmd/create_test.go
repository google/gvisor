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

package cmd

import (
	"testing"
)

func TestGoferFDFlags(t *testing.T) {
	for _, tc := range []struct {
		val      string
		wantDest string
		wantFD   int
		wantConf string
		wantErr  bool
	}{
		{val: "/:5", wantDest: "/", wantFD: 5},
		{val: "/data:6", wantDest: "/data", wantFD: 6},
		{val: "/data:6:lisafs:memory", wantDest: "/data", wantFD: 6, wantConf: "lisafs:memory"},
		{val: "/data:6:lisafs:self:size=1M", wantDest: "/data", wantFD: 6, wantConf: "lisafs:self:size=1M"},
		{val: "/data", wantErr: true},
		{val: "/data:x", wantErr: true},
		{val: "/data:-1", wantErr: true},
		{val: "/data:6:bogus", wantErr: true},
	} {
		t.Run(tc.val, func(t *testing.T) {
			var g goferFDFlags
			err := g.Set(tc.val)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("Set(%q) succeeded, want error", tc.val)
				}
				return
			}
			if err != nil {
				t.Fatalf("Set(%q) failed: %v", tc.val, err)
			}
			if len(g) != 1 {
				t.Fatalf("Set(%q) gave %d values, want 1", tc.val, len(g))
			}
			if g[0].dest != tc.wantDest || g[0].fd != tc.wantFD {
				t.Errorf("Set(%q) = %s:%d, want %s:%d", tc.val, g[0].dest, g[0].fd, tc.wantDest, tc.wantFD)
			}
			var gotConf string
			if g[0].conf != nil {
				gotConf = g[0].conf.String()
			}
			if gotConf != tc.wantConf {
				t.Errorf("Set(%q) conf = %q, want %q", tc.val, gotConf, tc.wantConf)
			}
			if got := g.String(); got != tc.val {
				t.Errorf("String() = %q, want %q", got, tc.val)
			}
		})
	}
}

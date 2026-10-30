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

package container

import (
	"slices"
	"testing"

	"gvisor.dev/gvisor/pkg/test/testutil"
	"gvisor.dev/gvisor/pkg/timing"
	"gvisor.dev/gvisor/runsc/config"
)

// TestMinimalBoot verifies that booting a container with --boot-times-log
// exports a startup timeline with ordered timestamps across the boot phases and
// a child timeline for the root container.
func TestMinimalBoot(t *testing.T) {
	root := setupMinimalRootfs(t)
	for _, bc := range bootConfigs(t, func() *config.Config { return testutil.TestConfig(t) }) {
		t.Run(bc.Name, func(t *testing.T) {
			tl := bootMinimal(t, *bc.Conf, root)
			if tl.Start.IsZero() || tl.End.IsZero() {
				t.Fatalf("startup timeline %q has zero bounds: Start=%v End=%v", tl.Name, tl.Start, tl.End)
			}
			prev := tl.Start
			for _, name := range []string{
				"creating loader",
				"loader created",
				"control server started",
				"start signal received",
				"kernel started",
			} {
				when, err := tl.Reached(name)
				if err != nil {
					t.Fatal(err)
				}
				if !when.After(prev) {
					t.Errorf("midpoint %q (%v) is not after previous timestamp (%v)", name, when, prev)
				}
				prev = when
			}
			if tl.End.Before(prev) {
				t.Errorf("End (%v) is before last midpoint (%v)", tl.End, prev)
			}
			if !slices.ContainsFunc(tl.Children, func(c timing.ExportedTimeline) bool {
				return c.Name == "root container"
			}) {
				t.Errorf("startup timeline has no %q child timeline; got %+v", "root container", tl.Children)
			}
		})
	}
}

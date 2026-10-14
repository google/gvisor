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
	"testing"

	"gvisor.dev/gvisor/pkg/test/testutil"
	"gvisor.dev/gvisor/runsc/config"
)

// TestMinimalBoot verifies that booting a container with --boot-times-log
// records consistent boot durations (New > 0, Run > 0, New+Run <= Boot).
func TestMinimalBoot(t *testing.T) {
	root := setupMinimalRootfs(t)
	for _, pc := range platformConfigs(t, func() *config.Config { return testutil.TestConfig(t) }) {
		t.Run(pc.name, func(t *testing.T) {
			times := bootMinimal(t, *pc.conf, root)
			if times.New <= 0 || times.Run <= 0 || times.New+times.Run > times.Boot {
				t.Errorf("inconsistent boot times: %+v; want New > 0, Run > 0, New+Run <= Boot", times)
			}
		})
	}
}

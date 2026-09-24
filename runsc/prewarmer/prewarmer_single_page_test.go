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

// Package prewarmer_test verifies size constraints on the gvisor-sentry-prewarmer
// sidecar binary.
package prewarmer_test

import (
	"os"
	"testing"

	"gvisor.dev/gvisor/pkg/test/testutil"
)

// TestPrewarmerFitsInOnePage verifies that the compiled gvisor-sentry-prewarmer
// binary fits in a single 4KiB page.
// This ensures its faulting cost remains as small as we can make it,
// given its trivial nature and the fact that it's on the hot-path
// of gVisor startup.
func TestPrewarmerFitsInOnePage(t *testing.T) {
	const maxSize = 4096
	path, err := testutil.FindFile("runsc/prewarmer/gvisor-sentry-prewarmer")
	if err != nil {
		t.Fatalf("cannot find gvisor-sentry-prewarmer binary: %v", err)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatalf("cannot stat %q: %v", path, err)
	}
	if st.Size() > maxSize {
		t.Errorf("gvisor-sentry-prewarmer is %d bytes, which does not fit in a single %d-byte page", st.Size(), maxSize)
	}
}

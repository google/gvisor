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

package kernel

import (
	"bytes"
	"io"
	"testing"
	"testing/synctest"

	"gvisor.dev/gvisor/pkg/sentry/state/stateio"
)

func TestAsyncMFLoaderStartupError(t *testing.T) {
	// The bubble detects a missing mainMFStartWg completion as a deadlock,
	// without a timeout. This test does not depend on virtual time.
	synctest.Test(t, func(t *testing.T) {
		// A sub-page read limit fails before metadata or mainMF is loaded.
		pages := stateio.NewIOReader(bytes.NewReader(nil), 1, 1, 1)
		metadata := io.NopCloser(bytes.NewReader(nil))
		loader := NewAsyncMFLoader(metadata, pages, nil, nil)

		startErr := loader.WaitMainMFStart()
		if startErr == nil {
			t.Fatal("WaitMainMFStart() succeeded with a sub-page read limit")
		}
		if err := loader.WaitMetadata(); err != startErr {
			t.Errorf("WaitMetadata() = %v, want %v", err, startErr)
		}
		if err := loader.Wait(); err != startErr {
			t.Errorf("Wait() = %v, want %v", err, startErr)
		}
	})
}

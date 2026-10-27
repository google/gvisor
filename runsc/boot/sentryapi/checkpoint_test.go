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

package sentryapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"gvisor.dev/gvisor/pkg/sentry/control/controlapi"
	"gvisor.dev/gvisor/pkg/state"
)

func TestCheckpointResultErrorRoundTrip(t *testing.T) {
	for _, sentinel := range []error{state.ErrUnsavable, controlapi.ErrCudaNotReady} {
		t.Run(sentinel.Error(), func(t *testing.T) {
			want := fmt.Errorf("checkpoint failed: %w", sentinel)
			var result CheckpointResult
			if !result.SetError(want) {
				t.Fatalf("CheckpointResult.SetError(%v) = false, want true", want)
			}

			encoded, err := json.Marshal(result)
			if err != nil {
				t.Fatalf("json.Marshal(%+v): %v", result, err)
			}
			var decoded CheckpointResult
			if err := json.Unmarshal(encoded, &decoded); err != nil {
				t.Fatalf("json.Unmarshal(%q): %v", encoded, err)
			}
			got := decoded.Err()
			if !errors.Is(got, sentinel) {
				t.Fatalf("CheckpointResult.Err() = %v, want errors.Is(err, %v)", got, sentinel)
			}
			if got.Error() != want.Error() {
				t.Errorf("CheckpointResult.Err() = %q, want %q", got, want)
			}
		})
	}
}

func TestCheckpointResultOtherError(t *testing.T) {
	var result CheckpointResult
	if result.SetError(errors.New("other checkpoint failure")) {
		t.Error("CheckpointResult.SetError(other error) = true, want false")
	}
	if err := result.Err(); err != nil {
		t.Errorf("CheckpointResult.Err() = %v, want nil", err)
	}
}

// Copyright 2026 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmd

import (
	"errors"
	"fmt"
	"testing"

	"gvisor.dev/gvisor/pkg/sentry/control/controlapi"
	statepkg "gvisor.dev/gvisor/pkg/state"
)

func TestCheckpointStateExitStatus(t *testing.T) {
	for _, test := range []struct {
		name       string
		err        error
		wantStatus int
		wantOK     bool
	}{
		{name: "unsavable", err: fmt.Errorf("checkpoint: %w", statepkg.ErrUnsavable), wantStatus: 3, wantOK: true},
		{name: "CUDA not ready", err: fmt.Errorf("checkpoint: %w", controlapi.ErrCudaNotReady), wantStatus: 4, wantOK: true},
		{name: "other", err: errors.New("checkpoint failed")},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, ok := checkpointStateExitStatus(test.err)
			if got.ExitStatus() != test.wantStatus || ok != test.wantOK {
				t.Errorf("checkpointStateExitStatus(%v) = (%d, %t), want (%d, %t)", test.err, got.ExitStatus(), ok, test.wantStatus, test.wantOK)
			}
		})
	}
}

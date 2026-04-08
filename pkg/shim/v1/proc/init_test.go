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

package proc

import (
	"context"
	"fmt"
	"testing"

	"gvisor.dev/gvisor/pkg/shim/v1/runsccmd"
)

func TestAdjustWaitStatus(t *testing.T) {
	ctx := context.Background()

	for _, tc := range []struct {
		name       string
		status     int
		err        error
		wantStatus int
	}{
		{
			name:       "success with no error",
			status:     0,
			err:        nil,
			wantStatus: 0,
		},
		{
			name:       "non-zero exit with no error",
			status:     1,
			err:        nil,
			wantStatus: 1,
		},
		{
			name:       "signal exit with no error",
			status:     137,
			err:        nil,
			wantStatus: 137,
		},
		{
			name:       "success with benign error (short-lived container)",
			status:     0,
			err:        fmt.Errorf("sandbox no longer running and its exit status is unavailable"),
			wantStatus: 0,
		},
		{
			name:       "success with any error preserves zero status",
			status:     0,
			err:        fmt.Errorf("some unexpected error"),
			wantStatus: 0,
		},
		{
			name:       "non-zero exit with error becomes internalErrorCode",
			status:     1,
			err:        fmt.Errorf("wait failed"),
			wantStatus: internalErrorCode,
		},
		{
			name:       "signal exit with error becomes internalErrorCode",
			status:     137,
			err:        fmt.Errorf("wait failed"),
			wantStatus: internalErrorCode,
		},
		{
			name:       "negative status with error becomes internalErrorCode",
			status:     -1,
			err:        fmt.Errorf("wait failed unexpectedly"),
			wantStatus: internalErrorCode,
		},
		{
			name:       "exit 255 with no error passes through",
			status:     255,
			err:        nil,
			wantStatus: 255,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Create a minimal Init with a dummy runtime to prevent nil
			// dereference in killAllLocked for the error path.
			p := &Init{
				id:      "test-container",
				runtime: &runsccmd.Runsc{Command: "false"},
			}
			got := adjustWaitStatus(ctx, p, tc.status, tc.err)
			if got != tc.wantStatus {
				t.Errorf("adjustWaitStatus(status=%d, err=%v) = %d, want %d", tc.status, tc.err, got, tc.wantStatus)
			}
		})
	}
}

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

package control

import (
	"errors"
	"strings"
	"testing"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/sentry/control/controlapi"
)

func TestCudaCheckpointFailure(t *testing.T) {
	for _, test := range []struct {
		name     string
		output   string
		notReady bool
	}{
		{name: "device not ready", output: "CUDA_ERROR_NOT_READY: device not ready", notReady: true},
		{name: "other failure", output: "operation failed"},
		{name: "no output"},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := cudaCheckpointFailure("cuda-checkpoint --toggle --pid 123", linux.WaitStatusExit(1), test.output)
			if got := errors.Is(err, controlapi.ErrCudaNotReady); got != test.notReady {
				t.Errorf("errors.Is(err, controlapi.ErrCudaNotReady) = %t, want %t; err = %v", got, test.notReady, err)
			}
			if !strings.Contains(err.Error(), "failed with exit status") {
				t.Errorf("error %q does not contain exit status", err)
			}
		})
	}
}

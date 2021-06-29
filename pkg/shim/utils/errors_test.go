// Copyright 2021 The gVisor Authors.
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

package utils

import (
	"fmt"
	"testing"

	"github.com/containerd/containerd/errdefs"
)

func TestGRPCRoundTripsErrors(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		test func(err error) bool
	}{
		{
			name: "passthrough",
			err:  errdefs.ErrNotFound,
			test: errdefs.IsNotFound,
		},
		{
			name: "wrapped",
			err:  fmt.Errorf("oh no: %w", errdefs.ErrNotFound),
			test: errdefs.IsNotFound,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := errdefs.FromGRPC(ErrToGRPC(tc.err)); !tc.test(err) {
				t.Errorf("errToGRPC got %+v", err)
			}
			if err := errdefs.FromGRPC(ErrToGRPCf(tc.err, "testing %s", "123")); !tc.test(err) {
				t.Errorf("errToGRPCf got %+v", err)
			}
		})
	}
}

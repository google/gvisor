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

package boot

import (
	"strconv"
	"testing"

	"gvisor.dev/gvisor/pkg/hostarch"
)

func TestCheckPageSizeMetadata(t *testing.T) {
	pageSize := strconv.FormatUint(uint64(hostarch.PageSize), 10)
	otherPageSize := "65536"
	if pageSize == otherPageSize {
		otherPageSize = "4096"
	}
	for _, test := range []struct {
		name     string
		metadata map[string]string
		wantErr  bool
	}{
		{
			name:     "missing",
			metadata: map[string]string{},
		},
		{
			name:     "same",
			metadata: map[string]string{PageSizeKey: pageSize},
		},
		{
			name:     "different",
			metadata: map[string]string{PageSizeKey: otherPageSize},
			wantErr:  true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := checkPageSizeMetadata(test.metadata); (err != nil) != test.wantErr {
				t.Errorf("checkPageSizeMetadata(%v) = %v, want error: %t", test.metadata, err, test.wantErr)
			}
		})
	}
}

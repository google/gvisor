// Copyright 2018 The gVisor Authors.
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

package limits

import (
	"syscall"
	"testing"
)

func TestSet(t *testing.T) {
	testCases := []struct {
		limit       Limit
		privileged  bool
		expectedErr error
	}{
		{limit: Limit{Cur: 50, Max: 50}, privileged: false, expectedErr: nil},
		{limit: Limit{Cur: 20, Max: 50}, privileged: false, expectedErr: nil},
		{limit: Limit{Cur: 20, Max: 60}, privileged: false, expectedErr: syscall.EPERM},
		{limit: Limit{Cur: 60, Max: 50}, privileged: false, expectedErr: syscall.EINVAL},
		{limit: Limit{Cur: 11, Max: 10}, privileged: false, expectedErr: syscall.EINVAL},
		{limit: Limit{Cur: 20, Max: 60}, privileged: true, expectedErr: nil},
	}

	ls := NewLimitSet()
	for _, tc := range testCases {
		if _, err := ls.Set(1, tc.limit, tc.privileged); err != tc.expectedErr {
			t.Fatalf("Tried to set Limit to %+v and privilege %t: got %v, wanted %v", tc.limit, tc.privileged, err, tc.expectedErr)
		}
	}

}

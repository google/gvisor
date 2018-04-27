// Copyright 2018 Google Inc.
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
	ls := NewLimitSet()
	ls.Set(1, Limit{Cur: 50, Max: 50})
	if _, err := ls.Set(1, Limit{Cur: 20, Max: 50}); err != nil {
		t.Fatalf("Tried to lower Limit to valid new value: got %v, wanted nil", err)
	}
	if _, err := ls.Set(1, Limit{Cur: 20, Max: 60}); err != syscall.EPERM {
		t.Fatalf("Tried to raise limit.Max to invalid higher value: got %v, wanted syscall.EPERM", err)
	}
	if _, err := ls.Set(1, Limit{Cur: 60, Max: 50}); err != syscall.EINVAL {
		t.Fatalf("Tried to raise limit.Cur to invalid higher value: got %v, wanted syscall.EINVAL", err)
	}
	if _, err := ls.Set(1, Limit{Cur: 11, Max: 10}); err != syscall.EINVAL {
		t.Fatalf("Tried to set new limit with Cur > Max: got %v, wanted syscall.EINVAL", err)
	}
}

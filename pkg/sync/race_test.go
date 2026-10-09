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

package sync

import "testing"

func TestRaceUncheckedAtomicCompareAndSwapUintptr(t *testing.T) {
	const (
		oldValue = uintptr(1)
		newValue = uintptr(2)
	)

	value := oldValue
	if !RaceUncheckedAtomicCompareAndSwapUintptr(&value, oldValue, newValue) {
		t.Errorf("RaceUncheckedAtomicCompareAndSwapUintptr() = false, want true")
	}
	if value != newValue {
		t.Errorf("value = %d, want %d", value, newValue)
	}

	value = newValue
	if RaceUncheckedAtomicCompareAndSwapUintptr(&value, oldValue, newValue) {
		t.Errorf("RaceUncheckedAtomicCompareAndSwapUintptr() = true, want false")
	}
	if value != newValue {
		t.Errorf("value = %d after failed compare-and-swap, want %d", value, newValue)
	}
}

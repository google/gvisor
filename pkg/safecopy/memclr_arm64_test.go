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

package safecopy

import "testing"

func TestZeroOutWithoutZVA(t *testing.T) {
	// Run the ZeroOut tests again without DC ZVA, which cannot be enabled on
	// hosts that do not allow it or use another block size.
	if !useZVA {
		t.Skip("memclr does not use DC ZVA")
	}
	useZVA = false
	defer func() { useZVA = true }()
	t.Run("SegvError", TestZeroOutSegvError)
	t.Run("BusError", TestZeroOutBusError)
	t.Run("Lengths", TestZeroOutLengths)
	t.Run("LengthsFault", TestZeroOutLengthsFault)
}

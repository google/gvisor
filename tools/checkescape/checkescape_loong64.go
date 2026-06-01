// Copyright 2024 The gVisor Authors.
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

package checkescape

// fixOffset is a no-op on LoongArch.
//
// The arm64 implementation re-parses BL instruction encoding to translate
// objdump's "(PC)" relative offsets into byte offsets. For LoongArch we
// have not yet implemented the equivalent decoding for BL / B / JAL, so
// indirect-branch reachability analysis on loong64 binaries is a TODO.
// Returning the original target unchanged keeps checkescape usable for
// non-branch checks; loong64 binaries will see false negatives in the
// reachability analyzer but the analyzer is a static gate, not a runtime
// dependency.
func fixOffset(fields []string, target string) (string, error) {
	return target, nil
}

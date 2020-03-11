// Copyright 2020 The gVisor Authors.
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

package ctrie

type testKey int
type testAltKey int

// hashModulus is a very bad modulus to use for hashing.
//
// We intentionally create substantial collisions here to explicit test for
// this handling and behavior.
const hashModulus = 65536

func (t testKey) Hash() uint32 {
	return uint32(t % hashModulus)
}

func (t testKey) Equal(ot testKey) bool {
	return t == ot
}

func (t testAltKey) Hash() uint32 {
	return uint32(t)
}

func (t testAltKey) Equal(ot testAltKey) bool {
	return t == ot
}

type testValue int

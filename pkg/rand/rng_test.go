// Copyright 2023 The gVisor Authors.
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

package rand

import (
	"math/rand"
	"testing"
)

const testIterations = 100_000

func TestInt63n(t *testing.T) {
	for i := 0; i < testIterations; i++ {
		maximum := rand.Int63()
		for maximum <= 0 {
			maximum = rand.Int63()
		}
		if n := Int63n(maximum); n >= maximum || n < 0 {
			t.Errorf("Int63n(%d) returned bad value %d", maximum, n)
		}
	}
}

func TestInt63(t *testing.T) {
	for i := 0; i < testIterations; i++ {
		if n := Int63(); n < 0 {
			t.Errorf("Int63() returned bad value %d", n)
		}
	}
}

// Copyright 2022 The gVisor Authors.
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

package hostarch

import (
	"fmt"
	"math"
	"testing"
)

func TestCacheLineRoundUp(t *testing.T) {
	tests := []struct {
		input  uint64
		output uint64
	}{
		{0, 0},
		{63, 64},
		{64, 64},
		{65, 128},
		{66, 128},
		{99, 128},
		{127, 128},
		{128, 128},
		{129, 192},
		{math.MaxUint32, math.MaxUint32 + 1},
	}
	for i, tt := range tests {
		t.Run(fmt.Sprintf("case-%d", i), func(t *testing.T) {
			s, ok := CacheLineRoundUp(tt.input)
			if s != tt.output {
				t.Errorf("Expected %d, got %d", tt.output, s)
			}
			if !ok {
				t.Errorf("Expected no wrap around, got %t. Input %d, expected %d", ok, tt.input, tt.output)
			}
		})
	}
}

func TestCacheLineRoundUpWrapAround(t *testing.T) {
	tests := []struct {
		input  uint64
		output uint64
	}{
		{math.MaxUint64 - 1, 0},
		{math.MaxUint64, 0},
	}
	for i, tt := range tests {
		t.Run(fmt.Sprintf("case-%d", i), func(t *testing.T) {
			s, ok := CacheLineRoundUp(tt.input)
			if s != tt.output {
				t.Errorf("Expected %d, got %d", tt.output, s)
			}
			if ok {
				t.Errorf("Expected wrap around, got %t. Input %d, expected %d", ok, tt.input, tt.output)
			}
		})
	}
}

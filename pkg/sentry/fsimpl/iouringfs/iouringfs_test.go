// Copyright 2021 The gVisor Authors.
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

package iouringfs

import (
	"fmt"
	"math"
	"testing"
)

func TestRoundUpPowerOfTwo(t *testing.T) {
	tests := []struct {
		input  uint32
		output uint32
	}{
		{0, 1},
		{1, 1},
		{2, 2},
		{3, 4},
		{4, 4},
		{5, 8},
		{6, 8},
		{7, 8},
		{8, 8},
		{1 << 31, 2147483648},
		{1<<31 - 1, 2147483648},
	}
	for i, tt := range tests {
		t.Run(fmt.Sprintf("case-%d", i), func(t *testing.T) {
			s, ok := roundUpPowerOfTwo(tt.input)
			if s != tt.output {
				t.Errorf("Expected %d, got %d", tt.output, s)
			}
			if !ok {
				t.Errorf("Expected no error, got %t. Input %d, expected %d", ok, tt.input, tt.output)
			}
		})
	}
}

func TestRoundUpPowerOfTwoOverflow(t *testing.T) {
	tests := []struct {
		input  uint32
		output uint32
	}{
		{1<<31 + 1, 0},
		{math.MaxUint32, 0},
	}
	for i, tt := range tests {
		t.Run(fmt.Sprintf("case-%d", i), func(t *testing.T) {
			s, ok := roundUpPowerOfTwo(tt.input)
			if s != tt.output || ok {
				t.Errorf("Expected value %d and overflow, got %d and %t", tt.output, s, ok)
			}
		})
	}
}

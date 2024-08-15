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

package sys

import (
	"testing"
)

func TestFullCPUMask(t *testing.T) {
	for _, test := range []struct {
		cores uint
		want  string
	}{
		{1, "1"},
		{2, "3"},
		{3, "7"},
		{4, "f"},
		{5, "1f"},
		{32, "ffffffff"},
		{33, "1,ffffffff"},
		{36, "f,ffffffff"},
		{37, "1f,ffffffff"},
		{64, "ffffffff,ffffffff"},
		{65, "1,ffffffff,ffffffff"},
	} {
		if got := fullCPUMask(test.cores); got != test.want {
			t.Errorf("fullCPUMask(%d): got %s, want %s", test.cores, got, test.want)
		}
	}
}

func TestOneCPUMask(t *testing.T) {
	for _, test := range []struct {
		i     uint
		cores uint
		want  string
	}{
		{0, 1, "1"},
		{0, 4, "1"},
		{1, 4, "2"},
		{2, 4, "4"},
		{3, 4, "8"},
		{0, 5, "01"},
		{4, 5, "10"},
		{0, 32, "00000001"},
		{26, 32, "04000000"},
		{0, 33, "0,00000001"},
		{31, 33, "0,80000000"},
		{32, 33, "1,00000000"},
		{0, 64, "00000000,00000001"},
		{31, 64, "00000000,80000000"},
		{32, 64, "00000001,00000000"},
		{63, 64, "80000000,00000000"},
		{0, 65, "0,00000000,00000001"},
		{31, 65, "0,00000000,80000000"},
		{32, 65, "0,00000001,00000000"},
		{63, 65, "0,80000000,00000000"},
		{64, 65, "1,00000000,00000000"},
	} {
		if got := oneCPUMask(test.i, test.cores); got != test.want {
			t.Errorf("oneCPUMask(%d, %d): got %s, want %s", test.i, test.cores, got, test.want)
		}
	}
}

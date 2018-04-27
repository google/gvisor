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

package hostcpu

import (
	"fmt"
	"testing"
)

func TestMaxValueInLinuxBitmap(t *testing.T) {
	for _, test := range []struct {
		str string
		max uint64
	}{
		{"0", 0},
		{"0\n", 0},
		{"0,2", 2},
		{"0-63", 63},
		{"0-3,8-11", 11},
	} {
		t.Run(fmt.Sprintf("%q", test.str), func(t *testing.T) {
			max, err := maxValueInLinuxBitmap(test.str)
			if err != nil || max != test.max {
				t.Errorf("maxValueInLinuxBitmap: got (%d, %v), wanted (%d, nil)", max, err, test.max)
			}
		})
	}
}

func TestMaxValueInLinuxBitmapErrors(t *testing.T) {
	for _, str := range []string{"", "\n"} {
		t.Run(fmt.Sprintf("%q", str), func(t *testing.T) {
			max, err := maxValueInLinuxBitmap(str)
			if err == nil {
				t.Errorf("maxValueInLinuxBitmap: got (%d, nil), wanted (_, error)", max)
			}
			t.Log(err)
		})
	}
}

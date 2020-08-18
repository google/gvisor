// Copyright 2019 The gVisor Authors.
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
package buffer

import (
	"reflect"
	"testing"
)

func TestNewPrependableFromView(t *testing.T) {
	tests := []struct {
		comment   string
		view      View
		extraSize int
		want      Prependable
	}{
		{
			comment:   "Reserve extra space",
			view:      View("abc"),
			extraSize: 2,
			want:      Prependable{buf: View("\x00\x00abc"), usedIdx: 2},
		},
		{
			comment:   "Don't reserve extra space",
			view:      View("abc"),
			extraSize: 0,
			want:      Prependable{buf: View("abc"), usedIdx: 0},
		},
	}

	for _, testCase := range tests {
		t.Run(testCase.comment, func(t *testing.T) {
			prep := NewPrependableFromView(testCase.view, testCase.extraSize)
			if !reflect.DeepEqual(prep, testCase.want) {
				t.Errorf("NewPrependableFromView(%#v, %d) = %#v; want %#v", testCase.view, testCase.extraSize, prep, testCase.want)
			}
		})
	}
}

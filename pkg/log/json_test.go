// Copyright 2018 The gVisor Authors.
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

package log

import (
	"encoding/json"
	"testing"
)

// Tests that Level can marshal/unmarshal properly.
func TestLevelMarshal(t *testing.T) {
	lvs := []Level{Warning, Info, Debug}
	for _, lv := range lvs {
		bs, err := lv.MarshalJSON()
		if err != nil {
			t.Errorf("error marshaling %v: %v", lv, err)
		}
		var lv2 Level
		if err := lv2.UnmarshalJSON(bs); err != nil {
			t.Errorf("error unmarshaling %v: %v", bs, err)
		}
		if lv != lv2 {
			t.Errorf("marshal/unmarshal level got %v wanted %v", lv2, lv)
		}
	}
}

// Test that integers can be properly unmarshaled.
func TestUnmarshalFromInt(t *testing.T) {
	tcs := []struct {
		i    int
		want Level
	}{
		{0, Warning},
		{1, Info},
		{2, Debug},
	}

	for _, tc := range tcs {
		j, err := json.Marshal(tc.i)
		if err != nil {
			t.Errorf("error marshaling %v: %v", tc.i, err)
		}
		var lv Level
		if err := lv.UnmarshalJSON(j); err != nil {
			t.Errorf("error unmarshaling %v: %v", j, err)
		}
		if lv != tc.want {
			t.Errorf("marshal/unmarshal %v got %v want %v", tc.i, lv, tc.want)
		}
	}
}

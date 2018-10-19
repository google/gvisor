// Copyright 2018 Google LLC
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

package template_test

import (
	"math"
	"testing"
)

func TestMax(t *testing.T) {
	var a int = max(10, 20)
	if a != 20 {
		t.Errorf("Bad result of max, got %v, want %v", a, 20)
	}
}

func TestIntConst(t *testing.T) {
	var a int = add(10)
	if a != 30 {
		t.Errorf("Bad result of add, got %v, want %v", a, 30)
	}
}

func TestStrConst(t *testing.T) {
	v := getName()
	if v != "test" {
		t.Errorf("Bad name, got %v, want %v", v, "test")
	}
}

func TestImport(t *testing.T) {
	v := getMax()
	if v != math.MaxUint64 {
		t.Errorf("Bad max value, got %v, want %v", v, uint64(math.MaxUint64))
	}
}

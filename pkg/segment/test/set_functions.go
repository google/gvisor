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

// Package segment is a test package.
package segment

type setFunctions struct{}

// MinKey returns the minimum key for the set.
func (s setFunctions) MinKey() int {
	return -s.MaxKey() - 1
}

// MaxKey returns the maximum key for the set.
func (setFunctions) MaxKey() int {
	return int(^uint(0) >> 1)
}

func (setFunctions) ClearValue(*int) {}

func (setFunctions) Merge(_ Range, val1 int, _ Range, _ int) (int, bool) {
	return val1, true
}

func (setFunctions) Split(_ Range, val int, _ int) (int, int) {
	return val, val
}

type gapSetFunctions struct {
	setFunctions
}

// MinKey is adjusted to make sure no add overflow would happen in test cases.
// e.g. A gap with range {MinInt32, 2} would cause overflow in Range().Length().
//
// Normally Keys should be unsigned to avoid these issues.
func (s gapSetFunctions) MinKey() int {
	return s.setFunctions.MinKey() / 2
}

// MaxKey returns the maximum key for the set.
func (s gapSetFunctions) MaxKey() int {
	return s.setFunctions.MaxKey() / 2
}

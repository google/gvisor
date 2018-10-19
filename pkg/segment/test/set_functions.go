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

package segment

// Basic numeric constants that we define because the math package doesn't.
// TODO: These should be Math.MaxInt64/MinInt64?
const (
	maxInt = int(^uint(0) >> 1)
	minInt = -maxInt - 1
)

type setFunctions struct{}

func (setFunctions) MinKey() int {
	return minInt
}

func (setFunctions) MaxKey() int {
	return maxInt
}

func (setFunctions) ClearValue(*int) {}

func (setFunctions) Merge(_ Range, val1 int, _ Range, _ int) (int, bool) {
	return val1, true
}

func (setFunctions) Split(_ Range, val int, _ int) (int, int) {
	return val, val
}

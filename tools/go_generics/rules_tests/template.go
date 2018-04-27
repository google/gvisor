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

package template

type t float

const (
	n t = 10.1
	m   = "abc"
	o   = 0
)

func max(a, b t) t {
	if a > b {
		return a
	}
	return b
}

func add(a t) t {
	return a + n
}

func getName() string {
	return m
}

func getMax() uint64 {
	return o
}

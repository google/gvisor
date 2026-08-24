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

package main

type FooNew struct {
	Q
	Bar map[string]Q `json:"bar,omitempty"`
}

type BazNew struct {
	T someTypeNotT
}

func (f FooNew) GetBar(name string) Q {
	b, ok := f.Bar[name]
	if ok {
		b = f.Apply(b)
	} else {
		b = f.Q
	}
	return b
}

func foobarNew() {
	a := BazNew{}
	a.Q = 0 // should not be renamed, this is a limitation

	b := otherpkg.UnrelatedType{}
	b.Q = 0 // should not be renamed, this is a limitation
}

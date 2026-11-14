// Copyright 2026 The gVisor Authors.
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

package tests

type Number interface {
	~int | ~int64
}

type T struct{}

type Box[T any] struct {
	v T
}

func (b Box[T]) Get() T {
	return b.v
}

func Use[T Number](v T) Box[T] {
	return Box[T]{v: v}
}

func UseGlobal(x T) T {
	return x
}

type Pair[A, B any] struct {
	first  A
	second B
}

var _ = Pair[int, string]{}
var _ = Box[int]{}
var _ = Use[int](1)

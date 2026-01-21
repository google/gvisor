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

// Package test contains data structures for testing the go_stateify tool.
package test

import (
	"context"

	"gvisor.dev/gvisor/tools/go_stateify/test/external"
)

// +stateify savable
type box[T any] struct {
	Value T
}

// +stateify transparent
type intBox struct {
	box[int]
}

// +stateify transparent
type externalIntBox struct {
	external.Box[int]
}

// +stateify savable
type plainBox struct {
	Value int
}

// +stateify transparent
type plainBoxWrapper struct {
	plainBox
}

// +stateify savable
type embeddedExternal struct {
	external.Box[int]
}

// afterLoad exists to exercise receiver parsing for parenthesized generics.
func (s *(singleParamBox[T])) afterLoad(context.Context) {}

// +stateify savable
type singleParamBox[T any] struct {
	Value T
}

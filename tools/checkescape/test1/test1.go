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

// Package test1 is a test package.
package test1

import (
	"fmt"
	"reflect"
)

// Interface is a generic interface.
type Interface interface {
	Foo()
}

// Type is a concrete implementation of Interface.
type Type struct {
	A uint64
	B uint64
}

// Foo implements Interface.Foo.
//go:nosplit
func (t Type) Foo() {
	fmt.Printf("%v", t) // Never executed.
}

// +checkescape:all,hard
//go:nosplit
func InterfaceFunction(i Interface) {
	// Do nothing; exported for tests.
}

// +checkesacape:all,hard
//go:nosplit
func TypeFunction(t *Type) {
}

// +mustescape:local,builtin
//go:noinline
//go:nosplit
func BuiltinMap(x int) map[string]bool {
	return make(map[string]bool)
}

// +mustescape:builtin
//go:noinline
//go:nosplit
func builtinMapRec(x int) map[string]bool {
	return BuiltinMap(x)
}

// +temustescapestescape:local,builtin
//go:noinline
//go:nosplit
func BuiltinClosure(x int) func() {
	return func() {
		fmt.Printf("%v", x)
	}
}

// +mustescape:builtin
//go:noinline
//go:nosplit
func builtinClosureRec(x int) func() {
	return BuiltinClosure(x)
}

// +mustescape:local,builtin
//go:noinline
//go:nosplit
func BuiltinMakeSlice(x int) []byte {
	return make([]byte, x)
}

// +mustescape:builtin
//go:noinline
//go:nosplit
func builtinMakeSliceRec(x int) []byte {
	return BuiltinMakeSlice(x)
}

// +mustescape:local,builtin
//go:noinline
//go:nosplit
func BuiltinAppend(x []byte) []byte {
	return append(x, 0)
}

// +mustescape:builtin
//go:noinline
//go:nosplit
func builtinAppendRec() []byte {
	return BuiltinAppend(nil)
}

// +mustescape:local,builtin
//go:noinline
//go:nosplit
func BuiltinChan() chan int {
	return make(chan int)
}

// +mustescape:builtin
//go:noinline
//go:nosplit
func builtinChanRec() chan int {
	return BuiltinChan()
}

// +mustescape:local,heap
//go:noinline
//go:nosplit
func Heap() *Type {
	var t Type
	return &t
}

// +mustescape:heap
//go:noinline
//go:nosplit
func heapRec() *Type {
	return Heap()
}

// +mustescape:local,interface
//go:noinline
//go:nosplit
func Dispatch(i Interface) {
	i.Foo()
}

// +mustescape:interface
//go:noinline
//go:nosplit
func dispatchRec(i Interface) {
	Dispatch(i)
}

// +mustescape:local,dynamic
//go:noinline
//go:nosplit
func Dynamic(f func()) {
	f()
}

// +mustescape:dynamic
//go:noinline
//go:nosplit
func dynamicRec(f func()) {
	Dynamic(f)
}

// +mustescape:local,unknown
//go:noinline
//go:nosplit
func Unknown() {
	_ = reflect.TypeOf((*Type)(nil)) // Does not actually escape.
}

// +mustescape:unknown
//go:noinline
//go:nosplit
func unknownRec() {
	Unknown()
}

//go:noinline
//go:nosplit
func internalFunc() {
}

// +mustescape:local,stack
//go:noinline
func Split() {
	internalFunc()
}

// +mustescape:stack
//go:noinline
func splitRec() {
	Split()
}

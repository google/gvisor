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

package test2

import (
	"gvisor.dev/gvisor/tools/checkescape/test1"
)

// +checkescape:all
func interfaceFunctionCrossPkg() {
	var i test1.Interface
	test1.InterfaceFunction(i)
}

// +checkesacape:all
func typeFunctionCrossPkg() {
	var t test1.Type
	test1.TypeFunction(&t)
}

// +testescape:builtin
//go:noinline
func builtinMapCrossPkg(x int) map[string]bool {
	return test1.BuiltinMap(x)
}

// +testescape:builtin
//go:noinline
func builtinClosureCrossPkg(x int) func() {
	return test1.BuiltinClosure(x)
}

// +testescape:builtin
//go:noinline
func builtinMakeSliceCrossPkg(x int) []byte {
	return test1.BuiltinMakeSlice(x)
}

// +testescape:builtin
//go:noinline
func builtinAppendCrossPkg() []byte {
	return test1.BuiltinAppend(nil)
}

// +testescape:builtin
//go:noinline
func builtinChanCrossPkg() chan int {
	return test1.BuiltinChan()
}

// +testescape:heap
//go:noinline
func heapCrossPkg() *test1.Type {
	return test1.Heap()
}

// +testescape:interface
//go:noinline
func dispatchCrossPkg(i test1.Interface) {
	test1.Dispatch(i)
}

// +testescape:dynamic
//go:noinline
func dynamicCrossPkg(f func()) {
	test1.Dynamic(f)
}

// +testescape:unknown
//go:noinline
func unknownCrossPkg() {
	test1.Unknown()
}

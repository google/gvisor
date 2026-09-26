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

// Package test2 is a test package that imports test1.
package test2

import (
	"gvisor.dev/gvisor/tools/checkescape/test1"
)

// +checkescape:all
//
//go:nosplit
func interfaceFunctionCrossPkg() {
	var i test1.Interface
	test1.InterfaceFunction(i)
}

// +checkescape:all
//
//go:nosplit
func typeFunctionCrossPkg() {
	var t test1.Type
	test1.TypeFunction(&t)
}

// +mustescape:builtin
//
//go:noinline
func builtinMapCrossPkg(x int) map[string]bool {
	return test1.BuiltinMap(x)
}

// +mustescape:builtin
//
//go:noinline
func builtinClosureCrossPkg(x int) func() {
	return test1.BuiltinClosure(x)
}

// +mustescape:builtin
//
//go:noinline
func builtinMakeSliceCrossPkg(x int) []byte {
	return test1.BuiltinMakeSlice(x)
}

// +mustescape:builtin
//
//go:noinline
func builtinAppendCrossPkg() []byte {
	return test1.BuiltinAppend(nil)
}

// +mustescape:builtin
//
//go:noinline
func builtinChanCrossPkg() chan int {
	return test1.BuiltinChan()
}

// +mustescape:heap
//
//go:noinline
func heapCrossPkg() *test1.Type {
	return test1.Heap()
}

// +mustescape:interface
//
//go:noinline
func dispatchCrossPkg(i test1.Interface) {
	test1.Dispatch(i)
}

// +mustescape:dynamic
//
//go:noinline
func dynamicCrossPkg(f func()) {
	test1.Dynamic(f)
}

// +mustescape:stack
//
//go:noinline
//go:nosplit
func splitCrosssPkt() {
	test1.Split()
}

// +checkescape:all
//
//go:nosplit
func genericIdentityCrossPkg(v int) int {
	return test1.GenericIdentity(v)
}

// +checkescape:all
//
//go:nosplit
func genericMethodCrossPkg(v *test1.Value[uint64, int], expression bool) (uint64, int) {
	if expression {
		return (*test1.Value[uint64, int]).Get(v)
	}
	return v.Get()
}

// +mustescape:heap
//
//go:nosplit
func genericMethodHeapCrossPkg(v *test1.Value[uint64, int]) *int {
	return v.Copy()
}

// +mustescape:heap
//
//go:nosplit
func genericHeapCrossPkg() *int {
	return test1.GenericHeap[int]()
}

// +mustescape:heap
//
//go:nosplit
func genericScratchCrossPkg(v [1 << 17]byte, i int) [1 << 17]byte {
	return test1.GenericScratch(v, i)
}

// +mustescape:stack
//
//go:nosplit
func genericSplitCrossPkg(v int) int {
	return test1.GenericSplit(v)
}

// +mustescape:heap
//
//go:nosplit
func genericClosureCrossPkg() *int {
	return test1.GenericClosure[int]()
}

// +mustescape:interface,dynamic
//
//go:nosplit
func genericDispatchCrossPkg(v test1.Type, f func(test1.Type)) {
	test1.GenericDispatch(v)
	test1.GenericDynamic(f, v)
}

// +checkescape:all
//
//go:nosplit
func genericNumericCrossPkg(a, b uint64) (bool, uint32) {
	return test1.GenericNumeric(a, b)
}

// +checkescape:all
//
//go:nosplit
func genericLookupCrossPkg(values []test1.Value[string, int], key string) (int, bool) {
	return test1.GenericLookup(values, key)
}

// +mustescape:dynamic
//
//go:nosplit
func genericEqualCrossPkg(a, b any) bool {
	return test1.GenericEqual(a, b)
}

// +mustescape:heap,dynamic
//
//go:nosplit
func genericBoxCrossPkg(v [4]uint64) any {
	return test1.GenericBox(v)
}

// +mustescape:heap,dynamic
//
//go:nosplit
func genericBytesCrossPkg(v string) []byte {
	return test1.GenericBytes(v)
}

// +mustescape:dynamic
//
//go:nosplit
func genericAssertCrossPkg(v any) (test1.Interface, bool) {
	return test1.GenericAssert[test1.Interface](v)
}

// +mustescape:dynamic
//
//go:nosplit
func genericReceiveCrossPkg(ch <-chan int) int {
	return test1.GenericReceive(ch)
}

type embeddedValue struct {
	*test1.Value[uint64, int]
}

// A receiver adapter cannot reuse the embedded method's escape summary.
// +mustescape:local,unknown
//
//go:nosplit
func genericAdaptedMethod(v *embeddedValue) (uint64, int) {
	return (*embeddedValue).Get(v)
}

// +mustescape:dynamic
//
//go:nosplit
func concreteReceiveCrossPkg(ch <-chan int) int {
	return test1.ConcreteReceive(ch)
}

// +mustescape:heap,dynamic
//
//go:nosplit
func concreteBoxCrossPkg(v [4]uint64) any {
	return test1.ConcreteBoxImplicit(v)
}

// +mustescape:stack
//
//go:noinline
//go:nosplit
func mapLookupCrossPkg(m map[uint64]int, key uint64) int {
	return test1.MapLookup(m, key)
}

// +mustescape:stack
// +checkescape:hard
//
//go:nosplit
func genericMapLookupCrossPkg(m map[string]int, key string) int {
	return test1.GenericMapLookup(m, key)
}

// Declaration facts describe all instantiations, including the map case.
// +mustescape:stack
// +checkescape:hard
//
//go:nosplit
func genericClearCrossPkg(v []int) {
	test1.GenericClear(v)
}

// +checkescape:all
//
//go:nosplit
func genericClearSliceCrossPkg(v []*int) {
	test1.GenericClearSlice(v)
}

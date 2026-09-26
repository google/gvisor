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
//
//go:nosplit
func (t Type) Foo() {
	fmt.Printf("%v", t) // Never executed.
}

// InterfaceFunction is passed an interface argument.
// +checkescape:all,hard
//
//go:nosplit
func InterfaceFunction(i Interface) {
	// Do nothing; exported for tests.
}

// TypeFunction is passed a concrete pointer argument.
// +checkescape:all,hard
//
//go:nosplit
func TypeFunction(t *Type) {
}

// BuiltinMap creates a new map.
// +mustescape:local,builtin
//
//go:noinline
//go:nosplit
func BuiltinMap(x int) map[string]bool {
	return make(map[string]bool)
}

// +mustescape:builtin
//
//go:noinline
//go:nosplit
func builtinMapRec(x int) map[string]bool {
	return BuiltinMap(x)
}

// BuiltinClosure returns a closure around x.
// +mustescape:local,builtin
//
//go:noinline
//go:nosplit
func BuiltinClosure(x int) func() {
	return func() {
		fmt.Printf("%v", x)
	}
}

// +mustescape:builtin
//
//go:noinline
//go:nosplit
func builtinClosureRec(x int) func() {
	return BuiltinClosure(x)
}

// BuiltinMakeSlice makes a new slice.
// +mustescape:local,builtin
//
//go:noinline
//go:nosplit
func BuiltinMakeSlice(x int) []byte {
	return make([]byte, x)
}

// +mustescape:builtin
//
//go:noinline
//go:nosplit
func builtinMakeSliceRec(x int) []byte {
	return BuiltinMakeSlice(x)
}

// BuiltinAppend calls append on a slice.
// +mustescape:local,builtin
//
//go:noinline
//go:nosplit
func BuiltinAppend(x []byte) []byte {
	return append(x, 0)
}

// +mustescape:builtin
//
//go:noinline
//go:nosplit
func builtinAppendRec() []byte {
	return BuiltinAppend(nil)
}

// BuiltinChan makes a channel.
// +mustescape:local,builtin
//
//go:noinline
//go:nosplit
func BuiltinChan() chan int {
	return make(chan int)
}

// +mustescape:builtin
//
//go:noinline
//go:nosplit
func builtinChanRec() chan int {
	return BuiltinChan()
}

// Heap performs an explicit heap allocation.
// +mustescape:local,heap
//
//go:noinline
//go:nosplit
func Heap() *Type {
	var t Type
	return &t
}

// +mustescape:heap
//
//go:noinline
//go:nosplit
func heapRec() *Type {
	return Heap()
}

// Dispatch dispatches via an interface.
// +mustescape:local,interface
// +checkescape:hard
//
//go:noinline
//go:nosplit
func Dispatch(i Interface) {
	i.Foo()
}

// +mustescape:interface
//
//go:noinline
//go:nosplit
func dispatchRec(i Interface) {
	Dispatch(i)
}

// Dynamic invokes a dynamic function.
// +mustescape:local,dynamic
// +checkescape:hard
//
//go:noinline
//go:nosplit
func Dynamic(f func()) {
	f()
}

// +mustescape:dynamic
//
//go:noinline
//go:nosplit
func dynamicRec(f func()) {
	Dynamic(f)
}

//go:noinline
//go:nosplit
func internalFunc() {
}

// Split includes a guaranteed stack split.
// +mustescape:local,stack
//
//go:noinline
func Split() {
	internalFunc()
}

// +mustescape:stack
//
//go:noinline
//go:nosplit
func splitRec() {
	Split()
}

// Callers precede their generic callees so local analysis cannot depend on
// facts having already been exported in declaration order.
// +checkescape:all
//
//go:noinline
//go:nosplit
func genericLocal(v int) int {
	return genericDelegate(v)
}

// +mustescape:heap
//
//go:noinline
//go:nosplit
func genericHeapLocal() *int {
	return genericAllocate[int]()
}

// +checkescape:all
//
//go:nosplit
func genericMethodExpressionLocal(v *Value[uint64, int]) (uint64, int) {
	return (*Value[uint64, int]).Get(v)
}

// Value holds a key and value for generic method calls.
type Value[K, V any] struct {
	Key  K
	Data V
}

// Get returns the stored key and value.
// +checkescape:all
//
//go:nosplit
func (v *Value[K, V]) Get() (K, V) {
	return v.Key, v.Data
}

// Copy allocates a value, without any instantiation in this package.
// +mustescape:local,heap
//
//go:noinline
//go:nosplit
func (v *Value[K, V]) Copy() *V {
	value := new(V)
	*value = v.Data
	return value
}

// +checkescape:all
//
//go:nosplit
func genericDelegate[T any](v T) T {
	return GenericIdentity(v)
}

// +mustescape:local,heap
//
//go:noinline
//go:nosplit
func genericAllocate[T any]() *T {
	return new(T)
}

// GenericIdentity returns its argument.
// +checkescape:all
//
//go:nosplit
func GenericIdentity[T any](v T) T {
	return v
}

// GenericHeap allocates a value, without any instantiation in this package.
// +mustescape:local,heap
//
//go:noinline
//go:nosplit
func GenericHeap[T any]() *T {
	return new(T)
}

// GenericScratch can need heap storage even though the local does not escape.
// +mustescape:local,heap
//
//go:noinline
//go:nosplit
func GenericScratch[T any](v T, i int) T {
	var values [2]T
	values[i] = v
	return values[0]
}

// GenericSplit needs a stack check, without any instantiation in this package.
// +mustescape:local,stack
//
//go:noinline
func GenericSplit[T any](v T) T {
	internalFunc()
	return v
}

// GenericClosure allocates from a closure within an uninstantiated function.
// +mustescape:heap
//
//go:noinline
//go:nosplit
func GenericClosure[T any]() *T {
	return func() *T {
		return new(T)
	}()
}

// GenericDispatch retains the uncertainty of a constrained method call.
// +mustescape:local,interface
//
//go:noinline
//go:nosplit
func GenericDispatch[T Interface](v T) {
	v.Foo()
}

// GenericDynamic retains the uncertainty of a callback.
// +mustescape:local,dynamic
//
//go:noinline
//go:nosplit
func GenericDynamic[T any](f func(T), v T) {
	f(v)
}

// GenericNumeric uses operations that are safe for its entire type set.
// +checkescape:all
//
//go:noinline
//go:nosplit
func GenericNumeric[T ~uint64](a, b T) (bool, uint32) {
	return a == b, uint32(a)
}

// GenericLookup searches a read-only collection, including string equality.
// +checkescape:all
//
//go:noinline
//go:nosplit
func GenericLookup[K ~uint64 | ~string, V any](values []Value[K, V], key K) (V, bool) {
	for i := range values {
		if values[i].Key == key {
			return values[i].Data, true
		}
	}
	var zero V
	return zero, false
}

// GenericEqual may dispatch through an interface or aggregate equality helper.
// +mustescape:local,dynamic
//
//go:noinline
//go:nosplit
func GenericEqual[T comparable](a, b T) bool {
	return a == b
}

// GenericBox may allocate storage for the interface value.
// +mustescape:local,heap,dynamic
//
//go:noinline
//go:nosplit
func GenericBox[T any](v T) any {
	return v
}

// GenericBytes allocates writable storage for the string contents.
// +mustescape:local,heap,dynamic
//
//go:noinline
//go:nosplit
func GenericBytes[T ~string](v T) []byte {
	return []byte(v)
}

// GenericAssert may need runtime interface assertion helpers.
// +mustescape:local,dynamic
//
//go:noinline
//go:nosplit
func GenericAssert[T any](v any) (T, bool) {
	value, ok := v.(T)
	return value, ok
}

// GenericReceive calls the channel runtime.
// +mustescape:local,dynamic
//
//go:noinline
//go:nosplit
func GenericReceive[T any](ch <-chan T) T {
	return <-ch
}

// ConcreteReceive requires the same runtime call as GenericReceive.
// +mustescape:local,dynamic
//
//go:noinline
//go:nosplit
func ConcreteReceive(ch <-chan int) int {
	return <-ch
}

// ConcreteEqual may dispatch to an equality helper, like GenericEqual.
// +mustescape:local,dynamic
//
//go:noinline
//go:nosplit
func ConcreteEqual(a, b any) bool {
	return a == b
}

// ConcreteBox uses an explicit conversion with an SSA source position.
// +mustescape:local,heap,dynamic
//
//go:noinline
//go:nosplit
func ConcreteBox(v [4]uint64) any {
	return any(v)
}

// ConcreteBoxImplicit loses the conversion's source position in SSA. Its
// return is deliberately on a different line from the allocation.
// +mustescape:local,heap,dynamic
//
//go:noinline
//go:nosplit
func ConcreteBoxImplicit(v [4]uint64) any {
	var boxed any = v
	return boxed
}

// The compiler can eliminate these concrete operations even though their SSA
// instructions can require runtime calls for other types or uses.
// +checkescape:all
//
//go:noinline
//go:nosplit
func concreteEqualElided(a, b [1]uintptr) bool {
	return a == b
}

// +checkescape:all
//
//go:noinline
//go:nosplit
func concreteBoxElided(v int) int {
	var boxed any = v
	return boxed.(int)
}

// An unrelated non-escaping call and a stack split are not evidence of an
// implicit allocation. The call ensures that the compiler retains the split.
// +checkescape:hard,dynamic
// +mustescape:local,stack
//
//go:noinline
func concreteBoxElidedWithCall(v int) int {
	internalFunc()
	var boxed any = v
	return boxed.(int)
}

// Pointer boxing never needs storage, even with another call in the function.
// +checkescape:all
//
//go:noinline
//go:nosplit
func concretePointerBox(v *int) any {
	internalFunc()
	return v
}

// Panic's call does not imply that either constant conversion allocates.
// Cover both implicit boxing without an SSA position and an explicit cast.
// +checkescape:all
//
//go:noinline
//go:nosplit
func concreteConstantPanic(explicit bool, s string) {
	if len(s) != 0 {
		panic(fmt.Sprintf("%s", s)) // escapes: formatted panic.
	}
	if explicit {
		panic(any("explicit constant"))
	}
	panic("implicit constant")
}

// The real allocation belongs to Heap, not to the constant boxing here.
// +checkescape:local,heap,dynamic
// +mustescape:heap
//
//go:noinline
//go:nosplit
func concreteConstantBoxWithAllocation() (any, *Type) {
	p := Heap()
	var boxed any = "constant"
	return boxed, p
}

// These concrete types use different runtime boxing helpers from ConcreteBox.
// +mustescape:local,heap,dynamic
//
//go:noinline
//go:nosplit
func concreteBoxString(v string) any {
	return v
}

// +mustescape:local,heap,dynamic
//
//go:noinline
//go:nosplit
func concreteBoxSlice(v []byte) any {
	return v
}

// +mustescape:local,heap,dynamic
//
//go:noinline
//go:nosplit
func concreteBoxUint64(v uint64) any {
	return v
}

// +mustescape:local,heap,dynamic
//
//go:noinline
//go:nosplit
func concreteBoxPointers(v struct{ A, B *int }) any {
	return v
}

// Exempting one implicit conversion must not hide another helper in the body.
// +mustescape:local,heap,dynamic
//
//go:noinline
//go:nosplit
func concreteBoxPartlyExempt(exempt bool, s string, n uint64) any {
	if exempt {
		return s // escapes: this conversion only.
	}
	return n
}

// A same-line call does not imply that the literal conversion allocates.
// +checkescape:all
//
//go:noinline
//go:nosplit
func concreteStringConversionElided() int {
	return concreteSliceLength([]byte("constant"))
}

//go:noinline
//go:nosplit
func concreteSliceLength(b []byte) int {
	return len(b)
}

// Returning the same conversion instead requires an allocated array.
// +mustescape:local,heap,dynamic
//
//go:noinline
//go:nosplit
func concreteStringConversionEscapes() []byte {
	return []byte("constant")
}

// A nonconstant conversion uses a string conversion helper instead.
// +mustescape:local,heap,dynamic
//
//go:noinline
//go:nosplit
func concreteStringConversionDynamic(s string) []byte {
	return []byte(s)
}

// The compiler inlines the comparison, leaving only the unrelated callee.
// +checkescape:all
//
//go:noinline
//go:nosplit
func concreteEqualElidedWithCall(a, b [1]uintptr) bool {
	return concreteBoolIdentity(a == b)
}

//go:noinline
//go:nosplit
func concreteBoolIdentity(v bool) bool {
	return v
}

// Larger composite equality retains a compiler-generated type algorithm.
// +mustescape:local,dynamic
//
//go:noinline
//go:nosplit
func concreteEqualGenerated(a, b [5]string) bool {
	return a == b
}

// String equality is safe both with a memequal call and when it is elided.
// GenericLookup covers the same property across a package/type-parameter boundary.
// +checkescape:all
//
//go:noinline
//go:nosplit
func concreteStringEqual(a, b string) bool {
	return a == b
}

// +checkescape:all
//
//go:noinline
//go:nosplit
func concreteStringEqualElided(a string) bool {
	return concreteBoolIdentity(a == "")
}

// MapLookup calls the runtime even though the caller cannot split its stack.
// +mustescape:local,stack
// +checkescape:hard
//
//go:noinline
//go:nosplit
func MapLookup(m map[uint64]int, key uint64) int {
	return m[key]
}

// MapLookupOK uses the comma-ok form and pointer keys used by metric fields.
// +mustescape:local,stack
// +checkescape:hard
//
//go:noinline
//go:nosplit
func MapLookupOK(m map[*int]int, key *int) (int, bool) {
	value, ok := m[key]
	return value, ok
}

// +mustescape:stack
//
//go:noinline
//go:nosplit
func mapLookupRec(m map[uint64]int, key uint64) int {
	return MapLookup(m, key)
}

// MapUpdate can both grow the map and split the stack.
// +mustescape:local,builtin,stack
//
//go:noinline
//go:nosplit
func MapUpdate(m map[int]int, key, value int) {
	m[key] = value
}

// MapDelete can split the stack without allocating map storage.
// +mustescape:local,stack
// +checkescape:hard
//
//go:noinline
//go:nosplit
func MapDelete(m map[int]int, key int) {
	delete(m, key)
}

// MapClear can split the stack without allocating map storage.
// +mustescape:local,stack
// +checkescape:hard
//
//go:noinline
//go:nosplit
func MapClear(m map[int]int) {
	clear(m)
}

// MapRange invokes runtime iterator helpers.
// +mustescape:local,stack
// +checkescape:hard
//
//go:noinline
//go:nosplit
func MapRange(m map[int]int) int {
	var sum int
	for _, value := range m {
		sum += value
	}
	return sum
}

// String iteration shares SSA instructions with map iteration, but its
// decoderune helper has no nosplit guarantee on both supported architectures.
// +mustescape:local,dynamic
// +checkescape:hard,stack
//
//go:noinline
//go:nosplit
func stringRange(s string) int {
	var sum int
	for _, value := range s {
		sum += int(value)
	}
	return sum
}

// Clearing a slice does not call the map runtime.
// +checkescape:all
//
//go:noinline
//go:nosplit
func clearSlice(s []int) {
	clear(s)
}

// +checkescape:all
//
//go:noinline
//go:nosplit
func clearPointerSlice(s []*int) {
	clear(s)
}

// +checkescape:all
//
//go:noinline
//go:nosplit
func exemptMapRange(m map[int]int) int {
	var sum int
	for _, value := range m { // escapes: Test an exemption on an implicit runtime call.
		sum += value
	}
	return sum
}

// GenericMapLookup requires a runtime map helper for every instantiation.
// +mustescape:local,stack
// +checkescape:hard
//
//go:noinline
//go:nosplit
func GenericMapLookup[K comparable, V any](m map[K]V, key K) V {
	return m[key]
}

// GenericClear permits maps as well as slices, so clearing can split the stack.
// +mustescape:local,stack
// +checkescape:hard
//
//go:noinline
//go:nosplit
func GenericClear[T ~[]int | ~map[int]int](v T) {
	clear(v)
}

// GenericClearSlice proves that every permitted type uses slice clearing.
// +checkescape:all
//
//go:noinline
//go:nosplit
func GenericClearSlice[T ~[]*int](v T) {
	clear(v)
}

// A generic map iterator has the same source/exemption owner as a concrete one.
// +checkescape:all
//
//go:noinline
//go:nosplit
func genericExemptMapRange[K comparable, V any](m map[K]V) int {
	var count int
	for range m { // escapes: this iterator only.
		count++
	}
	return count
}

// Constructor syntax is not proof of retained heap allocation.
// +checkescape:all
//
//go:noinline
//go:nosplit
func elidedMap() int {
	m := make(map[int]int)
	return len(m)
}

// +checkescape:all
//
//go:noinline
//go:nosplit
func elidedClosure(value int) bool {
	f := func() int { return value }
	return f == nil
}

// SSA marks both locals as nonescaping, but gc's size limit forces only the
// large one onto the heap. Indexing prevents the storage from being lifted.
// +mustescape:local,heap
//
//go:noinline
//go:nosplit
func largeLocal(i, j int, value byte) byte {
	var values [256 * 1024]byte
	values[i] = value
	return values[j]
}

// +checkescape:all
//
//go:noinline
//go:nosplit
func smallLocal(i, j int, value byte) byte {
	var values [4]byte
	values[i] = value
	return values[j]
}

// The append allocates builtin storage, but the address-taken local on the same
// source line remains on the stack. These are distinct diagnostic categories.
// +mustescape:local,builtin
// +checkescape:heap
//
//go:noinline
//go:nosplit
func stackLocalWithAppend(s []int, value int) int {
	values := [1]int{len(append(s, value))}
	storeInt(&values[0], value)
	return values[0]
}

//go:noinline
//go:nosplit
func storeInt(dst *int, value int) {
	*dst = value
}

// A call on a declaration line is not evidence of that function's own prologue.
// +checkescape:all
//
//go:noinline
//go:nosplit
func sameLineCall(value bool) bool { return concreteBoolIdentity(value) }

// The compiler can use stack storage for these appends and promote the backing
// array only at return. Its slice pass requires at least two appends.
// +mustescape:local,builtin
// +checkescape:heap
//
//go:noinline
//go:nosplit
func promotedAppends() []int {
	var values []int
	values = append(values, 1)
	values = append(values, 2)
	return values
}

// The same code must honor an exemption at the retained promotion helper.
// +checkescape:all
//
//go:noinline
//go:nosplit
func exemptPromotedAppends() []int {
	var values []int
	values = append(values, 1)
	values = append(values, 2)
	return values // escapes: heap promotion of stack-backed append storage.
}

// Preserving capacity uses the buffered growth and capacity-preserving move
// helpers rather than only the original growslice implementation.
// +mustescape:local,builtin
// +checkescape:heap
//
//go:noinline
//go:nosplit
func bufferedAppends(n int) ([]int, int) {
	var values []int
	for i := range n {
		values = append(values, i)
	}
	return values, cap(values)
}

// An elided append must not borrow another append's exempt growth call.
// +checkescape:all
//
//go:noinline
//go:nosplit
func elidedAppendWithExemptGrowth(values []int) int {
	values = append(values, 1) // escapes: this growing append only.
	var local [2]int
	slice := append(local[:0], 1)
	return len(values) + slice[0]
}

// Constant-capacity make is SSA Alloc + Slice but retains runtime.makeslice
// when the backing storage escapes. Keep its existing heap category.
// +mustescape:local,heap
// +checkescape:builtin
//
//go:noinline
//go:nosplit
func constantMake() []byte {
	return make([]byte, 8)
}

// +checkescape:all
//
//go:noinline
//go:nosplit
func elidedConstantMake(value byte) byte {
	values := make([]byte, 8)
	values[0] = value
	return values[0]
}

// A make on the same line cannot change an unrelated stack local into a heap
// allocation. Source operation identity and compiler helper family both matter.
// +mustescape:local,builtin
// +checkescape:heap
//
//go:noinline
//go:nosplit
func stackLocalWithMake(n int) []byte {
	value := len(make([]byte, n))
	storeInt(&value, n)
	return make([]byte, value)
}

// Exempting source growth does not exempt a distinct compiler-inserted
// promotion at the return site.
// +mustescape:local,builtin
// +checkescape:heap
//
//go:noinline
//go:nosplit
func promotedExemptAppends() []int {
	var values []int
	values = append(values, 1) // escapes: source growth only.
	values = append(values, 2) // escapes: source growth only.
	return values
}

// Adding an unrelated elided append must not change the promotion's ownership
// or make its finding depend on whether a source append is exempt.
// +mustescape:local,builtin
// +checkescape:heap
//
//go:noinline
//go:nosplit
func promotedExemptAppendsWithLocal() ([]int, int) {
	var values []int
	values = append(values, 1) // escapes: source growth only.
	values = append(values, 2) // escapes: source growth only.
	var local [2]int
	slice := append(local[:0], 3)
	return values, slice[0]
}

// Returning a capture-free function does not execute its promoted appends.
// +checkescape:all
//
//go:noinline
//go:nosplit
func returnedAppendingClosure() func() []int {
	return func() []int {
		var values []int
		values = append(values, 1)
		values = append(values, 2)
		return values
	}
}

// Calling the same closure shape must still import the child's allocation.
// +mustescape:builtin
//
//go:noinline
//go:nosplit
func calledAppendingClosure() []int {
	return func() []int {
		var values []int
		values = append(values, 1)
		values = append(values, 2)
		return values
	}()
}

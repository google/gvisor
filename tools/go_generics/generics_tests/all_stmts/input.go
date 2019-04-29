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

package tests

import (
	"sync"
)

type T int

func h(T) {
}

type s struct {
	a, b int
	c    []int
}

func g(T) *s {
	return &s{}
}

func f() (T, []int) {
	// Branch.
	goto T
	goto R

	// Labeled.
T:
	_ = T(0)

	// Empty.
R:
	;

	// Assignment with definition.
	a, b, c := T(1), T(2), T(3)
	_, _, _ = a, b, c

	// Assignment without definition.
	g(T(0)).a, g(T(1)).b, c = int(T(1)), int(T(2)), T(3)
	_, _, _ = a, b, c

	// Block.
	{
		var T T
		T = 0
		_ = T
	}

	// Declarations.
	type Type T
	const Const T = 10
	var g1 func(T, int, ...T) (int, T)
	var v T
	var w = T(0)
	{
		var T struct {
			f []T
		}
		_ = T
	}

	// Defer.
	defer g1(T(0), 1)

	// Expression.
	h(v + w + T(1))

	// For statements.
	for i := T(0); i < T(10); i++ {
		var T func(int) T
		v := T(0)
		_ = v
	}

	for {
		var T func(int) T
		v := T(0)
		_ = v
	}

	// Go.
	go g1(T(0), 1)

	// If statements.
	if a != T(1) {
		var T func(int) T
		v := T(0)
		_ = v
	}

	if a := T(0); a != T(1) {
		var T func(int) T
		v := T(0)
		_ = v
	}

	if a := T(0); a != T(1) {
		var T func(int) T
		v := T(0)
		_ = v
	} else if b := T(0); b != T(1) {
		var T func(int) T
		v := T(0)
		_ = v
	} else if T := T(0); T != 1 {
		T++
	} else {
		T--
	}

	if a := T(0); a != T(1) {
		var T func(int) T
		v := T(0)
		_ = v
	} else {
		var T func(int) T
		v := T(0)
		_ = v
	}

	// Inc/Dec statements.
	(*(*T)(nil))++
	(*(*T)(nil))--

	// Range statements.
	for g(T(0)).a, g(T(1)).b = range g(T(10)).c {
		var d T
		_ = d
	}

	for T, b := range g(T(10)).c {
		_ = T
		_ = b
	}

	// Select statement.
	{
		var fch func(T) chan int

		select {
		case <-fch(T(30)):
			var T T
			T = 0
			_ = T
		default:
			var T T
			T = 0
			_ = T
		case T := <-fch(T(30)):
			T = 0
			_ = T
		case g(T(0)).a = <-fch(T(30)):
			var T T
			T = 0
			_ = T
		case fch(T(30)) <- int(T(0)):
			var T T
			T = 0
			_ = T
		}
	}

	// Send statements.
	{
		var ch chan T
		var fch func(T) chan int

		ch <- T(0)
		fch(T(1)) <- g(T(10)).a
	}

	// Switch statements.
	{
		var a T
		var b int
		switch {
		case a == T(0):
			var T T
			T = 0
			_ = T
		case a < T(0), b < g(T(10)).a:
			var T T
			T = 0
			_ = T
		default:
			var T T
			T = 0
			_ = T
		}
	}

	switch T(g(T(10)).a) {
	case T(0):
		var T T
		T = 0
		_ = T
	case T(1), T(g(T(10)).a):
		var T T
		T = 0
		_ = T
	default:
		var T T
		T = 0
		_ = T
	}

	switch b := g(T(10)); T(b.a) + T(10) {
	case T(0):
		var T T
		T = 0
		_ = T
	case T(1), T(g(T(10)).a):
		var T T
		T = 0
		_ = T
	default:
		var T T
		T = 0
		_ = T
	}

	// Type switch statements.
	{
		var interfaceFunc func(T) interface{}

		switch interfaceFunc(T(0)).(type) {
		case *T, T, int:
			var T T
			T = 0
			_ = T
		case sync.Mutex, **T:
			var T T
			T = 0
			_ = T
		default:
			var T T
			T = 0
			_ = T
		}

		switch x := interfaceFunc(T(0)).(type) {
		case *T, T, int:
			var T T
			T = 0
			_ = T
			_ = x
		case sync.Mutex, **T:
			var T T
			T = 0
			_ = T
		default:
			var T T
			T = 0
			_ = T
		}

		switch t := T(0); x := interfaceFunc(T(0) + t).(type) {
		case *T, T, int:
			var T T
			T = 0
			_ = T
			_ = x
		case sync.Mutex, **T:
			var T T
			T = 0
			_ = T
		default:
			var T T
			T = 0
			_ = T
		}
	}

	// Return statement.
	return T(10), g(T(11)).c
}

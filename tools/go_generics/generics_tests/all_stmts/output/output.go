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

package main

import (
	"sync"
)

func h(Q) {
}

type s struct {
	a, b int
	c    []int
}

func g(Q) *s {
	return &s{}
}

func f() (Q, []int) {
	// Branch.
	goto T
	goto R

	// Labeled.
T:
	_ = Q(0)

	// Empty.
R:
	;

	// Assignment with definition.
	a, b, c := Q(1), Q(2), Q(3)
	_, _, _ = a, b, c

	// Assignment without definition.
	g(Q(0)).a, g(Q(1)).b, c = int(Q(1)), int(Q(2)), Q(3)
	_, _, _ = a, b, c

	// Block.
	{
		var T Q
		T = 0
		_ = T
	}

	// Declarations.
	type Type Q
	const Const Q = 10
	var g1 func(Q, int, ...Q) (int, Q)
	var v Q
	var w = Q(0)
	{
		var T struct {
			f []Q
		}
		_ = T
	}

	// Defer.
	defer g1(Q(0), 1)

	// Expression.
	h(v + w + Q(1))

	// For statements.
	for i := Q(0); i < Q(10); i++ {
		var T func(int) Q
		v := T(0)
		_ = v
	}

	for {
		var T func(int) Q
		v := T(0)
		_ = v
	}

	// Go.
	go g1(Q(0), 1)

	// If statements.
	if a != Q(1) {
		var T func(int) Q
		v := T(0)
		_ = v
	}

	if a := Q(0); a != Q(1) {
		var T func(int) Q
		v := T(0)
		_ = v
	}

	if a := Q(0); a != Q(1) {
		var T func(int) Q
		v := T(0)
		_ = v
	} else if b := Q(0); b != Q(1) {
		var T func(int) Q
		v := T(0)
		_ = v
	} else if T := Q(0); T != 1 {
		T++
	} else {
		T--
	}

	if a := Q(0); a != Q(1) {
		var T func(int) Q
		v := T(0)
		_ = v
	} else {
		var T func(int) Q
		v := T(0)
		_ = v
	}

	// Inc/Dec statements.
	(*(*Q)(nil))++
	(*(*Q)(nil))--

	// Range statements.
	for g(Q(0)).a, g(Q(1)).b = range g(Q(10)).c {
		var d Q
		_ = d
	}

	for T, b := range g(Q(10)).c {
		_ = T
		_ = b
	}

	// Select statement.
	{
		var fch func(Q) chan int

		select {
		case <-fch(Q(30)):
			var T Q
			T = 0
			_ = T
		default:
			var T Q
			T = 0
			_ = T
		case T := <-fch(Q(30)):
			T = 0
			_ = T
		case g(Q(0)).a = <-fch(Q(30)):
			var T Q
			T = 0
			_ = T
		case fch(Q(30)) <- int(Q(0)):
			var T Q
			T = 0
			_ = T
		}
	}

	// Send statements.
	{
		var ch chan Q
		var fch func(Q) chan int

		ch <- Q(0)
		fch(Q(1)) <- g(Q(10)).a
	}

	// Switch statements.
	{
		var a Q
		var b int
		switch {
		case a == Q(0):
			var T Q
			T = 0
			_ = T
		case a < Q(0), b < g(Q(10)).a:
			var T Q
			T = 0
			_ = T
		default:
			var T Q
			T = 0
			_ = T
		}
	}

	switch Q(g(Q(10)).a) {
	case Q(0):
		var T Q
		T = 0
		_ = T
	case Q(1), Q(g(Q(10)).a):
		var T Q
		T = 0
		_ = T
	default:
		var T Q
		T = 0
		_ = T
	}

	switch b := g(Q(10)); Q(b.a) + Q(10) {
	case Q(0):
		var T Q
		T = 0
		_ = T
	case Q(1), Q(g(Q(10)).a):
		var T Q
		T = 0
		_ = T
	default:
		var T Q
		T = 0
		_ = T
	}

	// Type switch statements.
	{
		var interfaceFunc func(Q) interface{}

		switch interfaceFunc(Q(0)).(type) {
		case *Q, Q, int:
			var T Q
			T = 0
			_ = T
		case sync.Mutex, **Q:
			var T Q
			T = 0
			_ = T
		default:
			var T Q
			T = 0
			_ = T
		}

		switch x := interfaceFunc(Q(0)).(type) {
		case *Q, Q, int:
			var T Q
			T = 0
			_ = T
			_ = x
		case sync.Mutex, **Q:
			var T Q
			T = 0
			_ = T
		default:
			var T Q
			T = 0
			_ = T
		}

		switch t := Q(0); x := interfaceFunc(Q(0) + t).(type) {
		case *Q, Q, int:
			var T Q
			T = 0
			_ = T
			_ = x
		case sync.Mutex, **Q:
			var T Q
			T = 0
			_ = T
		default:
			var T Q
			T = 0
			_ = T
		}
	}

	// Return statement.
	return Q(10), g(Q(11)).c
}

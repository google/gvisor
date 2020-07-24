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

package main

import (
	"./lib"
)

type newType struct {
	a Q
	b lib.T
	c *Q
	d (Q)
	e chan Q
	f <-chan Q
	g chan<- Q
	h []Q
	i [10]Q
	j map[Q]Q
	k func(Q, Q) (Q, Q)
	l interface {
		f(Q)
	}
	m struct {
		Q
		a Q
	}
}

func f(...Q) {
}

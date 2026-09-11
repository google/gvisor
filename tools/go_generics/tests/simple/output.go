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

import _ "os" // Earlier blank import.

import "fmt" // Later named import.

var globalNew Q

func fNew(_ Q, a int) {
}

func gNew(a Q, b int) {
	var c Q
	_ = c

	d := (*Q)(nil)
	_ = d
	_ = new(Q) // escapes: test annotation.
}

type RNew struct {
	Q
	a *Q
}

var (
	ZNew *Q = (*Q)(nil)
)

const (
	XNew Q = (Q)(0)
)

type YNew Q

func hNew(a Q) string {
	return fmt.Sprint(a) // escapes: test annotation in a second file.
}

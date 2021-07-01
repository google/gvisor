// Copyright 2020 The gVisor Authors.
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

package test

type alignedStruct32 struct {
	v int32
}

type alignedStruct64 struct {
	v int64
}

type alignedStructGood struct {
	v0 alignedStruct32
	v1 alignedStruct32
	v2 alignedStruct64
}

type alignedStructGoodArray0 struct {
	v0 [3]alignedStruct32
	v1 [3]alignedStruct32
	v2 alignedStruct64
}

type alignedStructGoodArray1 [16]alignedStructGood

type alignedStructBad struct {
	v0 alignedStruct32
	v1 alignedStruct64
	v2 alignedStruct32
}

type alignedStructBadArray0 struct {
	v0 [3]alignedStruct32
	v1 [2]alignedStruct64
	v2 [1]alignedStruct32
}

type alignedStructBadArray1 [16]alignedStructBad

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

type unregisteredEmptyStruct struct{}

// typeOnlyEmptyStruct just implements the state.Type interface.
type typeOnlyEmptyStruct struct{}

func (*typeOnlyEmptyStruct) StateTypeName() string { return "registeredEmptyStruct" }

func (*typeOnlyEmptyStruct) StateFields() []string { return nil }

// +stateify savable
type savableEmptyStruct struct{}

// +stateify savable
type emptyStructPointer struct {
	nothing *struct{}
}

// +stateify savable
type outerSame struct {
	inner inner
}

// +stateify savable
type outerFieldFirst struct {
	inner inner
	v     int64
}

// +stateify savable
type outerFieldSecond struct {
	v     int64
	inner inner
}

// +stateify savable
type outerArray struct {
	inner [2]inner
}

// +stateify savable
type inner struct {
	v int64
}

// +stateify savable
type system struct {
	v1 interface{}
	v2 interface{}
}

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
	"testing"

	"gvisor.dev/gvisor/pkg/state"
)

func TestEmptyStruct(t *testing.T) {
	runTestCases(t, false, "plain", []interface{}{
		unregisteredEmptyStruct{},
		typeOnlyEmptyStruct{},
		savableEmptyStruct{},
	})
	runTestCases(t, false, "pointers", pointersTo([]interface{}{
		unregisteredEmptyStruct{},
		typeOnlyEmptyStruct{},
		savableEmptyStruct{},
	}))
	runTestCases(t, false, "interfaces-pass", interfacesTo([]interface{}{
		// Only registered types can be dispatched via interfaces. All
		// other types should fail, even if it is the empty struct.
		savableEmptyStruct{},
	}))
	runTestCases(t, true, "interfaces-fail", interfacesTo([]interface{}{
		unregisteredEmptyStruct{},
		typeOnlyEmptyStruct{},
	}))
	runTestCases(t, false, "interfacesToPointers-pass", interfacesTo(pointersTo([]interface{}{
		savableEmptyStruct{},
	})))
	runTestCases(t, true, "interfacesToPointers-fail", interfacesTo(pointersTo([]interface{}{
		unregisteredEmptyStruct{},
		typeOnlyEmptyStruct{},
	})))

	// Ensuring empty struct aliasing works.
	es := emptyStructPointer{new(struct{})}
	runTestCases(t, false, "empty-struct-pointers", []interface{}{
		emptyStructPointer{},
		es,
		[]emptyStructPointer{es, es}, // Same pointer.
	})
}

func TestRegisterTypeOnlyStruct(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("Register did not panic")
		}
	}()
	state.Register((*typeOnlyEmptyStruct)(nil))
}

func TestEmbeddedPointers(t *testing.T) {
	var (
		ofs outerSame
		of1 outerFieldFirst
		of2 outerFieldSecond
		oa  outerArray
	)

	runTestCases(t, false, "embedded-pointers", []interface{}{
		system{&ofs, &ofs.inner},
		system{&ofs.inner, &ofs},
		system{&of1, &of1.inner},
		system{&of1.inner, &of1},
		system{&of2, &of2.inner},
		system{&of2.inner, &of2},
		system{&oa, &oa.inner[0]},
		system{&oa, &oa.inner[1]},
		system{&oa.inner[0], &oa},
		system{&oa.inner[1], &oa},
	})
}

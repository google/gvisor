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

//go:build race
// +build race

package tests

import (
	"testing"

	"gvisor.dev/gvisor/pkg/state"
)

// faker calls itself whatever is in the name field.
type faker struct {
	Name   string
	Fields []string
}

func (f *faker) StateTypeName() string {
	return f.Name
}

func (f *faker) StateFields() []string {
	return f.Fields
}

// fakerWithSaverLoader has all it needs.
type fakerWithSaverLoader struct {
	faker
}

func (f *fakerWithSaverLoader) StateSave(m state.Sink) {}

func (f *fakerWithSaverLoader) StateLoad(m state.Source) {}

// fakerOther calls itself .. uh, itself?
type fakerOther string

func (f *fakerOther) StateTypeName() string {
	return string(*f)
}

func (f *fakerOther) StateFields() []string {
	return nil
}

func newFakerOther(name string) *fakerOther {
	f := fakerOther(name)
	return &f
}

// fakerOtherBadFields returns non-nil fields.
type fakerOtherBadFields string

func (f *fakerOtherBadFields) StateTypeName() string {
	return string(*f)
}

func (f *fakerOtherBadFields) StateFields() []string {
	return []string{string(*f)}
}

func newFakerOtherBadFields(name string) *fakerOtherBadFields {
	f := fakerOtherBadFields(name)
	return &f
}

// fakerOtherSaverLoader implements SaverLoader methods.
type fakerOtherSaverLoader string

func (f *fakerOtherSaverLoader) StateTypeName() string {
	return string(*f)
}

func (f *fakerOtherSaverLoader) StateFields() []string {
	return nil
}

func (f *fakerOtherSaverLoader) StateSave(m state.Sink) {}

func (f *fakerOtherSaverLoader) StateLoad(m state.Source) {}

func newFakerOtherSaverLoader(name string) *fakerOtherSaverLoader {
	f := fakerOtherSaverLoader(name)
	return &f
}

func TestRegisterPrimitives(t *testing.T) {
	for _, typeName := range []string{
		"int",
		"int8",
		"int16",
		"int32",
		"int64",
		"uint",
		"uintptr",
		"uint8",
		"uint16",
		"uint32",
		"uint64",
		"float32",
		"float64",
		"complex64",
		"complex128",
		"string",
	} {
		t.Run("struct/"+typeName, func(t *testing.T) {
			defer func() {
				if r := recover(); r == nil {
					t.Errorf("Registering type %q did not panic", typeName)
				}
			}()
			state.Register(&faker{
				Name: typeName,
			})
		})
		t.Run("other/"+typeName, func(t *testing.T) {
			defer func() {
				if r := recover(); r == nil {
					t.Errorf("Registering type %q did not panic", typeName)
				}
			}()
			state.Register(newFakerOther(typeName))
		})
	}
}

func TestRegisterBad(t *testing.T) {
	const (
		goodName    = "foo"
		firstField  = "a"
		secondField = "b"
	)
	for name, object := range map[string]state.Type{
		"non-struct-with-fields":                  newFakerOtherBadFields(goodName),
		"non-struct-with-saverloader":             newFakerOtherSaverLoader(goodName),
		"struct-without-saverloader":              &faker{Name: goodName},
		"non-struct-duplicate-with-struct":        newFakerOther((new(alreadyRegisteredStruct)).StateTypeName()),
		"non-struct-duplicate-with-non-struct":    newFakerOther((new(alreadyRegisteredOther)).StateTypeName()),
		"struct-duplicate-with-struct":            &fakerWithSaverLoader{faker{Name: (new(alreadyRegisteredStruct)).StateTypeName()}},
		"struct-duplicate-with-non-struct":        &fakerWithSaverLoader{faker{Name: (new(alreadyRegisteredOther)).StateTypeName()}},
		"struct-with-empty-field":                 &fakerWithSaverLoader{faker{Name: goodName, Fields: []string{""}}},
		"struct-with-empty-field-and-non-empty":   &fakerWithSaverLoader{faker{Name: goodName, Fields: []string{firstField, ""}}},
		"struct-with-duplicate-field":             &fakerWithSaverLoader{faker{Name: goodName, Fields: []string{firstField, firstField}}},
		"struct-with-duplicate-field-and-non-dup": &fakerWithSaverLoader{faker{Name: goodName, Fields: []string{firstField, secondField, firstField}}},
	} {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if r := recover(); r == nil {
					t.Errorf("Registering object %#v did not panic", object)
				}
			}()
			state.Register(object)
		})

	}
}

func TestRegisterTypeOnlyStruct(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("Register did not panic")
		}
	}()
	state.Register((*typeOnlyEmptyStruct)(nil))
}

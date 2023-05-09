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

// Package facts implements alternate fact types.
package facts

import (
	"encoding/gob"
	"fmt"
	"go/types"
	"io"
	"reflect"
	"sort"

	"archive/zip"
	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/types/objectpath"
)

// Serializer is used for fact serialization.
//
// It generalizes over the Package and Bundle types.
type Serializer interface {
	Serialize(w io.Writer) error
}

// item is used for serialiation.
type item struct {
	Key   string
	Value any
}

// writeItems is an implementation of Serialize.
//
// This will sort the list as a side effect.
func writeItems(w io.Writer, is []item) error {
	sort.Slice(is, func(i, j int) bool {
		return is[i].Key < is[j].Key
	})
	enc := gob.NewEncoder(w)
	return enc.Encode(is)
}

// readItems is an implementation of io.ReaderTo.ReadTo.
func readItems(r io.Reader) (is []item, err error) {
	dec := gob.NewDecoder(r)
	err = dec.Decode(&is)
	return
}

// Package is a set of facts about a single package.
//
// These use the types.Object as the key because this is canonical. Normally,
// this is canonical only in the context of a single types.Package. However,
// because all imports are shared across all packages, there is a single
// canonical types.Object shared among all packages being analyzed.
type Package struct {
	Objects map[types.Object][]analysis.Fact
}

// NewPackage returns a new set of Package facts.
func NewPackage() *Package {
	return &Package{
		Objects: make(map[types.Object][]analysis.Fact),
	}
}

func extractObjectpath(obj types.Object) (name objectpath.Path, err error) {
	defer func() {
		// Unfortunately, objectpath.For will occasionally panic for
		// certain objects. This happens with basic analysis packages
		// (buildssa), and therefore cannot be avoided.
		if r := recover(); r != nil {
			err = fmt.Errorf("panic: %v", r)
		}
	}()
	// Allow empty name for no object.
	if obj != nil {
		name, err = objectpath.For(obj)
	}
	return
}

// Serialize implements Serializer.Serialize.
func (p *Package) Serialize(w io.Writer) error {
	is := make([]item, 0, len(p.Objects))
	for obj, facts := range p.Objects {
		name, err := extractObjectpath(obj)
		if err != nil {
			continue // Not exported; expected.
		}
		is = append(is, item{
			Key:   string(name),
			Value: facts,
		})
	}
	return writeItems(w, is)
}

// ReadFrom deserializes a package.
func (p *Package) ReadFrom(pkg *types.Package, r io.Reader) error {
	is, err := readItems(r)
	if err != nil {
		return err
	}
	for _, fi := range is {
		var (
			obj types.Object
			err error
		)
		if fi.Key != "" {
			obj, err = objectpath.Object(pkg, objectpath.Path(fi.Key))
		}
		if err != nil {
			// This could simply be a fact saved on an unexported
			// object. We just suppress this error and ignore it.
			continue
		}
		p.Objects[obj] = fi.Value.([]analysis.Fact)
	}
	return nil
}

// ExportFact exports an object fact.
func (p *Package) ExportFact(obj types.Object, ptr analysis.Fact) {
	for i, v := range p.Objects[obj] {
		if reflect.TypeOf(v) == reflect.TypeOf(ptr) {
			p.Objects[obj][i] = ptr // Replace.
			return
		}
	}
	// Append this new fact.
	p.Objects[obj] = append(p.Objects[obj], ptr)
}

// ImportFact imports an object fact.
func (p *Package) ImportFact(obj types.Object, ptr analysis.Fact) bool {
	if p == nil {
		return false // No facts.
	}
	for _, v := range p.Objects[obj] {
		if reflect.TypeOf(v) == reflect.TypeOf(ptr) {
			// Set the value to the element saved in our facts.
			reflect.ValueOf(ptr).Elem().Set(reflect.ValueOf(v).Elem())
			return true
		}
	}
	return false
}

// Bundle is a set of facts about different packages.
//
// This is used to serialize a collection of facts about different packages,
// which will be loaded and evaluated lazily.
type Bundle struct {
	reader  *zip.ReadCloser
	decoded map[string]*Package
}

// NewBundle makes a new package bundle.
func NewBundle() *Bundle {
	return &Bundle{
		decoded: make(map[string]*Package),
	}
}

// Serialize implements Serializer.Serialize.
func (b *Bundle) Serialize(w io.Writer) error {
	zw := zip.NewWriter(w)
	for pkg, facts := range b.decoded {
		if facts == nil {
			// Some facts may be omitted for bundles, if there is
			// only type information but no source information. We
			// omit these completely from the serialized bundle.
			continue
		}
		if len(facts.Objects) == 0 {
			// Similarly prevent serializing any Packages that have
			// no facts associated with them. This will speed up
			// deserialization since the Package can handle nil.
			continue
		}
		wc, err := zw.Create(pkg)
		if err != nil {
			return err
		}
		if err := facts.Serialize(wc); err != nil {
			return err
		}
	}
	return zw.Close()
}

// BundleFrom may be used to create a new bundle that deserializes the contents
// of the given file.
//
// Note that there is no explicit close mechanism, and the underlying file will
// be closed only when the object is finalized.
func BundleFrom(filename string) (*Bundle, error) {
	r, err := zip.OpenReader(filename)
	if err != nil {
		return nil, err
	}
	return &Bundle{
		reader:  r,
		decoded: make(map[string]*Package),
	}, nil
}

// Add adds the package to the Bundle.
func (b *Bundle) Add(path string, facts *Package) {
	b.decoded[path] = facts
}

// Package looks up the given package in the bundle.
func (b *Bundle) Package(pkg *types.Package) (*Package, error) {
	// Already decoded?
	if facts, ok := b.decoded[pkg.Path()]; ok {
		return facts, nil
	}

	if b.reader == nil {
		// Nothing available.
		//
		// N.B. some bundles contain only cached packages.
		return nil, nil
	}

	// Find based on the reader.
	for _, f := range b.reader.File {
		if f.Name != pkg.Path() {
			continue
		}

		// Extract from the archive.
		facts := NewPackage()
		rc, err := f.Open()
		if err != nil {
			return nil, err
		}
		defer rc.Close()
		if err := facts.ReadFrom(pkg, rc); err != nil {
			return nil, err
		}

		// Memoize the result.
		b.Add(pkg.Path(), facts)
		return facts, nil
	}

	// Nothing available.
	return nil, fmt.Errorf("no facts available for package %q", pkg.Path())
}

func init() {
	gob.Register((*item)(nil))
	gob.Register(([]analysis.Fact)(nil))
}

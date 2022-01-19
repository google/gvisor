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
	"bytes"
	"encoding/gob"
	"go/types"
	"io"
	"log"
	"reflect"
	"sort"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/types/objectpath"
)

// Writer is used for fact serialization.
type Writer interface {
	io.ReaderFrom
	io.WriterTo
}

// item is used for serialiation.
type item struct {
	Key   string
	Value interface{}
}

// writeItems is an implementation of io.WriterTo.WriteTo.
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
	pkg     *types.Package
	Objects map[types.Object][]analysis.Fact
}

// NewPackage returns a new set of Package facts.
func NewPackage(pkg *types.Package) *Package {
	return &Package{
		pkg:     pkg,
		Objects: make(map[types.Object][]analysis.Fact),
	}
}

// WriteTo implements io.WriterTo.WriteTo.
func (p *Package) WriteTo(w io.Writer) (int64, error) {
	is := make([]item, 0, len(p.Objects))
	for obj, facts := range p.Objects {
		var (
			name objectpath.Path
			err  error
		)
		if obj != nil {
			name, err = objectpath.For(obj)
		}
		if err != nil {
			continue // Not exported, expected.
		}
		for _, fact := range facts {
			is = append(is, item{
				Key:   string(name),
				Value: fact,
			})
		}
	}
	if err := writeItems(w, is); err != nil {
		return 0, err
	}
	return 1, nil
}

// ReadFrom implements io.ReaderFrom.ReadFrom.
func (p *Package) ReadFrom(r io.Reader) (int64, error) {
	is, err := readItems(r)
	if err != nil {
		return 0, err
	}
	for _, fi := range is {
		var (
			obj types.Object
			err error
		)
		if fi.Key != "" {
			obj, err = objectpath.Object(p.pkg, objectpath.Path(fi.Key))
		}
		if err != nil {
			// This could simply be a fact saved on an unexported
			// object. We just suppress this error and ignore it.
			continue
		}
		p.Objects[obj] = append(p.Objects[obj], fi.Value.(analysis.Fact))
	}
	return 1, nil
}

// Size implements worker.Sizer.Size.
func (p *Package) Size() int64 {
	total := int64(0)
	for _, val := range p.Objects {
		total += int64(8)             // 8-byte pointer.
		total += int64(len(val)) * 16 // 16-bytes per object.
	}
	return total
}

// ExportFact exports an object fact.
func (p Package) ExportFact(obj types.Object, ptr analysis.Fact) {
	for i, v := range p.Objects[obj] {
		if reflect.TypeOf(v) == reflect.TypeOf(ptr) {
			// Drop this item from the list.
			p.Objects[obj] = append(p.Objects[obj][:i], p.Objects[obj][i+1:]...)
			break
		}
	}
	// Append this new fact.
	p.Objects[obj] = append(p.Objects[obj], ptr)
}

// ImportFact imports an object fact.
func (p *Package) ImportFact(obj types.Object, ptr analysis.Fact) bool {
	for _, v := range p.Objects[obj] {
		if reflect.TypeOf(v) == reflect.TypeOf(ptr) {
			// Set the value to the element saved in our facts.
			reflect.ValueOf(ptr).Elem().Set(reflect.ValueOf(v).Elem())
			return true
		}
	}
	return false
}

// Bundle is a set of facts about different packages. This is typically
// used for the standard library, but may be used for e.g. module dependencies.
type Bundle struct {
	importer types.Importer
	Packages map[string]*Package
}

// NewBundle returns a new bundle.
func NewBundle(importer types.Importer) *Bundle {
	return &Bundle{
		importer: importer,
		Packages: make(map[string]*Package),
	}
}

// Size implements worker.Sizer.Size.
func (b *Bundle) Size() int64 {
	size := int64(0)
	for filename, p := range b.Packages {
		size += int64(len(filename))
		size += p.Size()
	}
	return size
}

// WriteTo implements io.WriterTo.WriteTo.
func (b *Bundle) WriteTo(w io.Writer) (int64, error) {
	is := make([]item, 0, len(b.Packages))
	for pkg, facts := range b.Packages {
		if facts == nil {
			// Some facts may be omitted for bundles, if there is
			// only type information but no source information. We
			// omit these completely from the serialized bundle.
			continue
		}
		var buf bytes.Buffer
		if _, err := facts.WriteTo(&buf); err != nil {
			return 0, err
		}
		is = append(is, item{
			Key:   pkg,
			Value: buf.Bytes(),
		})
	}
	if err := writeItems(w, is); err != nil {
		return 0, err
	}
	return 1, nil
}

// ReadFrom implements io.ReaderFrom.ReadFrom.
func (b *Bundle) ReadFrom(r io.Reader) (int64, error) {
	is, err := readItems(r)
	if err != nil {
		return 0, err
	}
	for _, fi := range is {
		pkg, err := b.importer.Import(fi.Key)
		if err != nil {
			// There's nothing that can be done here, but we can
			// report the warning at least. This is not expected.
			log.Printf("WARNING: lost facts from %q: %v", fi.Key, err)
			continue
		}
		buf := bytes.NewBuffer(fi.Value.([]byte))
		facts := NewPackage(pkg)
		if _, err := facts.ReadFrom(buf); err != nil {
			return 0, err
		}
		b.Packages[fi.Key] = facts
	}
	return 1, nil
}

// Resolved is a human-readable fact format.
type Resolved map[string]interface{}

// addRecursively adds a entry to a map recursively.
//
// Precondition: len(names) > 0.
func (r Resolved) addRecursively(names []string, value interface{}) {
	start := r
	for i := 0; i < len(names)-1; i++ {
		m, ok := start[names[i]]
		if !ok {
			m = make(Resolved)
			start[names[i]] = m
		} else {
			// This may have been used by a conflicting fact. This
			// should be rare, but we ensure that the proper name
			// itself is used in the scope instead of the fact.
			if _, ok = m.(Resolved); !ok {
				m = make(Resolved)
				start[names[i]] = m
			}
		}
		start = m.(Resolved)
	}
	if _, ok := start[names[len(names)-1]]; ok {
		// Skip, already exists. See above.
		return
	}
	start[names[len(names)-1]] = value
}

// addObject adds the object with the given name.
func (r Resolved) addObject(names []string, obj types.Object, facts *Package, allFactNames map[reflect.Type]string) {
	for _, fact := range facts.Objects[obj] {
		v := reflect.ValueOf(fact)
		typeName, ok := allFactNames[v.Type()]
		if !ok {
			continue
		}
		for v.Kind() == reflect.Ptr {
			v = v.Elem()
		}
		r.addRecursively(append(names, typeName), v.Interface())
	}
}

// walkObject resolves all objects recursively.
//
// Parent should be empty or end with a period.
func (r Resolved) walkObject(parents []string, obj types.Object, facts *Package, allFactNames map[reflect.Type]string) {
	switch x := obj.(type) {
	case *types.TypeName:
		s := append(parents, x.Name())
		r.addObject(s, obj, facts, allFactNames)
		// Skip if just an alias, or if not underlying type.
		if x.IsAlias() || x.Type() == nil || x.Type().Underlying() == nil {
			break
		}
		// Recurse to fields if this is a definition.
		if structType, ok := x.Type().Underlying().(*types.Struct); ok {
			for i := 0; i < structType.NumFields(); i++ {
				r.walkObject(s, structType.Field(i), facts, allFactNames)
			}
		}
	case *types.Func:
		// Skip if no underlying type.
		if x.Type() == nil {
			break
		}
		// Recurse to all parameters.
		sig := x.Type().(*types.Signature)
		s := parents
		if recv := sig.Recv(); recv != nil {
			s = append(s, recv.Type().String())
		}
		s = append(s, x.Name())
		r.addObject(s, obj, facts, allFactNames)
		if params := sig.Params(); params != nil {
			for i := 0; i < params.Len(); i++ {
				r.walkObject(s, params.At(i), facts, allFactNames)
			}
		}
		if results := sig.Results(); results != nil {
			for i := 0; i < results.Len(); i++ {
				r.walkObject(s, results.At(i), facts, allFactNames)
			}
		}
	default:
		r.addObject(append(parents, obj.Name()), obj, facts, allFactNames)
	}
}

// walkScope recursively resolves a scope.
func (r Resolved) walkScope(parents []string, scope *types.Scope, facts *Package, allFactNames map[reflect.Type]string) {
	for _, name := range scope.Names() {
		r.walkObject(parents, scope.Lookup(name), facts, allFactNames)
	}
}

// Resolve resolves all object facts.
func Resolve(pkg *types.Package, localFacts *Package, allFacts *Bundle, allFactNames map[reflect.Type]string) Resolved {
	// Populate the tree. Allocating this slice up front prevents
	// allocation during name resolution. We allow for up to 64 names
	// without allocating a new backing array.
	r := make(Resolved)
	names := make([]string, 0, 64)
	r.walkScope(names, pkg.Scope(), localFacts, allFactNames)
	for _, importPkg := range pkg.Imports() {
		importFacts := allFacts.Packages[importPkg.Path()]
		r.walkScope(append(names, "import", importPkg.Name()), importPkg.Scope(), importFacts, allFactNames)
	}
	return r
}

func init() {
	gob.Register((*item)(nil))
}

// Copyright 2026 The gVisor Authors.
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

package state

import (
	"context"
	"fmt"
	"html"
	"io"
	"reflect"
	"sort"
	"strings"
	"unsafe"
)

// PrintGraph prints a single graph-engine object graph from data, as text or
// HTML.
//
// Since streams don't describe the types of fields, they can only be printed
// by the binary that saved them. Objects are decoded without running their
// load callbacks.
func PrintGraph(w io.Writer, data []byte, graph uint64, asHTML bool) (err error) {
	defer recoverState(&err)
	ds := graphDecodeState{ctx: context.Background(), in: decBuf{b: data}, noCallbacks: true}
	d := &ds.in
	if magic := d.uint32(); magic != streamMagic {
		return stateError(fmt.Errorf("invalid stream: bad magic %#x", magic))
	}
	if f := d.uint64(); f != schemaFingerprint() {
		return stateError(fmt.Errorf("the state was saved by a binary with different types"))
	}
	ds.readTypes()
	// Peek at the root type to allocate the root.
	pos := d.pos
	d.count(1)
	if d.byte()&^objInexact != objKindValue {
		return stateError(fmt.Errorf("invalid root object"))
	}
	rootType := ds.typeAt(d.uvarint())
	if uint64(rootType.size) > maxDecodeObjectBytes {
		return stateError(fmt.Errorf("root object %v (%d bytes) exceeds limit", rootType.typ, rootType.size))
	}
	d.pos = pos
	root := reflect.New(rootType.typ).UnsafePointer()
	ds.readObjects(root, rootType)
	ds.readTargets()
	ds.decodeObjects()
	if d.pos != len(d.b) {
		return stateError(fmt.Errorf("%d bytes of trailing data", len(d.b)-d.pos))
	}

	p := printer{w: w, ds: &ds, graph: int(graph), html: asHTML}
	p.index()
	for i := range ds.objs {
		name := p.objName(i)
		if asHTML {
			if err := p.printf("<a name=\"%s\"></a>", name); err != nil {
				return err
			}
		}
		if err := p.printf("%s = ", name); err != nil {
			return err
		}
		if err := p.object(&ds.objs[i]); err != nil {
			return err
		}
		if err := p.write("\n"); err != nil {
			return err
		}
	}
	return nil
}

// printer prints decoded objects.
type printer struct {
	w     io.Writer
	ds    *graphDecodeState
	graph int
	html  bool
	// byAddr are the non-zero-sized non-map objects, sorted by address.
	byAddr []int
	// zeroObjs maps zero-sized object types to their object index.
	zeroObjs map[reflect.Type]int
	// maps maps map pointers to objects.
	maps map[unsafe.Pointer]int
	// inlineMaps contains the maps that are not objects and are being
	// printed, to stop at cycles.
	inlineMaps map[unsafe.Pointer]struct{}
}

func (p *printer) index() {
	p.maps = make(map[unsafe.Pointer]int)
	p.inlineMaps = make(map[unsafe.Pointer]struct{})
	for i := range p.ds.objs {
		o := &p.ds.objs[i]
		if o.kind == objKindMap {
			if o.base != nil {
				p.maps[o.base] = i
			}
			continue
		}
		if o.size == 0 {
			ti := o.ti
			if o.exact != nil {
				ti = o.exact
			}
			if p.zeroObjs == nil {
				p.zeroObjs = make(map[reflect.Type]int)
			}
			if _, ok := p.zeroObjs[ti.typ]; !ok {
				p.zeroObjs[ti.typ] = i
			}
			continue
		}
		p.byAddr = append(p.byAddr, i)
	}
	sort.Slice(p.byAddr, func(i, j int) bool {
		return uintptr(p.ds.objs[p.byAddr[i]].base) < uintptr(p.ds.objs[p.byAddr[j]].base)
	})
}

func (p *printer) objName(i int) string {
	return fmt.Sprintf("g%dr%d", p.graph, i)
}

func (p *printer) link(i int, s string) string {
	if p.html {
		return fmt.Sprintf("<a href=\"#%s\">%s</a>", p.objName(i), html.EscapeString(s))
	}
	return s
}

func (p *printer) text(s string) string {
	if p.html {
		return html.EscapeString(s)
	}
	return s
}

// ref returns a reference to the location of type t at addr.
func (p *printer) ref(addr uintptr, t reflect.Type) string {
	if addr == uintptr(zeroSizedPtr()) {
		if obj, ok := p.zeroObjs[t]; ok {
			return p.link(obj, p.objName(obj))
		}
		return p.text(fmt.Sprintf("&%v{}", t))
	}
	i := sort.Search(len(p.byAddr), func(i int) bool {
		return uintptr(p.ds.objs[p.byAddr[i]].base) > addr
	}) - 1
	if i >= 0 {
		obj := p.byAddr[i]
		o := &p.ds.objs[obj]
		if off := addr - uintptr(o.base); off < max(o.size, 1) {
			if off == 0 {
				return p.link(obj, p.objName(obj))
			}
			return p.link(obj, fmt.Sprintf("(*%v)(%s+%d)", t, p.objName(obj), off))
		}
	}
	return p.text(fmt.Sprintf("(*%v)(%#x)", t, addr))
}

func (p *printer) indent(depth int) string {
	return strings.Repeat("\t", depth)
}

func (p *printer) write(s string) error {
	_, err := io.WriteString(p.w, s)
	return err
}

func (p *printer) printf(format string, args ...any) error {
	_, err := fmt.Fprintf(p.w, format, args...)
	return err
}

func (p *printer) object(o *decObject) error {
	ti := o.ti
	if o.exact != nil {
		ti = o.exact
	}
	switch o.kind {
	case objKindValue:
		return p.value(reflect.NewAt(ti.typ, o.base).Elem(), 0)
	case objKindArray:
		n := int(o.size / ti.size)
		return p.value(reflect.NewAt(reflect.ArrayOf(n, ti.typ), o.base).Elem(), 0)
	case objKindMap:
		if o.mapType == nil {
			return p.write("map(unreferenced)")
		}
		m := o.base
		return p.mapValue(reflect.NewAt(o.mapType.typ, unsafe.Pointer(&m)).Elem(), 0)
	}
	return nil
}

func (p *printer) value(v reflect.Value, depth int) error {
	switch v.Kind() {
	case reflect.Bool:
		return p.printf("%v", v.Bool())
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return p.printf("%d", v.Int())
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return p.printf("%du", v.Uint())
	case reflect.Float32, reflect.Float64:
		return p.printf("%v", v.Float())
	case reflect.Complex64, reflect.Complex128:
		return p.printf("%v", v.Complex())
	case reflect.String:
		return p.write(p.text(fmt.Sprintf("%q", v.String())))
	case reflect.Pointer:
		if v.IsNil() {
			return p.write("nil")
		}
		return p.write(p.ref(v.Pointer(), v.Type().Elem()))
	case reflect.Slice:
		if v.IsNil() {
			return p.write("nil")
		}
		return p.printf("%s[:%d:%d]", p.ref(v.Pointer(), v.Type().Elem()), v.Len(), v.Cap())
	case reflect.Array:
		if v.Type().Elem().Kind() == reflect.Uint8 {
			b := make([]byte, v.Len())
			for i := range b {
				b[i] = byte(v.Index(i).Uint())
			}
			return p.printf("%x", b)
		}
		if err := p.write("["); err != nil {
			return err
		}
		for i := 0; i < v.Len(); i++ {
			if i > 0 {
				if err := p.write(", "); err != nil {
					return err
				}
			}
			if err := p.value(v.Index(i), depth); err != nil {
				return err
			}
		}
		return p.write("]")
	case reflect.Map:
		if v.IsNil() {
			return p.write("nil")
		}
		m := v.UnsafePointer()
		if i, ok := p.maps[m]; ok {
			return p.write(p.link(i, p.objName(i)))
		}
		if _, ok := p.inlineMaps[m]; ok {
			return p.write(p.text(fmt.Sprintf("%v{...}", v.Type())))
		}
		p.inlineMaps[m] = struct{}{}
		defer delete(p.inlineMaps, m)
		return p.mapValue(v, depth)
	case reflect.Interface:
		if v.IsNil() {
			return p.write("interface(nil)")
		}
		if v.CanAddr() {
			v = reflect.NewAt(v.Type(), unsafe.Pointer(v.UnsafeAddr())).Elem()
		}
		e := v.Elem()
		if !e.CanAddr() && e.CanInterface() {
			cp := reflect.New(e.Type()).Elem()
			cp.Set(e)
			e = cp
		}
		if err := p.write(p.text(fmt.Sprintf("interface(%v){", e.Type()))); err != nil {
			return err
		}
		if err := p.value(e, depth); err != nil {
			return err
		}
		return p.write("}")
	case reflect.Struct:
		t := v.Type()
		if t == reflect.TypeFor[struct{}]() || t.NumField() == 0 {
			return p.write("struct{}")
		}
		ti := typeInfoOf(t)
		if ti.structKind == structBinary {
			c := reflect.New(t)
			if v.CanAddr() {
				copy(unsafe.Slice((*byte)(c.UnsafePointer()), t.Size()), unsafe.Slice((*byte)(unsafe.Pointer(v.UnsafeAddr())), t.Size()))
			} else if v.CanInterface() {
				c.Elem().Set(v)
			}
			return p.write(p.text(fmt.Sprintf("%v", c.Elem().Interface())))
		}
		if err := p.write(p.text(t.String()) + "{\n"); err != nil {
			return err
		}
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			if f.Name == "_" {
				continue
			}
			switch f.Tag.Get("state") {
			case "nosave", "manual", "ignore":
				continue
			}
			if err := p.printf("%s%s: ", p.indent(depth+1), f.Name); err != nil {
				return err
			}
			fv := v.Field(i)
			switch fv.Kind() {
			case reflect.Func, reflect.Chan, reflect.UnsafePointer:
				if err := p.write("(not printed)"); err != nil {
					return err
				}
			default:
				if err := p.value(fv, depth+1); err != nil {
					return err
				}
			}
			if err := p.write(",\n"); err != nil {
				return err
			}
		}
		return p.printf("%s}", p.indent(depth))
	default:
		return p.write(p.text(fmt.Sprintf("(%v)", v.Type())))
	}
}

func (p *printer) mapValue(v reflect.Value, depth int) error {
	if !v.CanInterface() {
		// Maps reached through unexported fields are read-only, and
		// reflect does not permit copying their entries out. A map value
		// is a single pointer, so rebuild v from it.
		m := v.UnsafePointer()
		v = reflect.NewAt(v.Type(), unsafe.Pointer(&m)).Elem()
	}
	if err := p.write(p.text(v.Type().String()) + "{\n"); err != nil {
		return err
	}
	type mapEntry struct {
		key, val string
	}
	entries := make([]mapEntry, 0, v.Len())
	sub := *p
	var kb, eb strings.Builder
	k := reflect.New(v.Type().Key()).Elem()
	e := reflect.New(v.Type().Elem()).Elem()
	for it := v.MapRange(); it.Next(); {
		k.SetIterKey(it)
		e.SetIterValue(it)
		kb.Reset()
		eb.Reset()
		sub.w = &kb
		if err := sub.value(k, depth+1); err != nil {
			return err
		}
		sub.w = &eb
		if err := sub.value(e, depth+1); err != nil {
			return err
		}
		entries = append(entries, mapEntry{key: kb.String(), val: eb.String()})
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].key != entries[j].key {
			return entries[i].key < entries[j].key
		}
		return entries[i].val < entries[j].val
	})
	indent := p.indent(depth + 1)
	for _, entry := range entries {
		if err := p.printf("%s%s: %s,\n", indent, entry.key, entry.val); err != nil {
			return err
		}
	}
	return p.printf("%s}", p.indent(depth))
}

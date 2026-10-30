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
func PrintGraph(w io.Writer, data []byte, graph uint64, asHTML bool) error {
	return safely(func() {
		printGraph(w, data, int(graph), asHTML)
	})
}

// printGraph prints a single object graph.
func printGraph(w io.Writer, data []byte, graph int, asHTML bool) {
	ds := graphDecodeState{ctx: context.Background(), in: decBuf{b: data}, noCallbacks: true}
	d := &ds.in
	if magic := d.uint32(); magic != streamMagic {
		Failf("invalid stream: bad magic %#x", magic)
	}
	if f := d.uint64(); f != schemaFingerprint() {
		Failf("the state was saved by a binary with different types")
	}
	ds.readTypes()
	// Peek at the root type to allocate the root.
	pos := d.pos
	d.count(1)
	if d.byte()&^objInexact != objKindValue {
		Failf("invalid root object")
	}
	rootType := ds.typeAt(d.uvarint())
	if uint64(rootType.size) > maxDecodeObjectBytes {
		Failf("root object %v (%d bytes) exceeds limit", rootType.typ, rootType.size)
	}
	d.pos = pos
	root := reflect.New(rootType.typ).UnsafePointer()
	ds.readObjects(root, rootType)
	ds.readTargets()
	ds.decodeObjects()
	if d.pos != len(d.b) {
		Failf("%d bytes of trailing data", len(d.b)-d.pos)
	}

	p := printer{w: w, ds: &ds, graph: graph, html: asHTML}
	p.index()
	for i := range ds.objs {
		o := &ds.objs[i]
		name := p.objName(i)
		if asHTML {
			fmt.Fprintf(w, "<a name=\"%s\"></a>", name)
		}
		fmt.Fprintf(w, "%s = ", name)
		ti := o.ti
		if o.exact != nil {
			ti = o.exact
		}
		switch o.kind {
		case objKindValue:
			p.value(reflect.NewAt(ti.typ, o.base).Elem(), 0)
		case objKindArray:
			n := int(o.size / ti.size)
			p.value(reflect.NewAt(reflect.ArrayOf(n, ti.typ), o.base).Elem(), 0)
		case objKindMap:
			if o.mapType == nil {
				fmt.Fprint(w, "map(unreferenced)")
				break
			}
			m := o.base
			p.mapValue(reflect.NewAt(o.mapType.typ, unsafe.Pointer(&m)).Elem(), 0)
		}
		fmt.Fprint(w, "\n")
	}
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

func (p *printer) value(v reflect.Value, depth int) {
	w := p.w
	switch v.Kind() {
	case reflect.Bool:
		fmt.Fprintf(w, "%v", v.Bool())
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		fmt.Fprintf(w, "%d", v.Int())
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		fmt.Fprintf(w, "%du", v.Uint())
	case reflect.Float32, reflect.Float64:
		fmt.Fprintf(w, "%v", v.Float())
	case reflect.Complex64, reflect.Complex128:
		fmt.Fprintf(w, "%v", v.Complex())
	case reflect.String:
		fmt.Fprint(w, p.text(fmt.Sprintf("%q", v.String())))
	case reflect.Pointer:
		if v.IsNil() {
			fmt.Fprint(w, "nil")
			return
		}
		fmt.Fprint(w, p.ref(v.Pointer(), v.Type().Elem()))
	case reflect.Slice:
		if v.IsNil() {
			fmt.Fprint(w, "nil")
			return
		}
		fmt.Fprintf(w, "%s[:%d:%d]", p.ref(v.Pointer(), v.Type().Elem()), v.Len(), v.Cap())
	case reflect.Array:
		if v.Type().Elem().Kind() == reflect.Uint8 {
			b := make([]byte, v.Len())
			for i := range b {
				b[i] = byte(v.Index(i).Uint())
			}
			fmt.Fprintf(w, "%x", b)
			return
		}
		fmt.Fprint(w, "[")
		for i := 0; i < v.Len(); i++ {
			if i > 0 {
				fmt.Fprint(w, ", ")
			}
			p.value(v.Index(i), depth)
		}
		fmt.Fprint(w, "]")
	case reflect.Map:
		if v.IsNil() {
			fmt.Fprint(w, "nil")
			return
		}
		m := v.UnsafePointer()
		if i, ok := p.maps[m]; ok {
			fmt.Fprint(w, p.link(i, p.objName(i)))
			return
		}
		if _, ok := p.inlineMaps[m]; ok {
			fmt.Fprint(w, p.text(fmt.Sprintf("%v{...}", v.Type())))
			return
		}
		p.inlineMaps[m] = struct{}{}
		p.mapValue(v, depth)
		delete(p.inlineMaps, m)
	case reflect.Interface:
		if v.IsNil() {
			fmt.Fprint(w, "interface(nil)")
			return
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
		fmt.Fprint(w, p.text(fmt.Sprintf("interface(%v){", e.Type())))
		p.value(e, depth)
		fmt.Fprint(w, "}")
	case reflect.Struct:
		t := v.Type()
		if t == reflect.TypeFor[struct{}]() || t.NumField() == 0 {
			fmt.Fprint(w, "struct{}")
			return
		}
		ti := typeInfoOf(t)
		if ti.structKind == structBinary {
			c := reflect.New(t)
			if v.CanAddr() {
				copy(unsafe.Slice((*byte)(c.UnsafePointer()), t.Size()), unsafe.Slice((*byte)(unsafe.Pointer(v.UnsafeAddr())), t.Size()))
			} else if v.CanInterface() {
				c.Elem().Set(v)
			}
			fmt.Fprint(w, p.text(fmt.Sprintf("%v", c.Elem().Interface())))
			return
		}
		fmt.Fprint(w, p.text(t.String())+"{\n")
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			if f.Name == "_" {
				continue
			}
			switch f.Tag.Get("state") {
			case "nosave", "manual", "ignore":
				continue
			}
			fmt.Fprintf(w, "%s%s: ", p.indent(depth+1), f.Name)
			fv := v.Field(i)
			switch fv.Kind() {
			case reflect.Func, reflect.Chan, reflect.UnsafePointer:
				fmt.Fprint(w, "(not printed)")
			default:
				p.value(fv, depth+1)
			}
			fmt.Fprint(w, ",\n")
		}
		fmt.Fprintf(w, "%s}", p.indent(depth))
	default:
		fmt.Fprint(w, p.text(fmt.Sprintf("(%v)", v.Type())))
	}
}

func (p *printer) mapValue(v reflect.Value, depth int) {
	if !v.CanInterface() {
		// Maps reached through unexported fields are read-only, and
		// reflect does not permit copying their entries out. A map value
		// is a single pointer, so rebuild v from it.
		m := v.UnsafePointer()
		v = reflect.NewAt(v.Type(), unsafe.Pointer(&m)).Elem()
	}
	w := p.w
	fmt.Fprint(w, p.text(v.Type().String())+"{\n")
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
		sub.value(k, depth+1)
		sub.w = &eb
		sub.value(e, depth+1)
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
		fmt.Fprintf(w, "%s%s: %s,\n", indent, entry.key, entry.val)
	}
	fmt.Fprintf(w, "%s}", p.indent(depth))
}

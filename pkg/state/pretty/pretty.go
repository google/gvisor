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

// Package pretty is a pretty-printer for state streams.
package pretty

import (
	"fmt"
	"html"
	"io"
	"reflect"
	"strings"

	"gvisor.dev/gvisor/pkg/state"
	"gvisor.dev/gvisor/pkg/state/wire"
)

type printer struct {
	html      bool
	typeSpecs map[string]*wire.Type
}

func (p *printer) escape(s string) string {
	if p.html {
		return html.EscapeString(s)
	}
	return s
}

func (p *printer) formatRef(x *wire.Ref, graph uint64) string {
	baseRef := fmt.Sprintf("g%dr%d", graph, x.Root)
	fullRef := baseRef
	if len(x.Dots) > 0 {
		// See wire.Ref; Type valid if Dots non-zero.
		typ, _ := p.formatType(x.Type, graph)
		var buf strings.Builder
		buf.WriteString("(*")
		buf.WriteString(typ)
		buf.WriteString(")(")
		buf.WriteString(baseRef)
		buf.WriteString(")")
		for _, component := range x.Dots {
			switch v := component.(type) {
			case *wire.FieldName:
				buf.WriteString(".")
				buf.WriteString(p.escape(string(*v)))
			case wire.Index:
				fmt.Fprintf(&buf, "[%d]", v)
			default:
				panic(fmt.Sprintf("unreachable: switch should be exhaustive, unhandled case %v", reflect.TypeOf(component)))
			}
		}
		fullRef = buf.String()
	}
	if p.html {
		return fmt.Sprintf("<a href=\"#%s\">%s</a>", baseRef, fullRef)
	}
	return fullRef
}

func (p *printer) formatType(t wire.TypeSpec, graph uint64) (string, bool) {
	switch x := t.(type) {
	case wire.TypeID:
		tag := fmt.Sprintf("g%dt%d", graph, x)
		desc := tag
		if spec, ok := p.typeSpecs[tag]; ok {
			desc += fmt.Sprintf("=%s", p.escape(spec.Name))
		} else {
			desc += "!missing-type-spec"
		}
		if p.html {
			return fmt.Sprintf("<a href=\"#%s\">%s</a>", tag, desc), true
		}
		return desc, true
	case wire.TypeSpecNil:
		return "", false // Only nil type.
	case *wire.TypeSpecPointer:
		element, _ := p.formatType(x.Type, graph)
		return fmt.Sprintf("(*%s)", element), true
	case *wire.TypeSpecArray:
		element, _ := p.formatType(x.Type, graph)
		return fmt.Sprintf("[%d](%s)", x.Count, element), true
	case *wire.TypeSpecSlice:
		element, _ := p.formatType(x.Type, graph)
		return fmt.Sprintf("([]%s)", element), true
	case *wire.TypeSpecMap:
		key, _ := p.formatType(x.Key, graph)
		value, _ := p.formatType(x.Value, graph)
		return fmt.Sprintf("(map[%s]%s)", key, value), true
	default:
		panic(fmt.Sprintf("unreachable: unknown type %T", t))
	}
}

// format formats a single object, for pretty-printing. It also returns whether
// the value is a non-zero value.
func (p *printer) format(graph uint64, depth int, encoded wire.Object) (string, bool) {
	switch x := encoded.(type) {
	case wire.Nil:
		return "nil", false
	case *wire.String:
		return p.escape(fmt.Sprintf("%q", *x)), *x != ""
	case *wire.Complex64:
		return fmt.Sprintf("%f+%fi", real(*x), imag(*x)), *x != 0.0
	case *wire.Complex128:
		return fmt.Sprintf("%f+%fi", real(*x), imag(*x)), *x != 0.0
	case *wire.Ref:
		return p.formatRef(x, graph), x.Root != 0
	case *wire.Type:
		tabs := "\n" + strings.Repeat("\t", depth)
		items := make([]string, 0, len(x.Fields)+2)
		items = append(items, fmt.Sprintf("type %s {", p.escape(x.Name)))
		for i := 0; i < len(x.Fields); i++ {
			items = append(items, fmt.Sprintf("\t%d: %s,", i, p.escape(x.Fields[i])))
		}
		items = append(items, "}")
		return strings.Join(items, tabs), true // No zero value.
	case *wire.Slice:
		return fmt.Sprintf("%s{len:%d,cap:%d}", p.formatRef(&x.Ref, graph), x.Length, x.Capacity), x.Capacity != 0
	case *wire.Array:
		if len(x.Contents) == 0 {
			return "[]", false
		}
		items := make([]string, 0, len(x.Contents)+2)
		zeros := make([]string, 0) // used to eliminate zero entries.
		items = append(items, "[")
		tabs := "\n" + strings.Repeat("\t", depth)
		for i := 0; i < len(x.Contents); i++ {
			item, ok := p.format(graph, depth+1, x.Contents[i])
			if !ok {
				zeros = append(zeros, fmt.Sprintf("\t%s,", item))
				continue
			}
			if len(zeros) > 0 {
				items = append(items, zeros...)
				zeros = nil
			}
			items = append(items, fmt.Sprintf("\t%s,", item))
		}
		if len(zeros) > 0 {
			items = append(items, fmt.Sprintf("\t... (%d zeros),", len(zeros)))
		}
		items = append(items, "]")
		return strings.Join(items, tabs), len(zeros) < len(x.Contents)
	case *wire.Struct:
		tag := fmt.Sprintf("g%dt%d", graph, x.TypeID)
		spec := p.typeSpecs[tag]
		typ, _ := p.formatType(x.TypeID, graph)
		if x.Fields() == 0 {
			return fmt.Sprintf("struct[%s]{}", typ), false
		}
		items := make([]string, 0, 2)
		items = append(items, fmt.Sprintf("struct[%s]{", typ))
		tabs := "\n" + strings.Repeat("\t", depth)
		allZero := true
		for i := 0; i < x.Fields(); i++ {
			var name string
			if spec != nil && i < len(spec.Fields) {
				name = p.escape(spec.Fields[i])
			} else {
				name = fmt.Sprintf("%d", i)
			}
			element, ok := p.format(graph, depth+1, *x.Field(i))
			allZero = allZero && !ok
			items = append(items, fmt.Sprintf("\t%s: %s,", name, element))
		}
		items = append(items, "}")
		return strings.Join(items, tabs), !allZero
	case *wire.Map:
		if len(x.Keys) == 0 {
			return "map{}", false
		}
		items := make([]string, 0, len(x.Keys)+2)
		items = append(items, "map{")
		tabs := "\n" + strings.Repeat("\t", depth)
		for i := 0; i < len(x.Keys); i++ {
			key, _ := p.format(graph, depth+1, x.Keys[i])
			value, _ := p.format(graph, depth+1, x.Values[i])
			items = append(items, fmt.Sprintf("\t%s: %s,", key, value))
		}
		items = append(items, "}")
		return strings.Join(items, tabs), true
	case *wire.Interface:
		typ, typOk := p.formatType(x.Type, graph)
		element, elementOk := p.format(graph, depth+1, x.Value)
		return fmt.Sprintf("interface[%s]{%s}", typ, element), typOk || elementOk
	default:
		// Must be a primitive; use reflection.
		return p.escape(fmt.Sprintf("%v", encoded)), true
	}
}

// rootSliceLength returns the logical length of a known slice field, or -1
// if the encoded value does not contain that field.
func rootSliceLength(spec *wire.Type, root *wire.Struct, field string) int64 {
	for i, name := range spec.Fields {
		if name != field || i >= root.Fields() {
			continue
		}
		switch v := (*root.Field(i)).(type) {
		case *wire.Slice:
			if v.Length <= v.Capacity {
				return int64(v.Length)
			}
		case wire.Nil:
			return 0
		}
		break
	}
	return -1
}

// AfterGraph may consume application-specific data following an object graph.
// frame is the zero-based frame index read by the printer.
// root is the registered name of the root struct. sliceLength is the
// length of its requested slice field, or -1 when unavailable.
// Report each raw region consumed so subsequent object references keep their IDs.
type AfterGraph func(frame int, root string, sliceLength int64, reportRaw func(int64) error) error

// printStream is the basic print implementation.
func (p *printer) printStream(w io.Writer, r io.Reader, sliceRoot, sliceField string, after AfterGraph) (err error) {
	wr := wire.Reader{Reader: r}

	// current graph ID.
	var graph uint64
	reportRaw := func(n int64) error {
		graph++
		if n == 0 {
			return nil
		}
		_, err := fmt.Fprintf(w, "(%d bytes non-object data)\n", n)
		return err
	}

	if p.html {
		fmt.Fprintf(w, "<pre>")
		defer fmt.Fprintf(w, "</pre>")
	}

	defer func() {
		if r := recover(); r != nil {
			if rErr, ok := r.(error); ok {
				err = rErr // Override return.
				return
			}
			panic(r) // Propagate.
		}
	}()

	p.typeSpecs = make(map[string]*wire.Type)

	for frame := 0; ; frame++ {
		// Find the first object to begin generation.
		hdr, err := state.ReadHeaderMode(&wr)
		if err == io.EOF {
			// Nothing else to do.
			break
		} else if err != nil {
			return err
		}
		if !hdr.Object {
			length := int64(hdr.Length) // Raw headers use at most 62 bits.
			if err := reportRaw(length); err != nil {
				return err
			}
			if _, err := io.Copy(io.Discard, io.LimitReader(r, length)); err != nil {
				return err
			}
			continue
		}
		if hdr.Graph {
			if hdr.Length > 4<<30 {
				return fmt.Errorf("invalid object graph length %d", hdr.Length)
			}
			// A truncated input shouldn't allocate its declared full length.
			data, err := io.ReadAll(io.LimitReader(r, int64(hdr.Length)))
			if uint64(len(data)) != hdr.Length {
				if err != nil {
					return err
				}
				if len(data) == 0 {
					return io.EOF
				}
				return io.ErrUnexpectedEOF
			}
			root, length, err := state.PrintGraphRoot(w, data, graph, p.html, sliceRoot, sliceField)
			if err != nil {
				return err
			}
			graph++
			if after != nil {
				if err := after(frame, root, length, reportRaw); err != nil {
					return err
				}
			}
			continue
		}

		// Read & unmarshal the object.
		//
		// Note that this loop must match the general structure of the
		// loop in decode.go. But we don't register type information,
		// etc. and just print the raw structures.
		type objectAndID struct {
			id  uint64
			obj wire.Object
		}
		var (
			tid     uint64 = 1
			objects []objectAndID
		)
		for i := uint64(0); i < hdr.Length; {
			// Unmarshal either a type object or object ID.
			encoded := wire.Load(&wr)
			switch we := encoded.(type) {
			case *wire.Type:
				str, _ := p.format(graph, 0, encoded)
				tag := fmt.Sprintf("g%dt%d", graph, tid)
				p.typeSpecs[tag] = we
				if p.html {
					// See below.
					tag = fmt.Sprintf("<a name=\"%s\">%s</a><a href=\"#%s\">&#9875;</a>", tag, tag, tag)
				}
				if _, err := fmt.Fprintf(w, "%s = %s\n", tag, str); err != nil {
					return err
				}
				tid++
			case wire.Uint:
				// Unmarshal the actual object.
				objects = append(objects, objectAndID{
					id:  uint64(we),
					obj: wire.Load(&wr),
				})
				i++
			default:
				return fmt.Errorf("wanted type or object ID, got %#v", encoded)
			}
		}

		var root string
		length := int64(-1)
		for _, objAndID := range objects {
			if st, ok := objAndID.obj.(*wire.Struct); after != nil && ok && objAndID.id == 1 && st.TypeID > 0 && uint64(st.TypeID) < tid {
				spec := p.typeSpecs[fmt.Sprintf("g%dt%d", graph, st.TypeID)]
				root = spec.Name
				if root == sliceRoot {
					length = rootSliceLength(spec, st, sliceField)
				}
			}

			// Format the node.
			str, _ := p.format(graph, 0, objAndID.obj)
			tag := fmt.Sprintf("g%dr%d", graph, objAndID.id)
			if p.html {
				// Create a little tag with an anchor next to it for linking.
				tag = fmt.Sprintf("<a name=\"%s\">%s</a><a href=\"#%s\">&#9875;</a>", tag, tag, tag)
			}
			if _, err := fmt.Fprintf(w, "%s = %s\n", tag, str); err != nil {
				return err
			}
		}
		if after != nil {
			if err := after(frame, root, length, reportRaw); err != nil {
				return err
			}
		}
	}
	return nil
}

// PrintWithAfterGraph renders the stream, calling after for each decoded root.
// The callback must consume from the same reader passed to this function.
func PrintWithAfterGraph(w io.Writer, r io.Reader, asHTML bool, sliceRoot, sliceField string, after AfterGraph) error {
	return (&printer{html: asHTML}).printStream(w, r, sliceRoot, sliceField, after)
}

// PrintText reads the stream from r and prints text to w.
func PrintText(w io.Writer, r io.Reader) error {
	return PrintWithAfterGraph(w, r, false, "", "", nil)
}

// PrintHTML reads the stream from r and prints html to w.
func PrintHTML(w io.Writer, r io.Reader) error {
	return PrintWithAfterGraph(w, r, true, "", "", nil)
}

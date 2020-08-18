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
	"io"
	"io/ioutil"
	"reflect"
	"strings"

	"gvisor.dev/gvisor/pkg/state"
	"gvisor.dev/gvisor/pkg/state/wire"
)

func formatRef(x *wire.Ref, graph uint64, html bool) string {
	baseRef := fmt.Sprintf("g%dr%d", graph, x.Root)
	fullRef := baseRef
	if len(x.Dots) > 0 {
		// See wire.Ref; Type valid if Dots non-zero.
		typ, _ := formatType(x.Type, graph, html)
		var buf strings.Builder
		buf.WriteString("(*")
		buf.WriteString(typ)
		buf.WriteString(")(")
		buf.WriteString(baseRef)
		for _, component := range x.Dots {
			switch v := component.(type) {
			case *wire.FieldName:
				buf.WriteString(".")
				buf.WriteString(string(*v))
			case wire.Index:
				buf.WriteString(fmt.Sprintf("[%d]", v))
			default:
				panic(fmt.Sprintf("unreachable: switch should be exhaustive, unhandled case %v", reflect.TypeOf(component)))
			}
		}
		buf.WriteString(")")
		fullRef = buf.String()
	}
	if html {
		return fmt.Sprintf("<a href=\"#%s\">%s</a>", baseRef, fullRef)
	}
	return fullRef
}

func formatType(t wire.TypeSpec, graph uint64, html bool) (string, bool) {
	switch x := t.(type) {
	case wire.TypeID:
		base := fmt.Sprintf("g%dt%d", graph, x)
		if html {
			return fmt.Sprintf("<a href=\"#%s\">%s</a>", base, base), true
		}
		return fmt.Sprintf("%s", base), true
	case wire.TypeSpecNil:
		return "", false // Only nil type.
	case *wire.TypeSpecPointer:
		element, _ := formatType(x.Type, graph, html)
		return fmt.Sprintf("(*%s)", element), true
	case *wire.TypeSpecArray:
		element, _ := formatType(x.Type, graph, html)
		return fmt.Sprintf("[%d](%s)", x.Count, element), true
	case *wire.TypeSpecSlice:
		element, _ := formatType(x.Type, graph, html)
		return fmt.Sprintf("([]%s)", element), true
	case *wire.TypeSpecMap:
		key, _ := formatType(x.Key, graph, html)
		value, _ := formatType(x.Value, graph, html)
		return fmt.Sprintf("(map[%s]%s)", key, value), true
	default:
		panic(fmt.Sprintf("unreachable: unknown type %T", t))
	}
}

// format formats a single object, for pretty-printing. It also returns whether
// the value is a non-zero value.
func format(graph uint64, depth int, encoded wire.Object, html bool) (string, bool) {
	switch x := encoded.(type) {
	case wire.Nil:
		return "nil", false
	case *wire.String:
		return fmt.Sprintf("%q", *x), *x != ""
	case *wire.Complex64:
		return fmt.Sprintf("%f+%fi", real(*x), imag(*x)), *x != 0.0
	case *wire.Complex128:
		return fmt.Sprintf("%f+%fi", real(*x), imag(*x)), *x != 0.0
	case *wire.Ref:
		return formatRef(x, graph, html), x.Root != 0
	case *wire.Type:
		tabs := "\n" + strings.Repeat("\t", depth)
		items := make([]string, 0, len(x.Fields)+2)
		items = append(items, fmt.Sprintf("type %s {", x.Name))
		for i := 0; i < len(x.Fields); i++ {
			items = append(items, fmt.Sprintf("\t%d: %s,", i, x.Fields[i]))
		}
		items = append(items, "}")
		return strings.Join(items, tabs), true // No zero value.
	case *wire.Slice:
		return fmt.Sprintf("%s{len:%d,cap:%d}", formatRef(&x.Ref, graph, html), x.Length, x.Capacity), x.Capacity != 0
	case *wire.Array:
		if len(x.Contents) == 0 {
			return "[]", false
		}
		items := make([]string, 0, len(x.Contents)+2)
		zeros := make([]string, 0) // used to eliminate zero entries.
		items = append(items, "[")
		tabs := "\n" + strings.Repeat("\t", depth)
		for i := 0; i < len(x.Contents); i++ {
			item, ok := format(graph, depth+1, x.Contents[i], html)
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
		typ, _ := formatType(x.TypeID, graph, html)
		if x.Fields() == 0 {
			return fmt.Sprintf("struct[%s]{}", typ), false
		}
		items := make([]string, 0, 2)
		items = append(items, fmt.Sprintf("struct[%s]{", typ))
		tabs := "\n" + strings.Repeat("\t", depth)
		allZero := true
		for i := 0; i < x.Fields(); i++ {
			element, ok := format(graph, depth+1, *x.Field(i), html)
			allZero = allZero && !ok
			items = append(items, fmt.Sprintf("\t%d: %s,", i, element))
			i++
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
			key, _ := format(graph, depth+1, x.Keys[i], html)
			value, _ := format(graph, depth+1, x.Values[i], html)
			items = append(items, fmt.Sprintf("\t%s: %s,", key, value))
		}
		items = append(items, "}")
		return strings.Join(items, tabs), true
	case *wire.Interface:
		typ, typOk := formatType(x.Type, graph, html)
		element, elementOk := format(graph, depth+1, x.Value, html)
		return fmt.Sprintf("interface[%s]{%s}", typ, element), typOk || elementOk
	default:
		// Must be a primitive; use reflection.
		return fmt.Sprintf("%v", encoded), true
	}
}

// printStream is the basic print implementation.
func printStream(w io.Writer, r wire.Reader, html bool) (err error) {
	// current graph ID.
	var graph uint64

	if html {
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

	for {
		// Find the first object to begin generation.
		length, object, err := state.ReadHeader(r)
		if err == io.EOF {
			// Nothing else to do.
			break
		} else if err != nil {
			return err
		}
		if !object {
			graph++ // Increment the graph.
			if length > 0 {
				fmt.Fprintf(w, "(%d bytes non-object data)\n", length)
				io.Copy(ioutil.Discard, &io.LimitedReader{
					R: r,
					N: int64(length),
				})
			}
			continue
		}

		// Read & unmarshal the object.
		//
		// Note that this loop must match the general structure of the
		// loop in decode.go. But we don't register type information,
		// etc. and just print the raw structures.
		var (
			oid uint64 = 1
			tid uint64 = 1
		)
		for oid <= length {
			// Unmarshal the object.
			encoded := wire.Load(r)

			// Is this a type?
			if _, ok := encoded.(*wire.Type); ok {
				str, _ := format(graph, 0, encoded, html)
				tag := fmt.Sprintf("g%dt%d", graph, tid)
				if html {
					// See below.
					tag = fmt.Sprintf("<a name=\"%s\">%s</a><a href=\"#%s\">&#9875;</a>", tag, tag, tag)
				}
				if _, err := fmt.Fprintf(w, "%s = %s\n", tag, str); err != nil {
					return err
				}
				tid++
				continue
			}

			// Format the node.
			str, _ := format(graph, 0, encoded, html)
			tag := fmt.Sprintf("g%dr%d", graph, oid)
			if html {
				// Create a little tag with an anchor next to it for linking.
				tag = fmt.Sprintf("<a name=\"%s\">%s</a><a href=\"#%s\">&#9875;</a>", tag, tag, tag)
			}
			if _, err := fmt.Fprintf(w, "%s = %s\n", tag, str); err != nil {
				return err
			}
			oid++
		}
	}

	return nil
}

// PrintText reads the stream from r and prints text to w.
func PrintText(w io.Writer, r wire.Reader) error {
	return printStream(w, r, false /* html */)
}

// PrintHTML reads the stream from r and prints html to w.
func PrintHTML(w io.Writer, r wire.Reader) error {
	return printStream(w, r, true /* html */)
}

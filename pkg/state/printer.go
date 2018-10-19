// Copyright 2018 Google LLC
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
	"fmt"
	"io"
	"io/ioutil"
	"reflect"
	"strings"

	"github.com/golang/protobuf/proto"
	pb "gvisor.googlesource.com/gvisor/pkg/state/object_go_proto"
)

// format formats a single object, for pretty-printing. It also returns whether
// the value is a non-zero value.
func format(graph uint64, depth int, object *pb.Object, html bool) (string, bool) {
	switch x := object.GetValue().(type) {
	case *pb.Object_BoolValue:
		return fmt.Sprintf("%t", x.BoolValue), x.BoolValue != false
	case *pb.Object_StringValue:
		return fmt.Sprintf("\"%s\"", string(x.StringValue)), len(x.StringValue) != 0
	case *pb.Object_Int64Value:
		return fmt.Sprintf("%d", x.Int64Value), x.Int64Value != 0
	case *pb.Object_Uint64Value:
		return fmt.Sprintf("%du", x.Uint64Value), x.Uint64Value != 0
	case *pb.Object_DoubleValue:
		return fmt.Sprintf("%f", x.DoubleValue), x.DoubleValue != 0.0
	case *pb.Object_RefValue:
		if x.RefValue == 0 {
			return "nil", false
		}
		ref := fmt.Sprintf("g%dr%d", graph, x.RefValue)
		if html {
			ref = fmt.Sprintf("<a href=#%s>%s</a>", ref, ref)
		}
		return ref, true
	case *pb.Object_SliceValue:
		if x.SliceValue.RefValue == 0 {
			return "nil", false
		}
		ref := fmt.Sprintf("g%dr%d", graph, x.SliceValue.RefValue)
		if html {
			ref = fmt.Sprintf("<a href=#%s>%s</a>", ref, ref)
		}
		return fmt.Sprintf("%s[:%d:%d]", ref, x.SliceValue.Length, x.SliceValue.Capacity), true
	case *pb.Object_ArrayValue:
		if len(x.ArrayValue.Contents) == 0 {
			return "[]", false
		}
		items := make([]string, 0, len(x.ArrayValue.Contents)+2)
		zeros := make([]string, 0) // used to eliminate zero entries.
		items = append(items, "[")
		tabs := "\n" + strings.Repeat("\t", depth)
		for i := 0; i < len(x.ArrayValue.Contents); i++ {
			item, ok := format(graph, depth+1, x.ArrayValue.Contents[i], html)
			if ok {
				if len(zeros) > 0 {
					items = append(items, zeros...)
					zeros = nil
				}
				items = append(items, fmt.Sprintf("\t%s,", item))
			} else {
				zeros = append(zeros, fmt.Sprintf("\t%s,", item))
			}
		}
		if len(zeros) > 0 {
			items = append(items, fmt.Sprintf("\t... (%d zeros),", len(zeros)))
		}
		items = append(items, "]")
		return strings.Join(items, tabs), len(zeros) < len(x.ArrayValue.Contents)
	case *pb.Object_StructValue:
		if len(x.StructValue.Fields) == 0 {
			return "struct{}", false
		}
		items := make([]string, 0, len(x.StructValue.Fields)+2)
		items = append(items, "struct{")
		tabs := "\n" + strings.Repeat("\t", depth)
		allZero := true
		for _, field := range x.StructValue.Fields {
			element, ok := format(graph, depth+1, field.Value, html)
			allZero = allZero && !ok
			items = append(items, fmt.Sprintf("\t%s: %s,", field.Name, element))
		}
		items = append(items, "}")
		return strings.Join(items, tabs), !allZero
	case *pb.Object_MapValue:
		if len(x.MapValue.Keys) == 0 {
			return "map{}", false
		}
		items := make([]string, 0, len(x.MapValue.Keys)+2)
		items = append(items, "map{")
		tabs := "\n" + strings.Repeat("\t", depth)
		for i := 0; i < len(x.MapValue.Keys); i++ {
			key, _ := format(graph, depth+1, x.MapValue.Keys[i], html)
			value, _ := format(graph, depth+1, x.MapValue.Values[i], html)
			items = append(items, fmt.Sprintf("\t%s: %s,", key, value))
		}
		items = append(items, "}")
		return strings.Join(items, tabs), true
	case *pb.Object_InterfaceValue:
		if x.InterfaceValue.Type == "" {
			return "interface(nil){}", false
		}
		element, _ := format(graph, depth+1, x.InterfaceValue.Value, html)
		return fmt.Sprintf("interface(\"%s\"){%s}", x.InterfaceValue.Type, element), true
	case *pb.Object_ByteArrayValue:
		return printArray(reflect.ValueOf(x.ByteArrayValue))
	case *pb.Object_Uint16ArrayValue:
		return printArray(reflect.ValueOf(x.Uint16ArrayValue.Values))
	case *pb.Object_Uint32ArrayValue:
		return printArray(reflect.ValueOf(x.Uint32ArrayValue.Values))
	case *pb.Object_Uint64ArrayValue:
		return printArray(reflect.ValueOf(x.Uint64ArrayValue.Values))
	case *pb.Object_UintptrArrayValue:
		return printArray(castSlice(reflect.ValueOf(x.UintptrArrayValue.Values), reflect.TypeOf(uintptr(0))))
	case *pb.Object_Int8ArrayValue:
		return printArray(castSlice(reflect.ValueOf(x.Int8ArrayValue.Values), reflect.TypeOf(int8(0))))
	case *pb.Object_Int16ArrayValue:
		return printArray(reflect.ValueOf(x.Int16ArrayValue.Values))
	case *pb.Object_Int32ArrayValue:
		return printArray(reflect.ValueOf(x.Int32ArrayValue.Values))
	case *pb.Object_Int64ArrayValue:
		return printArray(reflect.ValueOf(x.Int64ArrayValue.Values))
	case *pb.Object_BoolArrayValue:
		return printArray(reflect.ValueOf(x.BoolArrayValue.Values))
	case *pb.Object_Float64ArrayValue:
		return printArray(reflect.ValueOf(x.Float64ArrayValue.Values))
	case *pb.Object_Float32ArrayValue:
		return printArray(reflect.ValueOf(x.Float32ArrayValue.Values))
	}

	// Should not happen, but tolerate.
	return fmt.Sprintf("(unknown proto type: %T)", object.GetValue()), true
}

// PrettyPrint reads the state stream from r, and pretty prints to w.
func PrettyPrint(w io.Writer, r io.Reader, html bool) error {
	var (
		// current graph ID.
		graph uint64

		// current object ID.
		id uint64
	)

	if html {
		fmt.Fprintf(w, "<pre>")
		defer fmt.Fprintf(w, "</pre>")
	}

	for {
		// Find the first object to begin generation.
		length, object, err := ReadHeader(r)
		if err == io.EOF {
			// Nothing else to do.
			break
		} else if err != nil {
			return err
		}
		if !object {
			// Increment the graph number & reset the ID.
			graph++
			id = 0
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
		buf := make([]byte, length)
		for done := 0; done < len(buf); {
			n, err := r.Read(buf[done:])
			done += n
			if n == 0 && err != nil {
				return err
			}
		}
		obj := new(pb.Object)
		if err := proto.Unmarshal(buf, obj); err != nil {
			return err
		}

		id++ // First object must be one.
		str, _ := format(graph, 0, obj, html)
		tag := fmt.Sprintf("g%dr%d", graph, id)
		if html {
			tag = fmt.Sprintf("<a name=%s>%s</a>", tag, tag)
		}
		if _, err := fmt.Fprintf(w, "%s = %s\n", tag, str); err != nil {
			return err
		}
	}

	return nil
}

func printArray(s reflect.Value) (string, bool) {
	zero := reflect.Zero(s.Type().Elem()).Interface()
	z := "0"
	switch s.Type().Elem().Kind() {
	case reflect.Bool:
		z = "false"
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
	case reflect.Float32, reflect.Float64:
	default:
		return fmt.Sprintf("unexpected non-primitive type array: %#v", s.Interface()), true
	}

	zeros := 0
	items := make([]string, 0, s.Len())
	for i := 0; i <= s.Len(); i++ {
		if i < s.Len() && reflect.DeepEqual(s.Index(i).Interface(), zero) {
			zeros++
			continue
		}
		if zeros > 0 {
			if zeros <= 4 {
				for ; zeros > 0; zeros-- {
					items = append(items, z)
				}
			} else {
				items = append(items, fmt.Sprintf("(%d %ss)", zeros, z))
				zeros = 0
			}
		}
		if i < s.Len() {
			items = append(items, fmt.Sprintf("%v", s.Index(i).Interface()))
		}
	}
	return "[" + strings.Join(items, ",") + "]", zeros < s.Len()
}

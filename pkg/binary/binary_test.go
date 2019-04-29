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

package binary

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
	"testing"
)

func newInt32(i int32) *int32 {
	return &i
}

func TestSize(t *testing.T) {
	if got, want := Size(uint32(10)), uintptr(4); got != want {
		t.Errorf("Got = %d, want = %d", got, want)
	}
}

func TestPanic(t *testing.T) {
	tests := []struct {
		name string
		f    func([]byte, binary.ByteOrder, interface{})
		data interface{}
		want string
	}{
		{"Unmarshal int", Unmarshal, 5, "invalid type: int"},
		{"Unmarshal []int", Unmarshal, []int{5}, "invalid type: int"},
		{"Marshal int", func(_ []byte, bo binary.ByteOrder, d interface{}) { Marshal(nil, bo, d) }, 5, "invalid type: int"},
		{"Marshal int[]", func(_ []byte, bo binary.ByteOrder, d interface{}) { Marshal(nil, bo, d) }, []int{5}, "invalid type: int"},
		{"Unmarshal short buffer", Unmarshal, newInt32(5), "runtime error: index out of range"},
		{"Unmarshal long buffer", func(_ []byte, bo binary.ByteOrder, d interface{}) { Unmarshal(make([]byte, 50), bo, d) }, newInt32(5), "buffer too long by 46 bytes"},
		{"marshal int", func(_ []byte, bo binary.ByteOrder, d interface{}) { marshal(nil, bo, reflect.ValueOf(d)) }, 5, "invalid type: int"},
		{"Size int", func(_ []byte, _ binary.ByteOrder, d interface{}) { Size(d) }, 5, "invalid type: int"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			defer func() {
				r := recover()
				if got := fmt.Sprint(r); !strings.HasPrefix(got, test.want) {
					t.Errorf("Got recover() = %q, want prefix = %q", got, test.want)
				}
			}()

			test.f(nil, LittleEndian, test.data)
		})
	}
}

type inner struct {
	Field int32
}

type outer struct {
	Int8   int8
	Int16  int16
	Int32  int32
	Int64  int64
	Uint8  uint8
	Uint16 uint16
	Uint32 uint32
	Uint64 uint64

	Slice  []int32
	Array  [5]int32
	Struct inner
}

func TestMarshalUnmarshal(t *testing.T) {
	want := outer{
		1, 2, 3, 4, 5, 6, 7, 8,
		[]int32{9, 10, 11},
		[5]int32{12, 13, 14, 15, 16},
		inner{17},
	}
	buf := Marshal(nil, LittleEndian, want)
	got := outer{Slice: []int32{0, 0, 0}}
	Unmarshal(buf, LittleEndian, &got)
	if !reflect.DeepEqual(&got, &want) {
		t.Errorf("Got = %#v, want = %#v", got, want)
	}
}

type outerBenchmark struct {
	Int8   int8
	Int16  int16
	Int32  int32
	Int64  int64
	Uint8  uint8
	Uint16 uint16
	Uint32 uint32
	Uint64 uint64

	Array  [5]int32
	Struct inner
}

func BenchmarkMarshalUnmarshal(b *testing.B) {
	b.ReportAllocs()

	in := outerBenchmark{
		1, 2, 3, 4, 5, 6, 7, 8,
		[5]int32{9, 10, 11, 12, 13},
		inner{14},
	}
	buf := make([]byte, Size(&in))
	out := outerBenchmark{}

	for i := 0; i < b.N; i++ {
		buf := Marshal(buf[:0], LittleEndian, &in)
		Unmarshal(buf, LittleEndian, &out)
	}
}

func BenchmarkReadWrite(b *testing.B) {
	b.ReportAllocs()

	in := outerBenchmark{
		1, 2, 3, 4, 5, 6, 7, 8,
		[5]int32{9, 10, 11, 12, 13},
		inner{14},
	}
	buf := bytes.NewBuffer(make([]byte, binary.Size(&in)))
	out := outerBenchmark{}

	for i := 0; i < b.N; i++ {
		buf.Reset()
		if err := binary.Write(buf, LittleEndian, &in); err != nil {
			b.Error("Write:", err)
		}
		if err := binary.Read(buf, LittleEndian, &out); err != nil {
			b.Error("Read:", err)
		}
	}
}

type outerPadding struct {
	_ int8
	_ int16
	_ int32
	_ int64
	_ uint8
	_ uint16
	_ uint32
	_ uint64

	_ []int32
	_ [5]int32
	_ inner
}

func TestMarshalUnmarshalPadding(t *testing.T) {
	var want outerPadding
	buf := Marshal(nil, LittleEndian, want)
	var got outerPadding
	Unmarshal(buf, LittleEndian, &got)
	if !reflect.DeepEqual(&got, &want) {
		t.Errorf("Got = %#v, want = %#v", got, want)
	}
}

// Numbers with bits in every byte that distinguishable in big and little endian.
const (
	want16 = 64<<8 | 128
	want32 = 16<<24 | 32<<16 | want16
	want64 = 1<<56 | 2<<48 | 4<<40 | 8<<32 | want32
)

func TestReadWriteUint16(t *testing.T) {
	const want = uint16(want16)
	var buf bytes.Buffer
	if err := WriteUint16(&buf, LittleEndian, want); err != nil {
		t.Error("WriteUint16:", err)
	}
	got, err := ReadUint16(&buf, LittleEndian)
	if err != nil {
		t.Error("ReadUint16:", err)
	}
	if got != want {
		t.Errorf("got = %d, want = %d", got, want)
	}
}

func TestReadWriteUint32(t *testing.T) {
	const want = uint32(want32)
	var buf bytes.Buffer
	if err := WriteUint32(&buf, LittleEndian, want); err != nil {
		t.Error("WriteUint32:", err)
	}
	got, err := ReadUint32(&buf, LittleEndian)
	if err != nil {
		t.Error("ReadUint32:", err)
	}
	if got != want {
		t.Errorf("got = %d, want = %d", got, want)
	}
}

func TestReadWriteUint64(t *testing.T) {
	const want = uint64(want64)
	var buf bytes.Buffer
	if err := WriteUint64(&buf, LittleEndian, want); err != nil {
		t.Error("WriteUint64:", err)
	}
	got, err := ReadUint64(&buf, LittleEndian)
	if err != nil {
		t.Error("ReadUint64:", err)
	}
	if got != want {
		t.Errorf("got = %d, want = %d", got, want)
	}
}

type readWriter struct {
	err error
}

func (rw *readWriter) Write([]byte) (int, error) {
	return 0, rw.err
}

func (rw *readWriter) Read([]byte) (int, error) {
	return 0, rw.err
}

func TestReadWriteError(t *testing.T) {
	tests := []struct {
		name string
		f    func(rw io.ReadWriter) error
	}{
		{"WriteUint16", func(rw io.ReadWriter) error { return WriteUint16(rw, LittleEndian, 0) }},
		{"ReadUint16", func(rw io.ReadWriter) error { _, err := ReadUint16(rw, LittleEndian); return err }},
		{"WriteUint32", func(rw io.ReadWriter) error { return WriteUint32(rw, LittleEndian, 0) }},
		{"ReadUint32", func(rw io.ReadWriter) error { _, err := ReadUint32(rw, LittleEndian); return err }},
		{"WriteUint64", func(rw io.ReadWriter) error { return WriteUint64(rw, LittleEndian, 0) }},
		{"ReadUint64", func(rw io.ReadWriter) error { _, err := ReadUint64(rw, LittleEndian); return err }},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			want := errors.New("want")
			if got := test.f(&readWriter{want}); got != want {
				t.Errorf("got = %v, want = %v", got, want)
			}
		})
	}
}

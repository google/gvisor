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

// Package binary translates between select fixed-sized types and a binary
// representation.
package binary

import (
	"encoding/binary"
	"fmt"
	"io"
	"reflect"
)

// LittleEndian is the same as encoding/binary.LittleEndian.
//
// It is included here as a convenience.
var LittleEndian = binary.LittleEndian

// BigEndian is the same as encoding/binary.BigEndian.
//
// It is included here as a convenience.
var BigEndian = binary.BigEndian

// AppendUint16 appends the binary representation of a uint16 to buf.
func AppendUint16(buf []byte, order binary.ByteOrder, num uint16) []byte {
	buf = append(buf, make([]byte, 2)...)
	order.PutUint16(buf[len(buf)-2:], num)
	return buf
}

// AppendUint32 appends the binary representation of a uint32 to buf.
func AppendUint32(buf []byte, order binary.ByteOrder, num uint32) []byte {
	buf = append(buf, make([]byte, 4)...)
	order.PutUint32(buf[len(buf)-4:], num)
	return buf
}

// AppendUint64 appends the binary representation of a uint64 to buf.
func AppendUint64(buf []byte, order binary.ByteOrder, num uint64) []byte {
	buf = append(buf, make([]byte, 8)...)
	order.PutUint64(buf[len(buf)-8:], num)
	return buf
}

// Marshal appends a binary representation of data to buf.
//
// data must only contain fixed-length signed and unsigned ints, arrays,
// slices, structs and compositions of said types. data may be a pointer,
// but cannot contain pointers.
func Marshal(buf []byte, order binary.ByteOrder, data interface{}) []byte {
	return marshal(buf, order, reflect.Indirect(reflect.ValueOf(data)))
}

func marshal(buf []byte, order binary.ByteOrder, data reflect.Value) []byte {
	switch data.Kind() {
	case reflect.Int8:
		buf = append(buf, byte(int8(data.Int())))
	case reflect.Int16:
		buf = AppendUint16(buf, order, uint16(int16(data.Int())))
	case reflect.Int32:
		buf = AppendUint32(buf, order, uint32(int32(data.Int())))
	case reflect.Int64:
		buf = AppendUint64(buf, order, uint64(data.Int()))

	case reflect.Uint8:
		buf = append(buf, byte(data.Uint()))
	case reflect.Uint16:
		buf = AppendUint16(buf, order, uint16(data.Uint()))
	case reflect.Uint32:
		buf = AppendUint32(buf, order, uint32(data.Uint()))
	case reflect.Uint64:
		buf = AppendUint64(buf, order, data.Uint())

	case reflect.Array, reflect.Slice:
		for i, l := 0, data.Len(); i < l; i++ {
			buf = marshal(buf, order, data.Index(i))
		}

	case reflect.Struct:
		for i, l := 0, data.NumField(); i < l; i++ {
			buf = marshal(buf, order, data.Field(i))
		}

	default:
		panic("invalid type: " + data.Type().String())
	}
	return buf
}

// Unmarshal unpacks buf into data.
//
// data must be a slice or a pointer and buf must have a length of exactly
// Size(data). data must only contain fixed-length signed and unsigned ints,
// arrays, slices, structs and compositions of said types.
func Unmarshal(buf []byte, order binary.ByteOrder, data interface{}) {
	value := reflect.ValueOf(data)
	switch value.Kind() {
	case reflect.Ptr:
		value = value.Elem()
	case reflect.Slice:
	default:
		panic("invalid type: " + value.Type().String())
	}
	buf = unmarshal(buf, order, value)
	if len(buf) != 0 {
		panic(fmt.Sprintf("buffer too long by %d bytes", len(buf)))
	}
}

func unmarshal(buf []byte, order binary.ByteOrder, data reflect.Value) []byte {
	switch data.Kind() {
	case reflect.Int8:
		data.SetInt(int64(int8(buf[0])))
		buf = buf[1:]
	case reflect.Int16:
		data.SetInt(int64(int16(order.Uint16(buf))))
		buf = buf[2:]
	case reflect.Int32:
		data.SetInt(int64(int32(order.Uint32(buf))))
		buf = buf[4:]
	case reflect.Int64:
		data.SetInt(int64(order.Uint64(buf)))
		buf = buf[8:]

	case reflect.Uint8:
		data.SetUint(uint64(buf[0]))
		buf = buf[1:]
	case reflect.Uint16:
		data.SetUint(uint64(order.Uint16(buf)))
		buf = buf[2:]
	case reflect.Uint32:
		data.SetUint(uint64(order.Uint32(buf)))
		buf = buf[4:]
	case reflect.Uint64:
		data.SetUint(order.Uint64(buf))
		buf = buf[8:]

	case reflect.Array, reflect.Slice:
		for i, l := 0, data.Len(); i < l; i++ {
			buf = unmarshal(buf, order, data.Index(i))
		}

	case reflect.Struct:
		for i, l := 0, data.NumField(); i < l; i++ {
			if field := data.Field(i); field.CanSet() {
				buf = unmarshal(buf, order, field)
			} else {
				buf = buf[sizeof(field):]
			}
		}

	default:
		panic("invalid type: " + data.Type().String())
	}
	return buf
}

// Size calculates the buffer sized needed by Marshal or Unmarshal.
//
// Size only support the types supported by Marshal.
func Size(v interface{}) uintptr {
	return sizeof(reflect.Indirect(reflect.ValueOf(v)))
}

func sizeof(data reflect.Value) uintptr {
	switch data.Kind() {
	case reflect.Int8, reflect.Uint8:
		return 1
	case reflect.Int16, reflect.Uint16:
		return 2
	case reflect.Int32, reflect.Uint32:
		return 4
	case reflect.Int64, reflect.Uint64:
		return 8

	case reflect.Array, reflect.Slice:
		var size uintptr
		for i, l := 0, data.Len(); i < l; i++ {
			size += sizeof(data.Index(i))
		}
		return size

	case reflect.Struct:
		var size uintptr
		for i, l := 0, data.NumField(); i < l; i++ {
			size += sizeof(data.Field(i))
		}
		return size

	default:
		panic("invalid type: " + data.Type().String())
	}
}

// ReadUint16 reads a uint16 from r.
func ReadUint16(r io.Reader, order binary.ByteOrder) (uint16, error) {
	buf := make([]byte, 2)
	if _, err := io.ReadFull(r, buf); err != nil {
		return 0, err
	}
	return order.Uint16(buf), nil
}

// ReadUint32 reads a uint32 from r.
func ReadUint32(r io.Reader, order binary.ByteOrder) (uint32, error) {
	buf := make([]byte, 4)
	if _, err := io.ReadFull(r, buf); err != nil {
		return 0, err
	}
	return order.Uint32(buf), nil
}

// ReadUint64 reads a uint64 from r.
func ReadUint64(r io.Reader, order binary.ByteOrder) (uint64, error) {
	buf := make([]byte, 8)
	if _, err := io.ReadFull(r, buf); err != nil {
		return 0, err
	}
	return order.Uint64(buf), nil
}

// WriteUint16 writes a uint16 to w.
func WriteUint16(w io.Writer, order binary.ByteOrder, num uint16) error {
	buf := make([]byte, 2)
	order.PutUint16(buf, num)
	_, err := w.Write(buf)
	return err
}

// WriteUint32 writes a uint32 to w.
func WriteUint32(w io.Writer, order binary.ByteOrder, num uint32) error {
	buf := make([]byte, 4)
	order.PutUint32(buf, num)
	_, err := w.Write(buf)
	return err
}

// WriteUint64 writes a uint64 to w.
func WriteUint64(w io.Writer, order binary.ByteOrder, num uint64) error {
	buf := make([]byte, 8)
	order.PutUint64(buf, num)
	_, err := w.Write(buf)
	return err
}

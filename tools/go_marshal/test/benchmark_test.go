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

package benchmark_test

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"reflect"
	"testing"

	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/tools/go_marshal/analysis"
	"gvisor.dev/gvisor/tools/go_marshal/test"
)

// Marshalling using the standard encoding/binary package.
func BenchmarkEncodingBinary(b *testing.B) {
	var s1, s2 test.Stat
	analysis.RandomizeValue(&s1)

	size := binary.Size(&s1)

	b.ResetTimer()

	for n := 0; n < b.N; n++ {
		buf := bytes.NewBuffer(make([]byte, 0, size))
		if err := binary.Write(buf, hostarch.ByteOrder, &s1); err != nil {
			b.Error("Write:", err)
		}
		if err := binary.Read(buf, hostarch.ByteOrder, &s2); err != nil {
			b.Error("Read:", err)
		}
	}

	b.StopTimer()

	// Sanity check, make sure the values were preserved.
	if !reflect.DeepEqual(s1, s2) {
		panic(fmt.Sprintf("Data corruption across marshal/unmarshal cycle:\nBefore: %+v\nAfter: %+v\n", s1, s2))
	}
}

// Marshalling field-by-field with manually-written code.
func BenchmarkMarshalManual(b *testing.B) {
	var s1, s2 test.Stat
	analysis.RandomizeValue(&s1)

	b.ResetTimer()

	for n := 0; n < b.N; n++ {
		buf := make([]byte, binary.Size(s1))

		// Marshal
		off := 0
		hostarch.ByteOrder.PutUint64(buf[off:], s1.Dev)
		off += 8
		hostarch.ByteOrder.PutUint64(buf[off:], s1.Ino)
		off += 8
		hostarch.ByteOrder.PutUint64(buf[off:], s1.Nlink)
		off += 8
		hostarch.ByteOrder.PutUint32(buf[off:], s1.Mode)
		off += 4
		hostarch.ByteOrder.PutUint32(buf[off:], s1.UID)
		off += 4
		hostarch.ByteOrder.PutUint32(buf[off:], s1.GID)
		off += 4
		hostarch.ByteOrder.PutUint32(buf[off:], 0)
		off += 4
		hostarch.ByteOrder.PutUint64(buf[off:], s1.Rdev)
		off += 8
		hostarch.ByteOrder.PutUint64(buf[off:], uint64(s1.Size))
		off += 8
		hostarch.ByteOrder.PutUint64(buf[off:], uint64(s1.Blksize))
		off += 8
		hostarch.ByteOrder.PutUint64(buf[off:], uint64(s1.Blocks))
		off += 8
		hostarch.ByteOrder.PutUint64(buf[off:], uint64(s1.ATime.Sec))
		off += 8
		hostarch.ByteOrder.PutUint64(buf[off:], uint64(s1.ATime.Nsec))
		off += 8
		hostarch.ByteOrder.PutUint64(buf[off:], uint64(s1.MTime.Sec))
		off += 8
		hostarch.ByteOrder.PutUint64(buf[off:], uint64(s1.MTime.Nsec))
		off += 8
		hostarch.ByteOrder.PutUint64(buf[off:], uint64(s1.CTime.Sec))
		off += 8
		hostarch.ByteOrder.PutUint64(buf[off:], uint64(s1.CTime.Nsec))
		off += 8

		// Unmarshal
		s2.Dev = hostarch.ByteOrder.Uint64(buf[0:8])
		s2.Ino = hostarch.ByteOrder.Uint64(buf[8:16])
		s2.Nlink = hostarch.ByteOrder.Uint64(buf[16:24])
		s2.Mode = hostarch.ByteOrder.Uint32(buf[24:28])
		s2.UID = hostarch.ByteOrder.Uint32(buf[28:32])
		s2.GID = hostarch.ByteOrder.Uint32(buf[32:36])
		// Padding: buf[36:40]
		s2.Rdev = hostarch.ByteOrder.Uint64(buf[40:48])
		s2.Size = int64(hostarch.ByteOrder.Uint64(buf[48:56]))
		s2.Blksize = int64(hostarch.ByteOrder.Uint64(buf[56:64]))
		s2.Blocks = int64(hostarch.ByteOrder.Uint64(buf[64:72]))
		s2.ATime.Sec = int64(hostarch.ByteOrder.Uint64(buf[72:80]))
		s2.ATime.Nsec = int64(hostarch.ByteOrder.Uint64(buf[80:88]))
		s2.MTime.Sec = int64(hostarch.ByteOrder.Uint64(buf[88:96]))
		s2.MTime.Nsec = int64(hostarch.ByteOrder.Uint64(buf[96:104]))
		s2.CTime.Sec = int64(hostarch.ByteOrder.Uint64(buf[104:112]))
		s2.CTime.Nsec = int64(hostarch.ByteOrder.Uint64(buf[112:120]))
	}

	b.StopTimer()

	// Sanity check, make sure the values were preserved.
	if !reflect.DeepEqual(s1, s2) {
		panic(fmt.Sprintf("Data corruption across marshal/unmarshal cycle:\nBefore: %+v\nAfter: %+v\n", s1, s2))
	}
}

// Marshalling with the go_marshal safe API.
func BenchmarkGoMarshalSafe(b *testing.B) {
	var s1, s2 test.Stat
	analysis.RandomizeValue(&s1)

	b.ResetTimer()

	for n := 0; n < b.N; n++ {
		buf := make([]byte, s1.SizeBytes())
		s1.MarshalBytes(buf)
		s2.UnmarshalBytes(buf)
	}

	b.StopTimer()

	// Sanity check, make sure the values were preserved.
	if !reflect.DeepEqual(s1, s2) {
		panic(fmt.Sprintf("Data corruption across marshal/unmarshal cycle:\nBefore: %+v\nAfter: %+v\n", s1, s2))
	}
}

// Marshalling with the go_marshal unsafe API.
func BenchmarkGoMarshalUnsafe(b *testing.B) {
	var s1, s2 test.Stat
	analysis.RandomizeValue(&s1)

	b.ResetTimer()

	for n := 0; n < b.N; n++ {
		buf := make([]byte, s1.SizeBytes())
		s1.MarshalUnsafe(buf)
		s2.UnmarshalUnsafe(buf)
	}

	b.StopTimer()

	// Sanity check, make sure the values were preserved.
	if !reflect.DeepEqual(s1, s2) {
		panic(fmt.Sprintf("Data corruption across marshal/unmarshal cycle:\nBefore: %+v\nAfter: %+v\n", s1, s2))
	}
}

func BenchmarkBinarySlice(b *testing.B) {
	var s1, s2 [64]test.Stat
	analysis.RandomizeValue(&s1)

	size := binary.Size(s1)

	b.ResetTimer()

	for n := 0; n < b.N; n++ {
		buf := bytes.NewBuffer(make([]byte, 0, size))
		if err := binary.Write(buf, hostarch.ByteOrder, s1[:]); err != nil {
			b.Error("Write:", err)
		}
		if err := binary.Read(buf, hostarch.ByteOrder, s2[:]); err != nil {
			b.Error("Read:", err)
		}
	}

	b.StopTimer()

	// Sanity check, make sure the values were preserved.
	if !reflect.DeepEqual(s1, s2) {
		panic(fmt.Sprintf("Data corruption across marshal/unmarshal cycle:\nBefore: %+v\nAfter: %+v\n", s1, s2))
	}
}

func BenchmarkGoMarshalUnsafeSlice(b *testing.B) {
	var s1, s2 [64]test.Stat
	analysis.RandomizeValue(&s1)

	b.ResetTimer()

	for n := 0; n < b.N; n++ {
		buf := make([]byte, (*test.Stat)(nil).SizeBytes()*len(s1))
		test.MarshalUnsafeStatSlice(s1[:], buf)
		test.UnmarshalUnsafeStatSlice(s2[:], buf)
	}

	b.StopTimer()

	// Sanity check, make sure the values were preserved.
	if !reflect.DeepEqual(s1, s2) {
		panic(fmt.Sprintf("Data corruption across marshal/unmarshal cycle:\nBefore: %+v\nAfter: %+v\n", s1, s2))
	}
}

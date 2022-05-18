// Copyright 2018 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package jenkins

import (
	"bytes"
	"encoding/binary"
	"hash"
	"hash/fnv"
	"math"
	"testing"
)

func TestGolden32(t *testing.T) {
	var golden32 = []struct {
		out []byte
		in  string
	}{
		{[]byte{0x00, 0x00, 0x00, 0x00}, ""},
		{[]byte{0xca, 0x2e, 0x94, 0x42}, "a"},
		{[]byte{0x45, 0xe6, 0x1e, 0x58}, "ab"},
		{[]byte{0xed, 0x13, 0x1f, 0x5b}, "abc"},
	}

	hash := New32()

	for _, g := range golden32 {
		hash.Reset()
		done, error := hash.Write([]byte(g.in))
		if error != nil {
			t.Fatalf("write error: %s", error)
		}
		if done != len(g.in) {
			t.Fatalf("wrote only %d out of %d bytes", done, len(g.in))
		}
		if actual := hash.Sum(nil); !bytes.Equal(g.out, actual) {
			t.Errorf("hash(%q) = 0x%x want 0x%x", g.in, actual, g.out)
		}
	}
}

func TestIntegrity32(t *testing.T) {
	data := []byte{'1', '2', 3, 4, 5}

	h := New32()
	h.Write(data)
	sum := h.Sum(nil)

	if size := h.Size(); size != len(sum) {
		t.Fatalf("Size()=%d but len(Sum())=%d", size, len(sum))
	}

	if a := h.Sum(nil); !bytes.Equal(sum, a) {
		t.Fatalf("first Sum()=0x%x, second Sum()=0x%x", sum, a)
	}

	h.Reset()
	h.Write(data)
	if a := h.Sum(nil); !bytes.Equal(sum, a) {
		t.Fatalf("Sum()=0x%x, but after Reset() Sum()=0x%x", sum, a)
	}

	h.Reset()
	h.Write(data[:2])
	h.Write(data[2:])
	if a := h.Sum(nil); !bytes.Equal(sum, a) {
		t.Fatalf("Sum()=0x%x, but with partial writes, Sum()=0x%x", sum, a)
	}

	sum32 := h.(hash.Hash32).Sum32()
	if sum32 != binary.BigEndian.Uint32(sum) {
		t.Fatalf("Sum()=0x%x, but Sum32()=0x%x", sum, sum32)
	}
}

func BenchmarkJenkins32KB(b *testing.B) {
	h := New32()

	b.SetBytes(1024)
	data := make([]byte, 1024)
	for i := range data {
		data[i] = byte(i)
	}
	in := make([]byte, 0, h.Size())

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		h.Reset()
		h.Write(data)
		h.Sum(in)
	}
}

func BenchmarkFnv32(b *testing.B) {
	arr := make([]int64, 1000)
	for i := 0; i < b.N; i++ {
		var payload [8]byte
		binary.BigEndian.PutUint32(payload[:4], uint32(i))
		binary.BigEndian.PutUint32(payload[4:], uint32(i))

		h := fnv.New32()
		h.Write(payload[:])
		idx := int(h.Sum32()) % len(arr)
		arr[idx]++
	}
	b.StopTimer()
	c := 0
	if b.N > 1000000 {
		for i := 0; i < len(arr)-1; i++ {
			if math.Abs(float64(arr[i]-arr[i+1]))/float64(arr[i]) > float64(0.1) {
				if c == 0 {
					b.Logf("i %d val[i] %d val[i+1] %d b.N %b\n", i, arr[i], arr[i+1], b.N)
				}
				c++
			}
		}
		if c > 0 {
			b.Logf("Unbalanced buckets: %d", c)
		}
	}
}

func BenchmarkSum32(b *testing.B) {
	arr := make([]int64, 1000)
	for i := 0; i < b.N; i++ {
		var payload [8]byte
		binary.BigEndian.PutUint32(payload[:4], uint32(i))
		binary.BigEndian.PutUint32(payload[4:], uint32(i))
		h := Sum32(0)
		h.Write(payload[:])
		idx := int(h.Sum32()) % len(arr)
		arr[idx]++
	}
	b.StopTimer()
	if b.N > 1000000 {
		for i := 0; i < len(arr)-1; i++ {
			if math.Abs(float64(arr[i]-arr[i+1]))/float64(arr[i]) > float64(0.1) {
				b.Logf("val[%3d]=%8d\tval[%3d]=%8d\tb.N=%b\n", i, arr[i], i+1, arr[i+1], b.N)
				break
			}
		}
	}
}

func BenchmarkNew32(b *testing.B) {
	arr := make([]int64, 1000)
	for i := 0; i < b.N; i++ {
		var payload [8]byte
		binary.BigEndian.PutUint32(payload[:4], uint32(i))
		binary.BigEndian.PutUint32(payload[4:], uint32(i))
		h := New32()
		h.Write(payload[:])
		idx := int(h.Sum32()) % len(arr)
		arr[idx]++
	}
	b.StopTimer()
	if b.N > 1000000 {
		for i := 0; i < len(arr)-1; i++ {
			if math.Abs(float64(arr[i]-arr[i+1]))/float64(arr[i]) > float64(0.1) {
				b.Logf("val[%3d]=%8d\tval[%3d]=%8d\tb.N=%b\n", i, arr[i], i+1, arr[i+1], b.N)
				break
			}
		}
	}
}

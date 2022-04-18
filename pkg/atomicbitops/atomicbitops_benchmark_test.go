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

package atomicbitops

import (
	"testing"
)

func BenchmarkAndUint32(b *testing.B) {
	var x [128]uint32
	for i := 0; i < b.N; i++ {
		AndUint32(&x[63], uint32(i))
	}
}

func BenchmarkAndUint64(b *testing.B) {
	var x [64]Uint64
	for i := 0; i < b.N; i++ {
		AndUint64(&x[31], uint64(i))
	}
}

func BenchmarkAndUint32Parallel(b *testing.B) {
	var x [128]uint32
	b.RunParallel(func(pb *testing.PB) {
		i := uint32(0)
		for pb.Next() {
			AndUint32(&x[63], i)
			i++
		}
	})
}

func BenchmarkAndUint64Parallel(b *testing.B) {
	var x [64]Uint64
	b.RunParallel(func(pb *testing.PB) {
		i := uint64(0)
		for pb.Next() {
			AndUint64(&x[31], i)
			i++
		}
	})
}

func BenchmarkOrUint32(b *testing.B) {
	var x [128]uint32
	for i := 0; i < b.N; i++ {
		OrUint32(&x[63], uint32(i))
	}
}

func BenchmarkOrUint64(b *testing.B) {
	var x [64]Uint64
	for i := 0; i < b.N; i++ {
		OrUint64(&x[31], uint64(i))
	}
}

func BenchmarkOrUint32Parallel(b *testing.B) {
	var x [128]uint32
	b.RunParallel(func(pb *testing.PB) {
		i := uint32(0)
		for pb.Next() {
			OrUint32(&x[63], i)
			i++
		}
	})
}

func BenchmarkOrUint64Parallel(b *testing.B) {
	var x [64]Uint64
	b.RunParallel(func(pb *testing.PB) {
		i := uint64(0)
		for pb.Next() {
			OrUint64(&x[31], i)
			i++
		}
	})
}

func BenchmarkXorUint32(b *testing.B) {
	var x [128]uint32
	for i := 0; i < b.N; i++ {
		XorUint32(&x[63], uint32(i))
	}
}

func BenchmarkXorUint64(b *testing.B) {
	var x [64]Uint64
	for i := 0; i < b.N; i++ {
		XorUint64(&x[31], uint64(i))
	}
}

func BenchmarkXorUint32Parallel(b *testing.B) {
	var x [128]uint32
	b.RunParallel(func(pb *testing.PB) {
		i := uint32(0)
		for pb.Next() {
			XorUint32(&x[63], i)
			i++
		}
	})
}

func BenchmarkXorUint64Parallel(b *testing.B) {
	var x [64]Uint64
	b.RunParallel(func(pb *testing.PB) {
		i := uint64(0)
		for pb.Next() {
			XorUint64(&x[31], i)
			i++
		}
	})
}

func BenchmarkCompareAndSwapUint32(b *testing.B) {
	var x uint32
	x = 1
	ptr := &x
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			CompareAndSwapUint32(ptr, 1, 0)
			CompareAndSwapUint32(ptr, 0, 1)
		}
	})
}

func BenchmarkCompareAndSwapUint64(b *testing.B) {
	var x Uint64
	x.RacyStore(1)
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			CompareAndSwapUint64(&x, 1, 0)
			CompareAndSwapUint64(&x, 0, 1)
		}
	})
}

func BenchmarkCompareAndSwapUint32Parallel(b *testing.B) {
	var x uint32
	x = 1
	ptr := &x
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			CompareAndSwapUint32(ptr, 1, 0)
			CompareAndSwapUint32(ptr, 0, 1)
		}
	})
}

func BenchmarkCompareAndSwapUint64Parallel(b *testing.B) {
	var x Uint64
	x.RacyStore(1)
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			CompareAndSwapUint64(&x, 1, 0)
			CompareAndSwapUint64(&x, 0, 1)
		}
	})
}

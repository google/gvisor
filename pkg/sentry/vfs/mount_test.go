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

package vfs

import (
	"fmt"
	"runtime"
	"sync"
	"testing"
)

func TestMountTableLookupEmpty(t *testing.T) {
	var mt mountTable
	mt.Init()

	parent := &Mount{}
	point := &Dentry{}
	if m := mt.Lookup(parent, point); m != nil {
		t.Errorf("empty mountTable lookup: got %p, wanted nil", m)
	}
}

func TestMountTableInsertLookup(t *testing.T) {
	var mt mountTable
	mt.Init()

	mount := &Mount{}
	mount.storeKey(VirtualDentry{&Mount{}, &Dentry{}})
	mt.Insert(mount)

	if m := mt.Lookup(mount.parent(), mount.point()); m != mount {
		t.Errorf("mountTable positive lookup: got %p, wanted %p", m, mount)
	}

	otherParent := &Mount{}
	if m := mt.Lookup(otherParent, mount.point()); m != nil {
		t.Errorf("mountTable lookup with wrong mount parent: got %p, wanted nil", m)
	}
	otherPoint := &Dentry{}
	if m := mt.Lookup(mount.parent(), otherPoint); m != nil {
		t.Errorf("mountTable lookup with wrong mount point: got %p, wanted nil", m)
	}
}

// TODO: concurrent lookup/insertion/removal

// must be powers of 2
var benchNumMounts = []int{1 << 2, 1 << 5, 1 << 8}

// For all of the following:
//
// - BenchmarkMountTableFoo tests usage pattern "Foo" for mountTable.
//
// - BenchmarkMountMapFoo tests usage pattern "Foo" for a
// sync.RWMutex-protected map. (Mutator benchmarks do not use a RWMutex, since
// mountTable also requires external synchronization between mutators.)
//
// - BenchmarkMountSyncMapFoo tests usage pattern "Foo" for a sync.Map.
//
// ParallelLookup is by far the most common and performance-sensitive operation
// for this application. NegativeLookup is also important, but less so (only
// relevant with multiple mount namespaces and significant differences in
// mounts between them). Insertion and removal are benchmarked for
// completeness.
const enableComparativeBenchmarks = false

func newBenchMount() *Mount {
	mount := &Mount{}
	mount.storeKey(VirtualDentry{&Mount{}, &Dentry{}})
	return mount
}

func BenchmarkMountTableParallelLookup(b *testing.B) {
	for numG, maxG := 1, runtime.GOMAXPROCS(0); numG >= 0 && numG <= maxG; numG *= 2 {
		for _, numMounts := range benchNumMounts {
			desc := fmt.Sprintf("%dx%d", numG, numMounts)
			b.Run(desc, func(b *testing.B) {
				var mt mountTable
				mt.Init()
				keys := make([]VirtualDentry, 0, numMounts)
				for i := 0; i < numMounts; i++ {
					mount := newBenchMount()
					mt.Insert(mount)
					keys = append(keys, mount.loadKey())
				}

				var ready sync.WaitGroup
				begin := make(chan struct{})
				var end sync.WaitGroup
				for g := 0; g < numG; g++ {
					ready.Add(1)
					end.Add(1)
					go func() {
						defer end.Done()
						ready.Done()
						<-begin
						for i := 0; i < b.N; i++ {
							k := keys[i&(numMounts-1)]
							m := mt.Lookup(k.mount, k.dentry)
							if m == nil {
								b.Fatalf("lookup failed")
							}
							if parent := m.parent(); parent != k.mount {
								b.Fatalf("lookup returned mount with parent %p, wanted %p", parent, k.mount)
							}
							if point := m.point(); point != k.dentry {
								b.Fatalf("lookup returned mount with point %p, wanted %p", point, k.dentry)
							}
						}
					}()
				}

				ready.Wait()
				b.ResetTimer()
				close(begin)
				end.Wait()
			})
		}
	}
}

func BenchmarkMountMapParallelLookup(b *testing.B) {
	if !enableComparativeBenchmarks {
		b.Skipf("comparative benchmarks are disabled")
	}

	for numG, maxG := 1, runtime.GOMAXPROCS(0); numG >= 0 && numG <= maxG; numG *= 2 {
		for _, numMounts := range benchNumMounts {
			desc := fmt.Sprintf("%dx%d", numG, numMounts)
			b.Run(desc, func(b *testing.B) {
				var mu sync.RWMutex
				ms := make(map[VirtualDentry]*Mount)
				keys := make([]VirtualDentry, 0, numMounts)
				for i := 0; i < numMounts; i++ {
					mount := newBenchMount()
					key := mount.loadKey()
					ms[key] = mount
					keys = append(keys, key)
				}

				var ready sync.WaitGroup
				begin := make(chan struct{})
				var end sync.WaitGroup
				for g := 0; g < numG; g++ {
					ready.Add(1)
					end.Add(1)
					go func() {
						defer end.Done()
						ready.Done()
						<-begin
						for i := 0; i < b.N; i++ {
							k := keys[i&(numMounts-1)]
							mu.RLock()
							m := ms[k]
							mu.RUnlock()
							if m == nil {
								b.Fatalf("lookup failed")
							}
							if parent := m.parent(); parent != k.mount {
								b.Fatalf("lookup returned mount with parent %p, wanted %p", parent, k.mount)
							}
							if point := m.point(); point != k.dentry {
								b.Fatalf("lookup returned mount with point %p, wanted %p", point, k.dentry)
							}
						}
					}()
				}

				ready.Wait()
				b.ResetTimer()
				close(begin)
				end.Wait()
			})
		}
	}
}

func BenchmarkMountSyncMapParallelLookup(b *testing.B) {
	if !enableComparativeBenchmarks {
		b.Skipf("comparative benchmarks are disabled")
	}

	for numG, maxG := 1, runtime.GOMAXPROCS(0); numG >= 0 && numG <= maxG; numG *= 2 {
		for _, numMounts := range benchNumMounts {
			desc := fmt.Sprintf("%dx%d", numG, numMounts)
			b.Run(desc, func(b *testing.B) {
				var ms sync.Map
				keys := make([]VirtualDentry, 0, numMounts)
				for i := 0; i < numMounts; i++ {
					mount := newBenchMount()
					key := mount.loadKey()
					ms.Store(key, mount)
					keys = append(keys, key)
				}

				var ready sync.WaitGroup
				begin := make(chan struct{})
				var end sync.WaitGroup
				for g := 0; g < numG; g++ {
					ready.Add(1)
					end.Add(1)
					go func() {
						defer end.Done()
						ready.Done()
						<-begin
						for i := 0; i < b.N; i++ {
							k := keys[i&(numMounts-1)]
							mi, ok := ms.Load(k)
							if !ok {
								b.Fatalf("lookup failed")
							}
							m := mi.(*Mount)
							if parent := m.parent(); parent != k.mount {
								b.Fatalf("lookup returned mount with parent %p, wanted %p", parent, k.mount)
							}
							if point := m.point(); point != k.dentry {
								b.Fatalf("lookup returned mount with point %p, wanted %p", point, k.dentry)
							}
						}
					}()
				}

				ready.Wait()
				b.ResetTimer()
				close(begin)
				end.Wait()
			})
		}
	}
}

func BenchmarkMountTableNegativeLookup(b *testing.B) {
	for _, numMounts := range benchNumMounts {
		desc := fmt.Sprintf("%d", numMounts)
		b.Run(desc, func(b *testing.B) {
			var mt mountTable
			mt.Init()
			for i := 0; i < numMounts; i++ {
				mt.Insert(newBenchMount())
			}
			negkeys := make([]VirtualDentry, 0, numMounts)
			for i := 0; i < numMounts; i++ {
				negkeys = append(negkeys, VirtualDentry{
					mount:  &Mount{},
					dentry: &Dentry{},
				})
			}

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				k := negkeys[i&(numMounts-1)]
				m := mt.Lookup(k.mount, k.dentry)
				if m != nil {
					b.Fatalf("lookup got %p, wanted nil", m)
				}
			}
		})
	}
}

func BenchmarkMountMapNegativeLookup(b *testing.B) {
	if !enableComparativeBenchmarks {
		b.Skipf("comparative benchmarks are disabled")
	}

	for _, numMounts := range benchNumMounts {
		desc := fmt.Sprintf("%d", numMounts)
		b.Run(desc, func(b *testing.B) {
			var mu sync.RWMutex
			ms := make(map[VirtualDentry]*Mount)
			for i := 0; i < numMounts; i++ {
				mount := newBenchMount()
				ms[mount.loadKey()] = mount
			}
			negkeys := make([]VirtualDentry, 0, numMounts)
			for i := 0; i < numMounts; i++ {
				negkeys = append(negkeys, VirtualDentry{
					mount:  &Mount{},
					dentry: &Dentry{},
				})
			}

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				k := negkeys[i&(numMounts-1)]
				mu.RLock()
				m := ms[k]
				mu.RUnlock()
				if m != nil {
					b.Fatalf("lookup got %p, wanted nil", m)
				}
			}
		})
	}
}

func BenchmarkMountSyncMapNegativeLookup(b *testing.B) {
	if !enableComparativeBenchmarks {
		b.Skipf("comparative benchmarks are disabled")
	}

	for _, numMounts := range benchNumMounts {
		desc := fmt.Sprintf("%d", numMounts)
		b.Run(desc, func(b *testing.B) {
			var ms sync.Map
			for i := 0; i < numMounts; i++ {
				mount := newBenchMount()
				ms.Store(mount.loadKey(), mount)
			}
			negkeys := make([]VirtualDentry, 0, numMounts)
			for i := 0; i < numMounts; i++ {
				negkeys = append(negkeys, VirtualDentry{
					mount:  &Mount{},
					dentry: &Dentry{},
				})
			}

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				k := negkeys[i&(numMounts-1)]
				m, _ := ms.Load(k)
				if m != nil {
					b.Fatalf("lookup got %p, wanted nil", m)
				}
			}
		})
	}
}

func BenchmarkMountTableInsert(b *testing.B) {
	// Preallocate Mounts so that allocation time isn't included in the
	// benchmark.
	mounts := make([]*Mount, 0, b.N)
	for i := 0; i < b.N; i++ {
		mounts = append(mounts, newBenchMount())
	}

	var mt mountTable
	mt.Init()
	b.ResetTimer()
	for i := range mounts {
		mt.Insert(mounts[i])
	}
}

func BenchmarkMountMapInsert(b *testing.B) {
	if !enableComparativeBenchmarks {
		b.Skipf("comparative benchmarks are disabled")
	}

	// Preallocate Mounts so that allocation time isn't included in the
	// benchmark.
	mounts := make([]*Mount, 0, b.N)
	for i := 0; i < b.N; i++ {
		mounts = append(mounts, newBenchMount())
	}

	ms := make(map[VirtualDentry]*Mount)
	b.ResetTimer()
	for i := range mounts {
		mount := mounts[i]
		ms[mount.loadKey()] = mount
	}
}

func BenchmarkMountSyncMapInsert(b *testing.B) {
	if !enableComparativeBenchmarks {
		b.Skipf("comparative benchmarks are disabled")
	}

	// Preallocate Mounts so that allocation time isn't included in the
	// benchmark.
	mounts := make([]*Mount, 0, b.N)
	for i := 0; i < b.N; i++ {
		mounts = append(mounts, newBenchMount())
	}

	var ms sync.Map
	b.ResetTimer()
	for i := range mounts {
		mount := mounts[i]
		ms.Store(mount.loadKey(), mount)
	}
}

func BenchmarkMountTableRemove(b *testing.B) {
	mounts := make([]*Mount, 0, b.N)
	for i := 0; i < b.N; i++ {
		mounts = append(mounts, newBenchMount())
	}
	var mt mountTable
	mt.Init()
	for i := range mounts {
		mt.Insert(mounts[i])
	}

	b.ResetTimer()
	for i := range mounts {
		mt.Remove(mounts[i])
	}
}

func BenchmarkMountMapRemove(b *testing.B) {
	if !enableComparativeBenchmarks {
		b.Skipf("comparative benchmarks are disabled")
	}

	mounts := make([]*Mount, 0, b.N)
	for i := 0; i < b.N; i++ {
		mounts = append(mounts, newBenchMount())
	}
	ms := make(map[VirtualDentry]*Mount)
	for i := range mounts {
		mount := mounts[i]
		ms[mount.loadKey()] = mount
	}

	b.ResetTimer()
	for i := range mounts {
		mount := mounts[i]
		delete(ms, mount.loadKey())
	}
}

func BenchmarkMountSyncMapRemove(b *testing.B) {
	if !enableComparativeBenchmarks {
		b.Skipf("comparative benchmarks are disabled")
	}

	mounts := make([]*Mount, 0, b.N)
	for i := 0; i < b.N; i++ {
		mounts = append(mounts, newBenchMount())
	}
	var ms sync.Map
	for i := range mounts {
		mount := mounts[i]
		ms.Store(mount.loadKey(), mount)
	}

	b.ResetTimer()
	for i := range mounts {
		mount := mounts[i]
		ms.Delete(mount.loadKey())
	}
}

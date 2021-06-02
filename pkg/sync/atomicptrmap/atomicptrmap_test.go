// Copyright 2020 The gVisor Authors.
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

package atomicptrmap

import (
	"context"
	"fmt"
	"math/rand"
	"reflect"
	"runtime"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/sync"
)

func TestConsistencyWithGoMap(t *testing.T) {
	const maxKey = 16
	var vals [4]*testValue
	for i := 1; /* leave vals[0] nil */ i < len(vals); i++ {
		vals[i] = new(testValue)
	}
	var (
		m   = make(map[int64]*testValue)
		apm testAtomicPtrMap
	)
	for i := 0; i < 100000; i++ {
		// Apply a random operation to both m and apm and expect them to have
		// the same result. Bias toward CompareAndSwap, which has the most
		// cases; bias away from Range and RangeRepeatable, which are
		// relatively expensive.
		switch rand.Intn(10) {
		case 0, 1: // Load
			key := rand.Int63n(maxKey)
			want := m[key]
			got := apm.Load(key)
			t.Logf("Load(%d) = %p", key, got)
			if got != want {
				t.Fatalf("got %p, wanted %p", got, want)
			}
		case 2, 3: // Swap
			key := rand.Int63n(maxKey)
			val := vals[rand.Intn(len(vals))]
			want := m[key]
			if val != nil {
				m[key] = val
			} else {
				delete(m, key)
			}
			got := apm.Swap(key, val)
			t.Logf("Swap(%d, %p) = %p", key, val, got)
			if got != want {
				t.Fatalf("got %p, wanted %p", got, want)
			}
		case 4, 5, 6, 7: // CompareAndSwap
			key := rand.Int63n(maxKey)
			oldVal := vals[rand.Intn(len(vals))]
			newVal := vals[rand.Intn(len(vals))]
			want := m[key]
			if want == oldVal {
				if newVal != nil {
					m[key] = newVal
				} else {
					delete(m, key)
				}
			}
			got := apm.CompareAndSwap(key, oldVal, newVal)
			t.Logf("CompareAndSwap(%d, %p, %p) = %p", key, oldVal, newVal, got)
			if got != want {
				t.Fatalf("got %p, wanted %p", got, want)
			}
		case 8: // Range
			got := make(map[int64]*testValue)
			var (
				haveDup = false
				dup     int64
			)
			apm.Range(func(key int64, val *testValue) bool {
				if _, ok := got[key]; ok && !haveDup {
					haveDup = true
					dup = key
				}
				got[key] = val
				return true
			})
			t.Logf("Range() = %v", got)
			if !reflect.DeepEqual(got, m) {
				t.Fatalf("got %v, wanted %v", got, m)
			}
			if haveDup {
				t.Fatalf("got duplicate key %d", dup)
			}
		case 9: // RangeRepeatable
			got := make(map[int64]*testValue)
			apm.RangeRepeatable(func(key int64, val *testValue) bool {
				got[key] = val
				return true
			})
			t.Logf("RangeRepeatable() = %v", got)
			if !reflect.DeepEqual(got, m) {
				t.Fatalf("got %v, wanted %v", got, m)
			}
		}
	}
}

func TestConcurrentHeterogeneous(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	var (
		apm testAtomicPtrMap
		wg  sync.WaitGroup
	)
	defer func() {
		cancel()
		wg.Wait()
	}()

	possibleKeyValuePairs := make(map[int64]map[*testValue]struct{})
	addKeyValuePair := func(key int64, val *testValue) {
		values := possibleKeyValuePairs[key]
		if values == nil {
			values = make(map[*testValue]struct{})
			possibleKeyValuePairs[key] = values
		}
		values[val] = struct{}{}
	}

	const numValuesPerKey = 4

	// These goroutines use keys not used by any other goroutine.
	const numPrivateKeys = 3
	for i := 0; i < numPrivateKeys; i++ {
		key := int64(i)
		var vals [numValuesPerKey]*testValue
		for i := 1; /* leave vals[0] nil */ i < len(vals); i++ {
			val := new(testValue)
			vals[i] = val
			addKeyValuePair(key, val)
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			r := rand.New(rand.NewSource(rand.Int63()))
			var stored *testValue
			for ctx.Err() == nil {
				switch r.Intn(4) {
				case 0:
					got := apm.Load(key)
					if got != stored {
						t.Errorf("Load(%d): got %p, wanted %p", key, got, stored)
						return
					}
				case 1:
					val := vals[r.Intn(len(vals))]
					want := stored
					stored = val
					got := apm.Swap(key, val)
					if got != want {
						t.Errorf("Swap(%d, %p): got %p, wanted %p", key, val, got, want)
						return
					}
				case 2, 3:
					oldVal := vals[r.Intn(len(vals))]
					newVal := vals[r.Intn(len(vals))]
					want := stored
					if stored == oldVal {
						stored = newVal
					}
					got := apm.CompareAndSwap(key, oldVal, newVal)
					if got != want {
						t.Errorf("CompareAndSwap(%d, %p, %p): got %p, wanted %p", key, oldVal, newVal, got, want)
						return
					}
				}
			}
		}()
	}

	// These goroutines share a small set of keys.
	const numSharedKeys = 2
	var (
		sharedKeys      [numSharedKeys]int64
		sharedValues    = make(map[int64][]*testValue)
		sharedValuesSet = make(map[int64]map[*testValue]struct{})
	)
	for i := range sharedKeys {
		key := int64(numPrivateKeys + i)
		sharedKeys[i] = key
		vals := make([]*testValue, numValuesPerKey)
		valsSet := make(map[*testValue]struct{})
		for j := range vals {
			val := new(testValue)
			vals[j] = val
			valsSet[val] = struct{}{}
			addKeyValuePair(key, val)
		}
		sharedValues[key] = vals
		sharedValuesSet[key] = valsSet
	}
	randSharedValue := func(r *rand.Rand, key int64) *testValue {
		vals := sharedValues[key]
		return vals[r.Intn(len(vals))]
	}
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r := rand.New(rand.NewSource(rand.Int63()))
			for ctx.Err() == nil {
				keyIndex := r.Intn(len(sharedKeys))
				key := sharedKeys[keyIndex]
				var (
					op  string
					got *testValue
				)
				switch r.Intn(4) {
				case 0:
					op = "Load"
					got = apm.Load(key)
				case 1:
					op = "Swap"
					got = apm.Swap(key, randSharedValue(r, key))
				case 2, 3:
					op = "CompareAndSwap"
					got = apm.CompareAndSwap(key, randSharedValue(r, key), randSharedValue(r, key))
				}
				if got != nil {
					valsSet := sharedValuesSet[key]
					if _, ok := valsSet[got]; !ok {
						t.Errorf("%s: got key %d, value %p; expected value in %v", op, key, got, valsSet)
						return
					}
				}
			}
		}()
	}

	// This goroutine repeatedly searches for unused keys.
	wg.Add(1)
	go func() {
		defer wg.Done()
		r := rand.New(rand.NewSource(rand.Int63()))
		for ctx.Err() == nil {
			key := -1 - r.Int63()
			if got := apm.Load(key); got != nil {
				t.Errorf("Load(%d): got %p, wanted nil", key, got)
			}
		}
	}()

	// This goroutine repeatedly calls RangeRepeatable() and checks that each
	// key corresponds to an expected value.
	wg.Add(1)
	go func() {
		defer wg.Done()
		abort := false
		for !abort && ctx.Err() == nil {
			apm.RangeRepeatable(func(key int64, val *testValue) bool {
				values, ok := possibleKeyValuePairs[key]
				if !ok {
					t.Errorf("RangeRepeatable: got invalid key %d", key)
					abort = true
					return false
				}
				if _, ok := values[val]; !ok {
					t.Errorf("RangeRepeatable: got key %d, value %p; expected one of %v", key, val, values)
					abort = true
					return false
				}
				return true
			})
		}
	}()

	// Finally, the main goroutine spins for the length of the test calling
	// Range() and checking that each key that it observes is unique and
	// corresponds to an expected value.
	seenKeys := make(map[int64]struct{})
	const testDuration = 5 * time.Second
	end := time.Now().Add(testDuration)
	abort := false
	for time.Now().Before(end) {
		apm.Range(func(key int64, val *testValue) bool {
			values, ok := possibleKeyValuePairs[key]
			if !ok {
				t.Errorf("Range: got invalid key %d", key)
				abort = true
				return false
			}
			if _, ok := values[val]; !ok {
				t.Errorf("Range: got key %d, value %p; expected one of %v", key, val, values)
				abort = true
				return false
			}
			if _, ok := seenKeys[key]; ok {
				t.Errorf("Range: got duplicate key %d", key)
				abort = true
				return false
			}
			seenKeys[key] = struct{}{}
			return true
		})
		if abort {
			break
		}
		for k := range seenKeys {
			delete(seenKeys, k)
		}
	}
}

type benchmarkableMap interface {
	Load(key int64) *testValue
	Store(key int64, val *testValue)
	LoadOrStore(key int64, val *testValue) (*testValue, bool)
	Delete(key int64)
}

// rwMutexMap implements benchmarkableMap for a RWMutex-protected Go map.
type rwMutexMap struct {
	mu sync.RWMutex
	m  map[int64]*testValue
}

func (m *rwMutexMap) Load(key int64) *testValue {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.m[key]
}

func (m *rwMutexMap) Store(key int64, val *testValue) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.m == nil {
		m.m = make(map[int64]*testValue)
	}
	m.m[key] = val
}

func (m *rwMutexMap) LoadOrStore(key int64, val *testValue) (*testValue, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.m == nil {
		m.m = make(map[int64]*testValue)
	}
	if oldVal, ok := m.m[key]; ok {
		return oldVal, true
	}
	m.m[key] = val
	return val, false
}

func (m *rwMutexMap) Delete(key int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.m, key)
}

// syncMap implements benchmarkableMap for a sync.Map.
type syncMap struct {
	m sync.Map
}

func (m *syncMap) Load(key int64) *testValue {
	val, ok := m.m.Load(key)
	if !ok {
		return nil
	}
	return val.(*testValue)
}

func (m *syncMap) Store(key int64, val *testValue) {
	m.m.Store(key, val)
}

func (m *syncMap) LoadOrStore(key int64, val *testValue) (*testValue, bool) {
	actual, loaded := m.m.LoadOrStore(key, val)
	return actual.(*testValue), loaded
}

func (m *syncMap) Delete(key int64) {
	m.m.Delete(key)
}

// benchmarkableAtomicPtrMap implements benchmarkableMap for testAtomicPtrMap.
type benchmarkableAtomicPtrMap struct {
	m testAtomicPtrMap
}

func (m *benchmarkableAtomicPtrMap) Load(key int64) *testValue {
	return m.m.Load(key)
}

func (m *benchmarkableAtomicPtrMap) Store(key int64, val *testValue) {
	m.m.Store(key, val)
}

func (m *benchmarkableAtomicPtrMap) LoadOrStore(key int64, val *testValue) (*testValue, bool) {
	if prev := m.m.CompareAndSwap(key, nil, val); prev != nil {
		return prev, true
	}
	return val, false
}

func (m *benchmarkableAtomicPtrMap) Delete(key int64) {
	m.m.Store(key, nil)
}

// benchmarkableAtomicPtrMapSharded implements benchmarkableMap for testAtomicPtrMapSharded.
type benchmarkableAtomicPtrMapSharded struct {
	m testAtomicPtrMapSharded
}

func (m *benchmarkableAtomicPtrMapSharded) Load(key int64) *testValue {
	return m.m.Load(key)
}

func (m *benchmarkableAtomicPtrMapSharded) Store(key int64, val *testValue) {
	m.m.Store(key, val)
}

func (m *benchmarkableAtomicPtrMapSharded) LoadOrStore(key int64, val *testValue) (*testValue, bool) {
	if prev := m.m.CompareAndSwap(key, nil, val); prev != nil {
		return prev, true
	}
	return val, false
}

func (m *benchmarkableAtomicPtrMapSharded) Delete(key int64) {
	m.m.Store(key, nil)
}

var mapImpls = [...]struct {
	name string
	ctor func() benchmarkableMap
}{
	{
		name: "RWMutexMap",
		ctor: func() benchmarkableMap {
			return new(rwMutexMap)
		},
	},
	{
		name: "SyncMap",
		ctor: func() benchmarkableMap {
			return new(syncMap)
		},
	},
	{
		name: "AtomicPtrMap",
		ctor: func() benchmarkableMap {
			return new(benchmarkableAtomicPtrMap)
		},
	},
	{
		name: "AtomicPtrMapSharded",
		ctor: func() benchmarkableMap {
			return new(benchmarkableAtomicPtrMapSharded)
		},
	},
}

func benchmarkStoreDelete(b *testing.B, mapCtor func() benchmarkableMap) {
	m := mapCtor()
	val := &testValue{}
	for i := 0; i < b.N; i++ {
		m.Store(int64(i), val)
	}
	for i := 0; i < b.N; i++ {
		m.Delete(int64(i))
	}
}

func BenchmarkStoreDelete(b *testing.B) {
	for _, mapImpl := range mapImpls {
		b.Run(mapImpl.name, func(b *testing.B) {
			benchmarkStoreDelete(b, mapImpl.ctor)
		})
	}
}

func benchmarkLoadOrStoreDelete(b *testing.B, mapCtor func() benchmarkableMap) {
	m := mapCtor()
	val := &testValue{}
	for i := 0; i < b.N; i++ {
		m.LoadOrStore(int64(i), val)
	}
	for i := 0; i < b.N; i++ {
		m.Delete(int64(i))
	}
}

func BenchmarkLoadOrStoreDelete(b *testing.B) {
	for _, mapImpl := range mapImpls {
		b.Run(mapImpl.name, func(b *testing.B) {
			benchmarkLoadOrStoreDelete(b, mapImpl.ctor)
		})
	}
}

func benchmarkLookupPositive(b *testing.B, mapCtor func() benchmarkableMap) {
	m := mapCtor()
	val := &testValue{}
	for i := 0; i < b.N; i++ {
		m.Store(int64(i), val)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.Load(int64(i))
	}
}

func BenchmarkLookupPositive(b *testing.B) {
	for _, mapImpl := range mapImpls {
		b.Run(mapImpl.name, func(b *testing.B) {
			benchmarkLookupPositive(b, mapImpl.ctor)
		})
	}
}

func benchmarkLookupNegative(b *testing.B, mapCtor func() benchmarkableMap) {
	m := mapCtor()
	val := &testValue{}
	for i := 0; i < b.N; i++ {
		m.Store(int64(i), val)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.Load(int64(-1 - i))
	}
}

func BenchmarkLookupNegative(b *testing.B) {
	for _, mapImpl := range mapImpls {
		b.Run(mapImpl.name, func(b *testing.B) {
			benchmarkLookupNegative(b, mapImpl.ctor)
		})
	}
}

type benchmarkConcurrentOptions struct {
	// loadsPerMutationPair is the number of map lookups between each
	// insertion/deletion pair.
	loadsPerMutationPair int

	// If changeKeys is true, the keys used by each goroutine change between
	// iterations of the test.
	changeKeys bool
}

func benchmarkConcurrent(b *testing.B, mapCtor func() benchmarkableMap, opts benchmarkConcurrentOptions) {
	var (
		started sync.WaitGroup
		workers sync.WaitGroup
	)
	started.Add(1)

	m := mapCtor()
	val := &testValue{}
	// Insert a large number of unused elements into the map so that used
	// elements are distributed throughout memory.
	for i := 0; i < 10000; i++ {
		m.Store(int64(-1-i), val)
	}
	// n := ceil(b.N / (opts.loadsPerMutationPair + 2))
	n := (b.N + opts.loadsPerMutationPair + 1) / (opts.loadsPerMutationPair + 2)
	for i, procs := 0, runtime.GOMAXPROCS(0); i < procs; i++ {
		workerID := i
		workers.Add(1)
		go func() {
			defer workers.Done()
			started.Wait()
			for i := 0; i < n; i++ {
				var key int64
				if opts.changeKeys {
					key = int64(workerID*n + i)
				} else {
					key = int64(workerID)
				}
				m.LoadOrStore(key, val)
				for j := 0; j < opts.loadsPerMutationPair; j++ {
					m.Load(key)
				}
				m.Delete(key)
			}
		}()
	}

	b.ResetTimer()
	started.Done()
	workers.Wait()
}

func BenchmarkConcurrent(b *testing.B) {
	changeKeysChoices := [...]struct {
		name string
		val  bool
	}{
		{"FixedKeys", false},
		{"ChangingKeys", true},
	}
	writePcts := [...]struct {
		name                 string
		loadsPerMutationPair int
	}{
		{"1PercentWrites", 198},
		{"10PercentWrites", 18},
		{"50PercentWrites", 2},
	}
	for _, changeKeys := range changeKeysChoices {
		for _, writePct := range writePcts {
			for _, mapImpl := range mapImpls {
				name := fmt.Sprintf("%s_%s_%s", changeKeys.name, writePct.name, mapImpl.name)
				b.Run(name, func(b *testing.B) {
					benchmarkConcurrent(b, mapImpl.ctor, benchmarkConcurrentOptions{
						loadsPerMutationPair: writePct.loadsPerMutationPair,
						changeKeys:           changeKeys.val,
					})
				})
			}
		}
	}
}

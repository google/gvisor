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

package ctrie

import (
	"math/rand"
	"runtime"
	"sync"
	"testing"
)

var (
	k0         = testKey(0)
	k1         = testKey(1)
	k0conflict = testKey(hashModulus)
	v0         = testValue(100)
	v1         = testValue(101)
)

func TestDuplicateKeys(t *testing.T) {
	var m testMap
	m.Insert(k0, v0)
	m.Insert(k1, v1) // Overrides the first.

	if v, ok := m.Lookup(k0); !ok || v != v0 {
		t.Fatalf("got (%d, %t), expected (%d, true)", v, ok, v0)
	}
}

func TestDuplicateHashes(t *testing.T) {
	var m testMap
	m.Insert(k0, v0)
	m.Insert(k0conflict, v1) // Hash collision.

	if v, ok := m.Lookup(k0); !ok || v != v0 {
		t.Fatalf("got (%d, %t), expected (%d, true)", v, ok, v0)
	}
	if v, ok := m.Lookup(k0conflict); !ok || v != v1 {
		t.Fatalf("got (%d, %t), expected (%d, true)", v, ok, v1)
	}
}

func Test1MEntries(t *testing.T) {
	var m testMap

	// Insert all entries.
	const maximum = (1024 * 1024)
	for i := 0; i < maximum; i++ {
		m.Insert(testKey(i), testValue(i))
	}

	// Lookup all values.
	for i := 0; i < maximum; i++ {
		if v, ok := m.Lookup(testKey(i)); !ok || v != testValue(i) {
			t.Fatalf("got (%d, %t), expected (%d, true)", v, ok, testValue(i))
		}
	}

	// Remove all values.
	for i := 0; i < maximum; i++ {
		if v, ok := m.Remove(testKey(i)); !ok || v != testValue(i) {
			t.Fatalf("got (%d, %t), expected (%d, true)", v, ok, testValue(i))
		}
	}

	// Check that nothing remains.
	for i := 0; i < maximum; i++ {
		if v, ok := m.Remove(testKey(i)); ok {
			t.Fatalf("got (%d, %t), expected (0, false)", v, ok)
		}
	}
}

func TestRange(t *testing.T) {
	var m testMap

	// Insert all entries.
	const maximum = (1024 * 1024)
	for i := 0; i < maximum; i++ {
		m.Insert(testKey(i), testValue(i))
	}

	// Pull all values into a map.
	contents := make(map[testKey]testValue)
	m.Range(func(k testKey, v testValue) {
		if v, ok := contents[k]; ok {
			// We hit this key already during Range? Unexpected.
			t.Fatalf("contents already contains key %d->%d: expected not", k, v)
		}
		contents[k] = v
	})

	// Check that contents is full.
	if len(contents) != maximum {
		t.Errorf("contents does not contain %d keys, got %d", maximum, len(contents))
	}

	// Validate that all the keys we expected are there.
	for i := 0; i < maximum; i++ {
		if v, ok := contents[testKey(i)]; !ok || v != testValue(i) {
			t.Fatalf("contents is lacking key %d->%d: expected (%d, true), got (%d, %t)", i, i, i, v, ok)
		}
	}
}

// Map is a generic interface implemented by testMap and the types below.
//
// The core stress-routine drivers and benchmark routines will use this
// definition. We include a "nil" implemention along with a benchmark to
// account for the overhead associated with interface dispatch itself.
type Map interface {
	Insert(testKey, testValue)
	Remove(testKey) (testValue, bool)
	Lookup(testKey) (testValue, bool)
}

// nilMap implements Map.
type nilMap struct{}

func newNilMap() Map {
	return &nilMap{}
}

func (m *nilMap) Insert(k testKey, v testValue) {
}

func (m *nilMap) Remove(k testKey) (testValue, bool) {
	return 0, false
}

func (m *nilMap) Lookup(k testKey) (testValue, bool) {
	return 0, false
}

// builtinMap implements Map.
type builtinMap struct {
	mu sync.RWMutex
	m  map[testKey]testValue
}

func newBuiltinMap() Map {
	return &builtinMap{
		m: make(map[testKey]testValue),
	}
}

func (m *builtinMap) Insert(k testKey, v testValue) {
	m.mu.Lock()
	m.m[k] = v
	m.mu.Unlock()
}

func (m *builtinMap) Remove(k testKey) (testValue, bool) {
	m.mu.Lock()
	if v, ok := m.m[k]; ok {
		delete(m.m, k)
		m.mu.Unlock()
		return v, true
	}
	m.mu.Unlock()
	return 0, false
}

func (m *builtinMap) Lookup(k testKey) (testValue, bool) {
	m.mu.RLock()
	v, ok := m.m[k]
	m.mu.RUnlock()
	return v, ok
}

// syncMap implements Map.
type syncMap struct {
	m sync.Map
}

func newSyncMap() Map {
	return &syncMap{}
}

func (m *syncMap) Insert(k testKey, v testValue) {
	m.m.Store(k, v)
}

func (m *syncMap) Remove(k testKey) (testValue, bool) {
	m.m.Delete(k)
	return testValue(0), false // No way to tell.
}

func (m *syncMap) Lookup(k testKey) (testValue, bool) {
	v, ok := m.m.Load(k)
	if ok {
		return v.(testValue), true
	}
	return testValue(0), false
}

// verificationMap implements Map.
type verificationMap struct {
	mu         sync.RWMutex
	t          *testing.T
	builtinMap builtinMap
	testMap    testMap
}

func newVerificationMap(t *testing.T) Map {
	return &verificationMap{
		t: t,
		builtinMap: builtinMap{
			m: make(map[testKey]testValue),
		},
	}
}

func (m *verificationMap) Insert(k testKey, v testValue) {
	m.mu.Lock()
	m.builtinMap.Insert(k, v)
	m.testMap.Insert(k, v)
	m.mu.Unlock()
}

func (m *verificationMap) Remove(k testKey) (testValue, bool) {
	m.mu.Lock()
	v0, ok0 := m.builtinMap.Remove(k)
	v, ok := m.testMap.Remove(k)
	m.mu.Unlock()
	if ok != ok0 || (ok && v != v0) {
		// We failed to produce the same result as the builtinMap.
		m.t.Errorf("Remove(%d) mismatched: expected (%d, %t), got (%d, %t)", k, v0, ok0, v, ok)
	}
	return v, ok
}

func (m *verificationMap) Lookup(k testKey) (testValue, bool) {
	m.mu.RLock()
	v0, ok0 := m.builtinMap.Lookup(k)
	v, ok := m.testMap.Lookup(k)
	m.mu.RUnlock()
	if ok != ok0 || (ok && v != v0) {
		// We failed to produce the same result as the builtinMap.
		m.t.Errorf("Lookup(%d) mismatched: expected (%d, %t), got (%d, %t)", k, v0, ok0, v, ok)
	}
	return v, ok
}

// newTestMap returns the map implementation under test.
func newTestMap() Map {
	return &testMap{}
}

type testAltMapAdapter struct {
	testAltMap
}

func (t *testAltMapAdapter) Insert(k testKey, v testValue) {
	t.testAltMap.Insert(testAltKey(k), v)
}

func (t *testAltMapAdapter) Remove(k testKey) (testValue, bool) {
	return t.testAltMap.Remove(testAltKey(k))
}

func (t *testAltMapAdapter) Lookup(k testKey) (testValue, bool) {
	return t.testAltMap.Lookup(testAltKey(k))
}

// newTestAltMap returns the map implementation accepting alt keys.
func newTestAltMap() Map {
	return &testAltMapAdapter{}
}

// stressWrite inserts and removes entries.
func stressWrite(wg *sync.WaitGroup, m Map, rounds, history, maxSize int) {
	defer wg.Done()
	buf := make([]testKey, 0, history)

	// Add history keys.
	for i := 0; i < history; i++ {
		k := testKey(rand.Uint32() % uint32(maxSize))
		m.Insert(k, testValue(i))
		buf = append(buf, k)
	}

	// Churn for N rounds.
	for i := history; i < rounds; i++ {
		// N.B. The Remove here may fail if someone generates the same
		// key. That's okay and expected -- we want to exercise these
		// code paths appropriately.
		m.Remove(buf[i%len(buf)])
		k := testKey(rand.Uint32() % uint32(maxSize))
		m.Insert(k, testValue(i))
		buf[i%len(buf)] = k
	}

	// Remove all keys. See N.B. above.
	for i := 0; i < history; i++ {
		m.Remove(buf[i])
	}
}

// stressRead looks up random keys in the map.
func stressRead(wg *sync.WaitGroup, m Map, rounds, maxSize int) {
	defer wg.Done()

	// Churn for N rounds.
	for i := 0; i < rounds; i++ {
		k := testKey(rand.Uint32() % uint32(maxSize))
		m.Lookup(k) // Don't do anything with the result.
	}
}

func stressHelper(m Map, readMultiplier, mapSize, totalRounds int) {
	orig := runtime.GOMAXPROCS(0)
	defer runtime.GOMAXPROCS(orig)

	// We want at least two writer routines that can contend with each
	// other, and the appropriate mix of readers. We pick a maxSize that
	// grows the key space linearly with the number of routines.
	totalRoutines := 2 + (2 * readMultiplier)
	runtime.GOMAXPROCS(totalRoutines)
	maxSize := hashModulus * totalRoutines
	rounds := totalRounds / totalRoutines

	// Start stress routines.
	var wg sync.WaitGroup
	wg.Add(totalRoutines)
	go stressWrite(&wg, m, rounds, mapSize/2, maxSize)
	go stressWrite(&wg, m, rounds, mapSize/2, maxSize)
	for i := 0; i < 2*readMultiplier; i++ {
		go stressRead(&wg, m, rounds, maxSize)
	}

	// Wait for completion.
	wg.Wait()
}

func TestConcurrentAccessEqualMix(t *testing.T) {
	const totalRounds = 1000000 // Decent amount of time.
	const mapSize = 1000000     // Decent number of entries.
	stressHelper(newVerificationMap(t), 1, mapSize, totalRounds)
}

var benchmarkCases = []struct {
	name        string
	constructor func() Map
}{
	{
		name:        "Nil",
		constructor: newNilMap,
	},
	{
		name:        "MapCollisions",
		constructor: newTestMap,
	},
	{
		name:        "Map",
		constructor: newTestAltMap,
	},
	{
		name:        "Builtin",
		constructor: newBuiltinMap,
	},
	{
		name:        "SyncMap",
		constructor: newSyncMap,
	},
}

func benchmarkStressHelper(b *testing.B, readMultiplier, mapSize int) {
	for _, bc := range benchmarkCases {
		b.Run(bc.name, func(b *testing.B) {
			stressHelper(bc.constructor(), readMultiplier, mapSize, b.N)
		})
	}
}

func BenchmarkStress50PercentWriters100KEntries(b *testing.B) {
	benchmarkStressHelper(b, 1, 100000)
}

func BenchmarkStress10PercentWriters100KEntries(b *testing.B) {
	benchmarkStressHelper(b, 9, 100000)
}

func BenchmarkStress1PercentWriters100KEntries(b *testing.B) {
	benchmarkStressHelper(b, 99, 100000)
}

func BenchmarkStress50PercentWriters1KEntries(b *testing.B) {
	benchmarkStressHelper(b, 1, 1000)
}

func BenchmarkStress10PercentWriters1KEntries(b *testing.B) {
	benchmarkStressHelper(b, 9, 1000)
}

func BenchmarkStress1PercentWriters1KEntries(b *testing.B) {
	benchmarkStressHelper(b, 99, 1000)
}

func BenchmarkStress50PercentWriters10Entries(b *testing.B) {
	benchmarkStressHelper(b, 1, 10)
}

func BenchmarkStress10PercentWriters10Entries(b *testing.B) {
	benchmarkStressHelper(b, 9, 10)
}

func BenchmarkStress1PercentWriters10Entries(b *testing.B) {
	benchmarkStressHelper(b, 99, 10)
}

func benchmarkOpHelper(b *testing.B, fill int, op func(Map, testKey)) {
	for _, bc := range benchmarkCases {
		b.Run(bc.name, func(b *testing.B) {
			// Build our pseudo-random generator.
			source := rand.NewSource(0)

			// Construct the map and fill.
			m := bc.constructor()
			entries := make([]testKey, fill)
			for i := 0; i < fill; i++ {
				k := testKey(source.Int63())
				entries[i] = k
				m.Insert(k, testValue(0))
			}

			b.ResetTimer()

			// Run the test.
			for i := 0; i < b.N; i++ {
				op(m, entries[i%fill])
			}
		})
	}
}

func BenchmarkOpInsertRemove100KEntries(b *testing.B) {
	benchmarkOpHelper(b, 100000, func(m Map, k testKey) {
		// Use a different key; may or may not exist.
		m.Insert(k+1, testValue(0))
		m.Remove(k + 1)
	})
}

func BenchmarkOpLookup100KEntries(b *testing.B) {
	benchmarkOpHelper(b, 100000, func(m Map, k testKey) {
		m.Lookup(k)
	})
}

func BenchmarkOpInsertRemove1KEntries(b *testing.B) {
	benchmarkOpHelper(b, 1000, func(m Map, k testKey) {
		// See above.
		m.Insert(k+1, testValue(0))
		m.Remove(k + 1)
	})
}

func BenchmarkOpLookup1KEntries(b *testing.B) {
	benchmarkOpHelper(b, 1000, func(m Map, k testKey) {
		m.Lookup(k)
	})
}

func BenchmarkOpInsertRemove10Entries(b *testing.B) {
	benchmarkOpHelper(b, 10, func(m Map, k testKey) {
		// See above.
		m.Insert(k+1, testValue(0))
		m.Remove(k + 1)
	})
}

func BenchmarkOpLookup10Entries(b *testing.B) {
	benchmarkOpHelper(b, 10, func(m Map, k testKey) {
		m.Lookup(k)
	})
}

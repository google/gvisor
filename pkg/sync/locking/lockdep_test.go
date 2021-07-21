package locking_test

import (
	"testing"
)

func TestReverse(t *testing.T) {
	m := MutexTest{}
	m2 := RWMutexTest2{}
	m.Lock()
	m2.Lock()
	m2.Unlock()
	m.Unlock()

	defer func() {
		if r := recover(); r != nil {
			t.Logf("%s", r)
		}
	}()

	m2.Lock()
	m.Lock()
	m.Unlock()
	m2.Unlock()
	t.Error("The reverse lock order hasn't been detected")
}

func TestIndirect(t *testing.T) {
	m1 := MutexTest{}
	m2 := RWMutexTest2{}
	m3 := MutexTest3{}

	m1.Lock()
	m2.Lock()
	m2.Unlock()
	m1.Unlock()
	m2.Lock()
	m3.Lock()
	m3.Unlock()
	m2.Unlock()
	defer func() {
		if r := recover(); r != nil {
			t.Logf("%s", r)
		}
	}()

	m3.Lock()
	m1.Lock()
	m1.Unlock()
	m3.Unlock()
	t.Error("The reverse lock order hasn't been detected")
}

func TestSame(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Logf("%s", r)
		}
	}()

	m := MutexTest{}
	m.Lock()
	m.Lock()
	m.Unlock()
	m.Unlock()
	t.Error("The same lock has been locked twice")
}

func TestReverseNested(t *testing.T) {
	m1 := MutexTest{}
	m2 := MutexTest{}
	m1.Lock()
	m2.NestedLock()
	m1.Unlock()
	m2.NestedUnlock()

	defer func() {
		if r := recover(); r != nil {
			t.Logf("%s", r)
		}
	}()

	m2.NestedLock()
	m1.Lock()
	m1.NestedUnlock()
	m2.Unlock()

	t.Error("The reverse lock order hasn't been detected")
}

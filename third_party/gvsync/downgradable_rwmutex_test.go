// Copyright 2009 The Go Authors. All rights reserved.
// Copyright 2019 The gVisor Authors.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// GOMAXPROCS=10 go test

// Copy/pasted from the standard library's sync/rwmutex_test.go, except for the
// addition of downgradingWriter and the renaming of num_iterations to
// numIterations to shut up Golint.

package gvsync

import (
	"fmt"
	"runtime"
	"sync/atomic"
	"testing"
)

func parallelReader(m *DowngradableRWMutex, clocked, cunlock, cdone chan bool) {
	m.RLock()
	clocked <- true
	<-cunlock
	m.RUnlock()
	cdone <- true
}

func doTestParallelReaders(numReaders, gomaxprocs int) {
	runtime.GOMAXPROCS(gomaxprocs)
	var m DowngradableRWMutex
	clocked := make(chan bool)
	cunlock := make(chan bool)
	cdone := make(chan bool)
	for i := 0; i < numReaders; i++ {
		go parallelReader(&m, clocked, cunlock, cdone)
	}
	// Wait for all parallel RLock()s to succeed.
	for i := 0; i < numReaders; i++ {
		<-clocked
	}
	for i := 0; i < numReaders; i++ {
		cunlock <- true
	}
	// Wait for the goroutines to finish.
	for i := 0; i < numReaders; i++ {
		<-cdone
	}
}

func TestParallelReaders(t *testing.T) {
	defer runtime.GOMAXPROCS(runtime.GOMAXPROCS(-1))
	doTestParallelReaders(1, 4)
	doTestParallelReaders(3, 4)
	doTestParallelReaders(4, 2)
}

func reader(rwm *DowngradableRWMutex, numIterations int, activity *int32, cdone chan bool) {
	for i := 0; i < numIterations; i++ {
		rwm.RLock()
		n := atomic.AddInt32(activity, 1)
		if n < 1 || n >= 10000 {
			panic(fmt.Sprintf("wlock(%d)\n", n))
		}
		for i := 0; i < 100; i++ {
		}
		atomic.AddInt32(activity, -1)
		rwm.RUnlock()
	}
	cdone <- true
}

func writer(rwm *DowngradableRWMutex, numIterations int, activity *int32, cdone chan bool) {
	for i := 0; i < numIterations; i++ {
		rwm.Lock()
		n := atomic.AddInt32(activity, 10000)
		if n != 10000 {
			panic(fmt.Sprintf("wlock(%d)\n", n))
		}
		for i := 0; i < 100; i++ {
		}
		atomic.AddInt32(activity, -10000)
		rwm.Unlock()
	}
	cdone <- true
}

func downgradingWriter(rwm *DowngradableRWMutex, numIterations int, activity *int32, cdone chan bool) {
	for i := 0; i < numIterations; i++ {
		rwm.Lock()
		n := atomic.AddInt32(activity, 10000)
		if n != 10000 {
			panic(fmt.Sprintf("wlock(%d)\n", n))
		}
		for i := 0; i < 100; i++ {
		}
		atomic.AddInt32(activity, -10000)
		rwm.DowngradeLock()
		n = atomic.AddInt32(activity, 1)
		if n < 1 || n >= 10000 {
			panic(fmt.Sprintf("wlock(%d)\n", n))
		}
		for i := 0; i < 100; i++ {
		}
		n = atomic.AddInt32(activity, -1)
		rwm.RUnlock()
	}
	cdone <- true
}

func HammerDowngradableRWMutex(gomaxprocs, numReaders, numIterations int) {
	runtime.GOMAXPROCS(gomaxprocs)
	// Number of active readers + 10000 * number of active writers.
	var activity int32
	var rwm DowngradableRWMutex
	cdone := make(chan bool)
	go writer(&rwm, numIterations, &activity, cdone)
	go downgradingWriter(&rwm, numIterations, &activity, cdone)
	var i int
	for i = 0; i < numReaders/2; i++ {
		go reader(&rwm, numIterations, &activity, cdone)
	}
	go writer(&rwm, numIterations, &activity, cdone)
	go downgradingWriter(&rwm, numIterations, &activity, cdone)
	for ; i < numReaders; i++ {
		go reader(&rwm, numIterations, &activity, cdone)
	}
	// Wait for the 4 writers and all readers to finish.
	for i := 0; i < 4+numReaders; i++ {
		<-cdone
	}
}

func TestDowngradableRWMutex(t *testing.T) {
	defer runtime.GOMAXPROCS(runtime.GOMAXPROCS(-1))
	n := 1000
	if testing.Short() {
		n = 5
	}
	HammerDowngradableRWMutex(1, 1, n)
	HammerDowngradableRWMutex(1, 3, n)
	HammerDowngradableRWMutex(1, 10, n)
	HammerDowngradableRWMutex(4, 1, n)
	HammerDowngradableRWMutex(4, 3, n)
	HammerDowngradableRWMutex(4, 10, n)
	HammerDowngradableRWMutex(10, 1, n)
	HammerDowngradableRWMutex(10, 3, n)
	HammerDowngradableRWMutex(10, 10, n)
	HammerDowngradableRWMutex(10, 5, n)
}

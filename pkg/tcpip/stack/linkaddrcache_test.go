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

package stack

import (
	"fmt"
	"math"
	"sync/atomic"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/sleep"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/tcpip"
)

type testaddr struct {
	addr     tcpip.FullAddress
	linkAddr tcpip.LinkAddress
}

var testAddrs = func() []testaddr {
	var addrs []testaddr
	for i := 0; i < 4*linkAddrCacheSize; i++ {
		addr := fmt.Sprintf("Addr%06d", i)
		addrs = append(addrs, testaddr{
			addr:     tcpip.FullAddress{NIC: 1, Addr: tcpip.Address(addr)},
			linkAddr: tcpip.LinkAddress("Link" + addr),
		})
	}
	return addrs
}()

type testLinkAddressResolver struct {
	cache                *linkAddrCache
	delay                time.Duration
	onLinkAddressRequest func()
}

func (r *testLinkAddressResolver) LinkAddressRequest(targetAddr, _ tcpip.Address, _ tcpip.LinkAddress, _ NetworkInterface) *tcpip.Error {
	time.AfterFunc(r.delay, func() { r.fakeRequest(targetAddr) })
	if f := r.onLinkAddressRequest; f != nil {
		f()
	}
	return nil
}

func (r *testLinkAddressResolver) fakeRequest(addr tcpip.Address) {
	for _, ta := range testAddrs {
		if ta.addr.Addr == addr {
			r.cache.add(ta.addr, ta.linkAddr)
			break
		}
	}
}

func (*testLinkAddressResolver) ResolveStaticAddress(addr tcpip.Address) (tcpip.LinkAddress, bool) {
	if addr == "broadcast" {
		return "mac_broadcast", true
	}
	return "", false
}

func (*testLinkAddressResolver) LinkAddressProtocol() tcpip.NetworkProtocolNumber {
	return 1
}

func getBlocking(c *linkAddrCache, addr tcpip.FullAddress, linkRes LinkAddressResolver) (tcpip.LinkAddress, *tcpip.Error) {
	w := sleep.Waker{}
	s := sleep.Sleeper{}
	s.AddWaker(&w, 123)
	defer s.Done()

	for {
		if got, _, err := c.get(addr, linkRes, "", nil, &w); err != tcpip.ErrWouldBlock {
			return got, err
		}
		s.Fetch(true)
	}
}

func TestCacheOverflow(t *testing.T) {
	c := newLinkAddrCache(1<<63-1, 1*time.Second, 3)
	for i := len(testAddrs) - 1; i >= 0; i-- {
		e := testAddrs[i]
		c.add(e.addr, e.linkAddr)
		got, _, err := c.get(e.addr, nil, "", nil, nil)
		if err != nil {
			t.Errorf("insert %d, c.get(%q)=%q, got error: %v", i, string(e.addr.Addr), got, err)
		}
		if got != e.linkAddr {
			t.Errorf("insert %d, c.get(%q)=%q, want %q", i, string(e.addr.Addr), got, e.linkAddr)
		}
	}
	// Expect to find at least half of the most recent entries.
	for i := 0; i < linkAddrCacheSize/2; i++ {
		e := testAddrs[i]
		got, _, err := c.get(e.addr, nil, "", nil, nil)
		if err != nil {
			t.Errorf("check %d, c.get(%q)=%q, got error: %v", i, string(e.addr.Addr), got, err)
		}
		if got != e.linkAddr {
			t.Errorf("check %d, c.get(%q)=%q, want %q", i, string(e.addr.Addr), got, e.linkAddr)
		}
	}
	// The earliest entries should no longer be in the cache.
	for i := len(testAddrs) - 1; i >= len(testAddrs)-linkAddrCacheSize; i-- {
		e := testAddrs[i]
		if _, _, err := c.get(e.addr, nil, "", nil, nil); err != tcpip.ErrNoLinkAddress {
			t.Errorf("check %d, c.get(%q), got error: %v, want: error ErrNoLinkAddress", i, string(e.addr.Addr), err)
		}
	}
}

func TestCacheConcurrent(t *testing.T) {
	c := newLinkAddrCache(1<<63-1, 1*time.Second, 3)

	var wg sync.WaitGroup
	for r := 0; r < 16; r++ {
		wg.Add(1)
		go func() {
			for _, e := range testAddrs {
				c.add(e.addr, e.linkAddr)
				c.get(e.addr, nil, "", nil, nil) // make work for gotsan
			}
			wg.Done()
		}()
	}
	wg.Wait()

	// All goroutines add in the same order and add more values than
	// can fit in the cache, so our eviction strategy requires that
	// the last entry be present and the first be missing.
	e := testAddrs[len(testAddrs)-1]
	got, _, err := c.get(e.addr, nil, "", nil, nil)
	if err != nil {
		t.Errorf("c.get(%q)=%q, got error: %v", string(e.addr.Addr), got, err)
	}
	if got != e.linkAddr {
		t.Errorf("c.get(%q)=%q, want %q", string(e.addr.Addr), got, e.linkAddr)
	}

	e = testAddrs[0]
	if _, _, err := c.get(e.addr, nil, "", nil, nil); err != tcpip.ErrNoLinkAddress {
		t.Errorf("c.get(%q), got error: %v, want: error ErrNoLinkAddress", string(e.addr.Addr), err)
	}
}

func TestCacheAgeLimit(t *testing.T) {
	c := newLinkAddrCache(1*time.Millisecond, 1*time.Second, 3)
	e := testAddrs[0]
	c.add(e.addr, e.linkAddr)
	time.Sleep(50 * time.Millisecond)
	if _, _, err := c.get(e.addr, nil, "", nil, nil); err != tcpip.ErrNoLinkAddress {
		t.Errorf("c.get(%q), got error: %v, want: error ErrNoLinkAddress", string(e.addr.Addr), err)
	}
}

func TestCacheReplace(t *testing.T) {
	c := newLinkAddrCache(1<<63-1, 1*time.Second, 3)
	e := testAddrs[0]
	l2 := e.linkAddr + "2"
	c.add(e.addr, e.linkAddr)
	got, _, err := c.get(e.addr, nil, "", nil, nil)
	if err != nil {
		t.Errorf("c.get(%q)=%q, got error: %v", string(e.addr.Addr), got, err)
	}
	if got != e.linkAddr {
		t.Errorf("c.get(%q)=%q, want %q", string(e.addr.Addr), got, e.linkAddr)
	}

	c.add(e.addr, l2)
	got, _, err = c.get(e.addr, nil, "", nil, nil)
	if err != nil {
		t.Errorf("c.get(%q)=%q, got error: %v", string(e.addr.Addr), got, err)
	}
	if got != l2 {
		t.Errorf("c.get(%q)=%q, want %q", string(e.addr.Addr), got, l2)
	}
}

func TestCacheResolution(t *testing.T) {
	// There is a race condition causing this test to fail when the executor
	// takes longer than the resolution timeout to call linkAddrCache.get. This
	// is especially common when this test is run with gotsan.
	//
	// Using a large resolution timeout decreases the probability of experiencing
	// this race condition and does not affect how long this test takes to run.
	c := newLinkAddrCache(1<<63-1, math.MaxInt64, 1)
	linkRes := &testLinkAddressResolver{cache: c}
	for i, ta := range testAddrs {
		got, err := getBlocking(c, ta.addr, linkRes)
		if err != nil {
			t.Errorf("check %d, c.get(%q)=%q, got error: %v", i, string(ta.addr.Addr), got, err)
		}
		if got != ta.linkAddr {
			t.Errorf("check %d, c.get(%q)=%q, want %q", i, string(ta.addr.Addr), got, ta.linkAddr)
		}
	}

	// Check that after resolved, address stays in the cache and never returns WouldBlock.
	for i := 0; i < 10; i++ {
		e := testAddrs[len(testAddrs)-1]
		got, _, err := c.get(e.addr, linkRes, "", nil, nil)
		if err != nil {
			t.Errorf("c.get(%q)=%q, got error: %v", string(e.addr.Addr), got, err)
		}
		if got != e.linkAddr {
			t.Errorf("c.get(%q)=%q, want %q", string(e.addr.Addr), got, e.linkAddr)
		}
	}
}

func TestCacheResolutionFailed(t *testing.T) {
	c := newLinkAddrCache(1<<63-1, 10*time.Millisecond, 5)
	linkRes := &testLinkAddressResolver{cache: c}

	var requestCount uint32
	linkRes.onLinkAddressRequest = func() {
		atomic.AddUint32(&requestCount, 1)
	}

	// First, sanity check that resolution is working...
	e := testAddrs[0]
	got, err := getBlocking(c, e.addr, linkRes)
	if err != nil {
		t.Errorf("c.get(%q)=%q, got error: %v", string(e.addr.Addr), got, err)
	}
	if got != e.linkAddr {
		t.Errorf("c.get(%q)=%q, want %q", string(e.addr.Addr), got, e.linkAddr)
	}

	before := atomic.LoadUint32(&requestCount)

	e.addr.Addr += "2"
	if _, err := getBlocking(c, e.addr, linkRes); err != tcpip.ErrNoLinkAddress {
		t.Errorf("c.get(%q), got error: %v, want: error ErrNoLinkAddress", string(e.addr.Addr), err)
	}

	if got, want := int(atomic.LoadUint32(&requestCount)-before), c.resolutionAttempts; got != want {
		t.Errorf("got link address request count = %d, want = %d", got, want)
	}
}

func TestCacheResolutionTimeout(t *testing.T) {
	resolverDelay := 500 * time.Millisecond
	expiration := resolverDelay / 10
	c := newLinkAddrCache(expiration, 1*time.Millisecond, 3)
	linkRes := &testLinkAddressResolver{cache: c, delay: resolverDelay}

	e := testAddrs[0]
	if _, err := getBlocking(c, e.addr, linkRes); err != tcpip.ErrNoLinkAddress {
		t.Errorf("c.get(%q), got error: %v, want: error ErrNoLinkAddress", string(e.addr.Addr), err)
	}
}

// TestStaticResolution checks that static link addresses are resolved immediately and don't
// send resolution requests.
func TestStaticResolution(t *testing.T) {
	c := newLinkAddrCache(1<<63-1, time.Millisecond, 1)
	linkRes := &testLinkAddressResolver{cache: c, delay: time.Minute}

	addr := tcpip.Address("broadcast")
	want := tcpip.LinkAddress("mac_broadcast")
	got, _, err := c.get(tcpip.FullAddress{Addr: addr}, linkRes, "", nil, nil)
	if err != nil {
		t.Errorf("c.get(%q)=%q, got error: %v", string(addr), string(got), err)
	}
	if got != want {
		t.Errorf("c.get(%q)=%q, want %q", string(addr), string(got), string(want))
	}
}

// TestCacheWaker verifies that RemoveWaker removes a waker previously added
// through get().
func TestCacheWaker(t *testing.T) {
	c := newLinkAddrCache(1<<63-1, 1*time.Second, 3)

	// First, sanity check that wakers are working.
	{
		linkRes := &testLinkAddressResolver{cache: c}
		s := sleep.Sleeper{}
		defer s.Done()

		const wakerID = 1
		w := sleep.Waker{}
		s.AddWaker(&w, wakerID)

		e := testAddrs[0]

		if _, _, err := c.get(e.addr, linkRes, "", nil, &w); err != tcpip.ErrWouldBlock {
			t.Fatalf("got c.get(%q, _, _, _, _) = %s, want = %s", e.addr.Addr, err, tcpip.ErrWouldBlock)
		}
		id, ok := s.Fetch(true /* block */)
		if !ok {
			t.Fatal("got s.Fetch(true) = (_, false), want = (_, true)")
		}
		if id != wakerID {
			t.Fatalf("got s.Fetch(true) = (%d, %t), want = (%d, true)", id, ok, wakerID)
		}

		if got, _, err := c.get(e.addr, linkRes, "", nil, nil); err != nil {
			t.Fatalf("c.get(%q, _, _, _, _): %s", e.addr.Addr, err)
		} else if got != e.linkAddr {
			t.Fatalf("got c.get(%q) = %q, want = %q", e.addr.Addr, got, e.linkAddr)
		}
	}

	// Check that RemoveWaker works.
	{
		linkRes := &testLinkAddressResolver{cache: c}
		s := sleep.Sleeper{}
		defer s.Done()

		const wakerID = 2 // different than the ID used in the sanity check
		w := sleep.Waker{}
		s.AddWaker(&w, wakerID)

		e := testAddrs[1]
		linkRes.onLinkAddressRequest = func() {
			// Remove the waker before the linkAddrCache has the opportunity to send
			// a notification.
			c.removeWaker(e.addr, &w)
		}

		if _, _, err := c.get(e.addr, linkRes, "", nil, &w); err != tcpip.ErrWouldBlock {
			t.Fatalf("got c.get(%q, _, _, _, _) = %s, want = %s", e.addr.Addr, err, tcpip.ErrWouldBlock)
		}

		if got, err := getBlocking(c, e.addr, linkRes); err != nil {
			t.Fatalf("c.get(%q, _, _, _, _): %s", e.addr.Addr, err)
		} else if got != e.linkAddr {
			t.Fatalf("c.get(%q) = %q, want = %q", e.addr.Addr, got, e.linkAddr)
		}

		if id, ok := s.Fetch(false /* block */); ok {
			t.Fatalf("unexpected notification from waker with id %d", id)
		}
	}
}

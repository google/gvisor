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

package stack

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"gvisor.googlesource.com/gvisor/pkg/sleep"
	"gvisor.googlesource.com/gvisor/pkg/tcpip"
)

type testaddr struct {
	addr     tcpip.FullAddress
	linkAddr tcpip.LinkAddress
}

var testaddrs []testaddr

type testLinkAddressResolver struct {
	cache *linkAddrCache
	delay time.Duration
}

func (r *testLinkAddressResolver) LinkAddressRequest(addr, _ tcpip.Address, _ LinkEndpoint) *tcpip.Error {
	go func() {
		if r.delay > 0 {
			time.Sleep(r.delay)
		}
		r.fakeRequest(addr)
	}()
	return nil
}

func (r *testLinkAddressResolver) fakeRequest(addr tcpip.Address) {
	for _, ta := range testaddrs {
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

func init() {
	for i := 0; i < 4*linkAddrCacheSize; i++ {
		addr := fmt.Sprintf("Addr%06d", i)
		testaddrs = append(testaddrs, testaddr{
			addr:     tcpip.FullAddress{NIC: 1, Addr: tcpip.Address(addr)},
			linkAddr: tcpip.LinkAddress("Link" + addr),
		})
	}
}

func TestCacheOverflow(t *testing.T) {
	c := newLinkAddrCache(1<<63-1, 1*time.Second, 3)
	for i := len(testaddrs) - 1; i >= 0; i-- {
		e := testaddrs[i]
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
		e := testaddrs[i]
		got, _, err := c.get(e.addr, nil, "", nil, nil)
		if err != nil {
			t.Errorf("check %d, c.get(%q)=%q, got error: %v", i, string(e.addr.Addr), got, err)
		}
		if got != e.linkAddr {
			t.Errorf("check %d, c.get(%q)=%q, want %q", i, string(e.addr.Addr), got, e.linkAddr)
		}
	}
	// The earliest entries should no longer be in the cache.
	for i := len(testaddrs) - 1; i >= len(testaddrs)-linkAddrCacheSize; i-- {
		e := testaddrs[i]
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
			for _, e := range testaddrs {
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
	e := testaddrs[len(testaddrs)-1]
	got, _, err := c.get(e.addr, nil, "", nil, nil)
	if err != nil {
		t.Errorf("c.get(%q)=%q, got error: %v", string(e.addr.Addr), got, err)
	}
	if got != e.linkAddr {
		t.Errorf("c.get(%q)=%q, want %q", string(e.addr.Addr), got, e.linkAddr)
	}

	e = testaddrs[0]
	if _, _, err := c.get(e.addr, nil, "", nil, nil); err != tcpip.ErrNoLinkAddress {
		t.Errorf("c.get(%q), got error: %v, want: error ErrNoLinkAddress", string(e.addr.Addr), err)
	}
}

func TestCacheAgeLimit(t *testing.T) {
	c := newLinkAddrCache(1*time.Millisecond, 1*time.Second, 3)
	e := testaddrs[0]
	c.add(e.addr, e.linkAddr)
	time.Sleep(50 * time.Millisecond)
	if _, _, err := c.get(e.addr, nil, "", nil, nil); err != tcpip.ErrNoLinkAddress {
		t.Errorf("c.get(%q), got error: %v, want: error ErrNoLinkAddress", string(e.addr.Addr), err)
	}
}

func TestCacheReplace(t *testing.T) {
	c := newLinkAddrCache(1<<63-1, 1*time.Second, 3)
	e := testaddrs[0]
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
	c := newLinkAddrCache(1<<63-1, 250*time.Millisecond, 1)
	linkRes := &testLinkAddressResolver{cache: c}
	for i, ta := range testaddrs {
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
		e := testaddrs[len(testaddrs)-1]
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

	// First, sanity check that resolution is working...
	e := testaddrs[0]
	got, err := getBlocking(c, e.addr, linkRes)
	if err != nil {
		t.Errorf("c.get(%q)=%q, got error: %v", string(e.addr.Addr), got, err)
	}
	if got != e.linkAddr {
		t.Errorf("c.get(%q)=%q, want %q", string(e.addr.Addr), got, e.linkAddr)
	}

	e.addr.Addr += "2"
	if _, err := getBlocking(c, e.addr, linkRes); err != tcpip.ErrNoLinkAddress {
		t.Errorf("c.get(%q), got error: %v, want: error ErrNoLinkAddress", string(e.addr.Addr), err)
	}
}

func TestCacheResolutionTimeout(t *testing.T) {
	resolverDelay := 500 * time.Millisecond
	expiration := resolverDelay / 10
	c := newLinkAddrCache(expiration, 1*time.Millisecond, 3)
	linkRes := &testLinkAddressResolver{cache: c, delay: resolverDelay}

	e := testaddrs[0]
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

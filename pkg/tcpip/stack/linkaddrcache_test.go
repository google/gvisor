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

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/tcpip"
)

type testaddr struct {
	addr     tcpip.Address
	linkAddr tcpip.LinkAddress
}

var testAddrs = func() []testaddr {
	var addrs []testaddr
	for i := 0; i < 4*linkAddrCacheSize; i++ {
		addr := fmt.Sprintf("Addr%06d", i)
		addrs = append(addrs, testaddr{
			addr:     tcpip.Address(addr),
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
	// TODO(gvisor.dev/issue/5141): Use a fake clock.
	time.AfterFunc(r.delay, func() { r.fakeRequest(targetAddr) })
	if f := r.onLinkAddressRequest; f != nil {
		f()
	}
	return nil
}

func (r *testLinkAddressResolver) fakeRequest(addr tcpip.Address) {
	for _, ta := range testAddrs {
		if ta.addr == addr {
			r.cache.AddLinkAddress(ta.addr, ta.linkAddr)
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

func getBlocking(c *linkAddrCache, addr tcpip.Address, linkRes LinkAddressResolver) (tcpip.LinkAddress, *tcpip.Error) {
	var attemptedResolution bool
	for {
		got, ch, err := c.get(addr, linkRes, "", nil, nil)
		if err == tcpip.ErrWouldBlock {
			if attemptedResolution {
				return got, tcpip.ErrTimeout
			}
			attemptedResolution = true
			<-ch
			continue
		}
		return got, err
	}
}

func newEmptyNIC() *NIC {
	n := &NIC{}
	n.linkResQueue.init(n)
	return n
}

func TestCacheOverflow(t *testing.T) {
	c := newLinkAddrCache(newEmptyNIC(), 1<<63-1, 1*time.Second, 3)
	for i := len(testAddrs) - 1; i >= 0; i-- {
		e := testAddrs[i]
		c.AddLinkAddress(e.addr, e.linkAddr)
		got, _, err := c.get(e.addr, nil, "", nil, nil)
		if err != nil {
			t.Errorf("insert %d, c.get(%s, nil, '', nil, nil): %s", i, e.addr, err)
		}
		if got != e.linkAddr {
			t.Errorf("insert %d, got c.get(%s, nil, '', nil, nil) = %s, want = %s", i, e.addr, got, e.linkAddr)
		}
	}
	// Expect to find at least half of the most recent entries.
	for i := 0; i < linkAddrCacheSize/2; i++ {
		e := testAddrs[i]
		got, _, err := c.get(e.addr, nil, "", nil, nil)
		if err != nil {
			t.Errorf("check %d, c.get(%s, nil, '', nil, nil): %s", i, e.addr, err)
		}
		if got != e.linkAddr {
			t.Errorf("check %d, got c.get(%s, nil, '', nil, nil) = %s, want = %s", i, e.addr, got, e.linkAddr)
		}
	}
	// The earliest entries should no longer be in the cache.
	c.cache.Lock()
	defer c.cache.Unlock()
	for i := len(testAddrs) - 1; i >= len(testAddrs)-linkAddrCacheSize; i-- {
		e := testAddrs[i]
		if entry, ok := c.cache.table[e.addr]; ok {
			t.Errorf("unexpected entry at c.cache.table[%s]: %#v", e.addr, entry)
		}
	}
}

func TestCacheConcurrent(t *testing.T) {
	c := newLinkAddrCache(newEmptyNIC(), 1<<63-1, 1*time.Second, 3)
	linkRes := &testLinkAddressResolver{cache: c}

	var wg sync.WaitGroup
	for r := 0; r < 16; r++ {
		wg.Add(1)
		go func() {
			for _, e := range testAddrs {
				c.AddLinkAddress(e.addr, e.linkAddr)
			}
			wg.Done()
		}()
	}
	wg.Wait()

	// All goroutines add in the same order and add more values than
	// can fit in the cache, so our eviction strategy requires that
	// the last entry be present and the first be missing.
	e := testAddrs[len(testAddrs)-1]
	got, _, err := c.get(e.addr, linkRes, "", nil, nil)
	if err != nil {
		t.Errorf("c.get(%s, _, '', nil, nil): %s", e.addr, err)
	}
	if got != e.linkAddr {
		t.Errorf("got c.get(%s, _, '', nil, nil) = %s, want = %s", e.addr, got, e.linkAddr)
	}

	e = testAddrs[0]
	c.cache.Lock()
	defer c.cache.Unlock()
	if entry, ok := c.cache.table[e.addr]; ok {
		t.Errorf("unexpected entry at c.cache.table[%s]: %#v", e.addr, entry)
	}
}

func TestCacheAgeLimit(t *testing.T) {
	c := newLinkAddrCache(newEmptyNIC(), 1*time.Millisecond, 1*time.Second, 3)
	linkRes := &testLinkAddressResolver{cache: c}

	e := testAddrs[0]
	c.AddLinkAddress(e.addr, e.linkAddr)
	time.Sleep(50 * time.Millisecond)
	if _, _, err := c.get(e.addr, linkRes, "", nil, nil); err != tcpip.ErrWouldBlock {
		t.Errorf("got c.get(%s, _, '', nil, nil) = %s, want = ErrWouldBlock", e.addr, err)
	}
}

func TestCacheReplace(t *testing.T) {
	c := newLinkAddrCache(newEmptyNIC(), 1<<63-1, 1*time.Second, 3)
	e := testAddrs[0]
	l2 := e.linkAddr + "2"
	c.AddLinkAddress(e.addr, e.linkAddr)
	got, _, err := c.get(e.addr, nil, "", nil, nil)
	if err != nil {
		t.Errorf("c.get(%s, nil, '', nil, nil): %s", e.addr, err)
	}
	if got != e.linkAddr {
		t.Errorf("got c.get(%s, nil, '', nil, nil) = %s, want = %s", e.addr, got, e.linkAddr)
	}

	c.AddLinkAddress(e.addr, l2)
	got, _, err = c.get(e.addr, nil, "", nil, nil)
	if err != nil {
		t.Errorf("c.get(%s, nil, '', nil, nil): %s", e.addr, err)
	}
	if got != l2 {
		t.Errorf("got c.get(%s, nil, '', nil, nil) = %s, want = %s", e.addr, got, l2)
	}
}

func TestCacheResolution(t *testing.T) {
	// There is a race condition causing this test to fail when the executor
	// takes longer than the resolution timeout to call linkAddrCache.get. This
	// is especially common when this test is run with gotsan.
	//
	// Using a large resolution timeout decreases the probability of experiencing
	// this race condition and does not affect how long this test takes to run.
	c := newLinkAddrCache(newEmptyNIC(), 1<<63-1, math.MaxInt64, 1)
	linkRes := &testLinkAddressResolver{cache: c}
	for i, ta := range testAddrs {
		got, err := getBlocking(c, ta.addr, linkRes)
		if err != nil {
			t.Errorf("check %d, getBlocking(_, %s, _): %s", i, ta.addr, err)
		}
		if got != ta.linkAddr {
			t.Errorf("check %d, got getBlocking(_, %s, _) = %s, want = %s", i, ta.addr, got, ta.linkAddr)
		}
	}

	// Check that after resolved, address stays in the cache and never returns WouldBlock.
	for i := 0; i < 10; i++ {
		e := testAddrs[len(testAddrs)-1]
		got, _, err := c.get(e.addr, linkRes, "", nil, nil)
		if err != nil {
			t.Errorf("c.get(%s, _, '', nil, nil): %s", e.addr, err)
		}
		if got != e.linkAddr {
			t.Errorf("got c.get(%s, _, '', nil, nil) = %s, want = %s", e.addr, got, e.linkAddr)
		}
	}
}

func TestCacheResolutionFailed(t *testing.T) {
	c := newLinkAddrCache(newEmptyNIC(), 1<<63-1, 10*time.Millisecond, 5)
	linkRes := &testLinkAddressResolver{cache: c}

	var requestCount uint32
	linkRes.onLinkAddressRequest = func() {
		atomic.AddUint32(&requestCount, 1)
	}

	// First, sanity check that resolution is working...
	e := testAddrs[0]
	got, err := getBlocking(c, e.addr, linkRes)
	if err != nil {
		t.Errorf("getBlocking(_, %s, _): %s", e.addr, err)
	}
	if got != e.linkAddr {
		t.Errorf("got getBlocking(_, %s, _) = %s, want = %s", e.addr, got, e.linkAddr)
	}

	before := atomic.LoadUint32(&requestCount)

	e.addr += "2"
	if a, err := getBlocking(c, e.addr, linkRes); err != tcpip.ErrTimeout {
		t.Errorf("got getBlocking(_, %s, _) = (%s, %s), want = (_, %s)", e.addr, a, err, tcpip.ErrTimeout)
	}

	if got, want := int(atomic.LoadUint32(&requestCount)-before), c.resolutionAttempts; got != want {
		t.Errorf("got link address request count = %d, want = %d", got, want)
	}
}

func TestCacheResolutionTimeout(t *testing.T) {
	resolverDelay := 500 * time.Millisecond
	expiration := resolverDelay / 10
	c := newLinkAddrCache(newEmptyNIC(), expiration, 1*time.Millisecond, 3)
	linkRes := &testLinkAddressResolver{cache: c, delay: resolverDelay}

	e := testAddrs[0]
	if a, err := getBlocking(c, e.addr, linkRes); err != tcpip.ErrTimeout {
		t.Errorf("got getBlocking(_, %s, _) = (%s, %s), want = (_, %s)", e.addr, a, err, tcpip.ErrTimeout)
	}
}

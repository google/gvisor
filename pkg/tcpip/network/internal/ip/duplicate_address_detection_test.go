// Copyright 2021 The gVisor Authors.
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

package ip_test

import (
	"bytes"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/faketime"
	"gvisor.dev/gvisor/pkg/tcpip/network/internal/ip"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

type mockDADProtocol struct {
	t *testing.T

	mu struct {
		sync.Mutex

		dad        ip.DAD
		sentNonces map[tcpip.Address][][]byte
	}
}

func (m *mockDADProtocol) init(t *testing.T, c stack.DADConfigurations, opts ip.DADOptions) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.t = t
	opts.Protocol = m
	m.mu.dad.Init(&m.mu, c, opts)
	m.initLocked()
}

func (m *mockDADProtocol) initLocked() {
	m.mu.sentNonces = make(map[tcpip.Address][][]byte)
}

func (m *mockDADProtocol) SendDADMessage(addr tcpip.Address, nonce []byte) tcpip.Error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.mu.sentNonces[addr] = append(m.mu.sentNonces[addr], nonce)
	return nil
}

func (m *mockDADProtocol) check(addrs []tcpip.Address) string {
	sentNonces := make(map[tcpip.Address][][]byte)
	for _, a := range addrs {
		sentNonces[a] = append(sentNonces[a], nil)
	}

	return m.checkWithNonce(sentNonces)
}

func (m *mockDADProtocol) checkWithNonce(expectedSentNonces map[tcpip.Address][][]byte) string {
	m.mu.Lock()
	defer m.mu.Unlock()

	diff := cmp.Diff(expectedSentNonces, m.mu.sentNonces)
	m.initLocked()
	return diff
}

func (m *mockDADProtocol) checkDuplicateAddress(addr tcpip.Address, h stack.DADCompletionHandler) stack.DADCheckAddressDisposition {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.mu.dad.CheckDuplicateAddressLocked(addr, h)
}

func (m *mockDADProtocol) stop(addr tcpip.Address, reason stack.DADResult) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.mu.dad.StopLocked(addr, reason)
}

func (m *mockDADProtocol) extendIfNonceEqual(addr tcpip.Address, nonce []byte) ip.ExtendIfNonceEqualLockedDisposition {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.mu.dad.ExtendIfNonceEqualLocked(addr, nonce)
}

func (m *mockDADProtocol) setConfigs(c stack.DADConfigurations) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.mu.dad.SetConfigsLocked(c)
}

var (
	addr1 = tcpip.AddrFromSlice([]byte("\x01\x00\x00\x00"))
	addr2 = tcpip.AddrFromSlice([]byte("\x02\x00\x00\x00"))
	addr3 = tcpip.AddrFromSlice([]byte("\x03\x00\x00\x00"))
	addr4 = tcpip.AddrFromSlice([]byte("\x04\x00\x00\x00"))
)

type dadResult struct {
	Addr tcpip.Address
	R    stack.DADResult
}

func handler(ch chan<- dadResult, a tcpip.Address) func(stack.DADResult) {
	return func(r stack.DADResult) {
		ch <- dadResult{Addr: a, R: r}
	}
}

func TestDADCheckDuplicateAddress(t *testing.T) {
	var dad mockDADProtocol
	clock := faketime.NewManualClock()
	dad.init(t, stack.DADConfigurations{}, ip.DADOptions{
		Clock: clock,
	})

	ch := make(chan dadResult, 2)

	// DAD should initially be disabled.
	if res := dad.checkDuplicateAddress(addr1, handler(nil, tcpip.Address{})); res != stack.DADDisabled {
		t.Errorf("got dad.checkDuplicateAddress(%s, _) = %d, want = %d", addr1, res, stack.DADDisabled)
	}
	// Wait for any initially fired timers to complete.
	clock.RunImmediatelyScheduledJobs()
	if diff := dad.check(nil); diff != "" {
		t.Errorf("dad check mismatch (-want +got):\n%s", diff)
	}

	// Enable and request DAD.
	dadConfigs1 := stack.DADConfigurations{
		DupAddrDetectTransmits: 1,
		RetransmitTimer:        time.Second,
	}
	dad.setConfigs(dadConfigs1)
	if res := dad.checkDuplicateAddress(addr1, handler(ch, addr1)); res != stack.DADStarting {
		t.Errorf("got dad.checkDuplicateAddress(%s, _) = %d, want = %d", addr1, res, stack.DADStarting)
	}
	clock.RunImmediatelyScheduledJobs()
	if diff := dad.check([]tcpip.Address{addr1}); diff != "" {
		t.Errorf("dad check mismatch (-want +got):\n%s", diff)
	}
	// The second request for DAD on the same address should use the original
	// request since it has not completed yet.
	if res := dad.checkDuplicateAddress(addr1, handler(ch, addr1)); res != stack.DADAlreadyRunning {
		t.Errorf("got dad.checkDuplicateAddress(%s, _) = %d, want = %d", addr1, res, stack.DADAlreadyRunning)
	}
	clock.RunImmediatelyScheduledJobs()
	if diff := dad.check(nil); diff != "" {
		t.Errorf("dad check mismatch (-want +got):\n%s", diff)
	}

	dadConfigs2 := stack.DADConfigurations{
		DupAddrDetectTransmits: 2,
		RetransmitTimer:        time.Second,
	}
	dad.setConfigs(dadConfigs2)
	// A new address should start a new DAD process.
	if res := dad.checkDuplicateAddress(addr2, handler(ch, addr2)); res != stack.DADStarting {
		t.Errorf("got dad.checkDuplicateAddress(%s, _) = %d, want = %d", addr2, res, stack.DADStarting)
	}
	clock.RunImmediatelyScheduledJobs()
	if diff := dad.check([]tcpip.Address{addr2}); diff != "" {
		t.Errorf("dad check mismatch (-want +got):\n%s", diff)
	}

	// Make sure DAD for addr1 only resolves after the expected timeout.
	const delta = time.Nanosecond
	dadConfig1Duration := time.Duration(dadConfigs1.DupAddrDetectTransmits) * dadConfigs1.RetransmitTimer
	clock.Advance(dadConfig1Duration - delta)
	select {
	case r := <-ch:
		t.Fatalf("unexpectedly got a DAD result before the expected timeout of %s; r = %#v", dadConfig1Duration, r)
	default:
	}
	clock.Advance(delta)
	for i := 0; i < 2; i++ {
		if diff := cmp.Diff(dadResult{Addr: addr1, R: &stack.DADSucceeded{}}, <-ch); diff != "" {
			t.Errorf("(i=%d) dad result mismatch (-want +got):\n%s", i, diff)
		}
	}

	// Make sure DAD for addr2 only resolves after the expected timeout.
	dadConfig2Duration := time.Duration(dadConfigs2.DupAddrDetectTransmits) * dadConfigs2.RetransmitTimer
	clock.Advance(dadConfig2Duration - dadConfig1Duration - delta)
	select {
	case r := <-ch:
		t.Fatalf("unexpectedly got a DAD result before the expected timeout of %s; r = %#v", dadConfig2Duration, r)
	default:
	}
	clock.Advance(delta)
	if diff := cmp.Diff(dadResult{Addr: addr2, R: &stack.DADSucceeded{}}, <-ch); diff != "" {
		t.Errorf("dad result mismatch (-want +got):\n%s", diff)
	}

	// Should be able to restart DAD for addr2 after it resolved.
	if res := dad.checkDuplicateAddress(addr2, handler(ch, addr2)); res != stack.DADStarting {
		t.Errorf("got dad.checkDuplicateAddress(%s, _) = %d, want = %d", addr2, res, stack.DADStarting)
	}
	clock.RunImmediatelyScheduledJobs()
	if diff := dad.check([]tcpip.Address{addr2, addr2}); diff != "" {
		t.Errorf("dad check mismatch (-want +got):\n%s", diff)
	}
	clock.Advance(dadConfig2Duration)
	if diff := cmp.Diff(dadResult{Addr: addr2, R: &stack.DADSucceeded{}}, <-ch); diff != "" {
		t.Errorf("dad result mismatch (-want +got):\n%s", diff)
	}

	// Should not have anymore results.
	select {
	case r := <-ch:
		t.Fatalf("unexpectedly got an extra DAD result; r = %#v", r)
	default:
	}
}

func TestDADStop(t *testing.T) {
	var dad mockDADProtocol
	clock := faketime.NewManualClock()
	dadConfigs := stack.DADConfigurations{
		DupAddrDetectTransmits: 1,
		RetransmitTimer:        time.Second,
	}
	dad.init(t, dadConfigs, ip.DADOptions{
		Clock: clock,
	})

	ch := make(chan dadResult, 1)

	if res := dad.checkDuplicateAddress(addr1, handler(ch, addr1)); res != stack.DADStarting {
		t.Errorf("got dad.checkDuplicateAddress(%s, _) = %d, want = %d", addr1, res, stack.DADStarting)
	}
	if res := dad.checkDuplicateAddress(addr2, handler(ch, addr2)); res != stack.DADStarting {
		t.Errorf("got dad.checkDuplicateAddress(%s, _) = %d, want = %d", addr2, res, stack.DADStarting)
	}
	if res := dad.checkDuplicateAddress(addr3, handler(ch, addr3)); res != stack.DADStarting {
		t.Errorf("got dad.checkDuplicateAddress(%s, _) = %d, want = %d", addr2, res, stack.DADStarting)
	}
	clock.RunImmediatelyScheduledJobs()
	if diff := dad.check([]tcpip.Address{addr1, addr2, addr3}); diff != "" {
		t.Errorf("dad check mismatch (-want +got):\n%s", diff)
	}

	dad.stop(addr1, &stack.DADAborted{})
	if diff := cmp.Diff(dadResult{Addr: addr1, R: &stack.DADAborted{}}, <-ch); diff != "" {
		t.Errorf("dad result mismatch (-want +got):\n%s", diff)
	}

	dad.stop(addr2, &stack.DADDupAddrDetected{})
	if diff := cmp.Diff(dadResult{Addr: addr2, R: &stack.DADDupAddrDetected{}}, <-ch); diff != "" {
		t.Errorf("dad result mismatch (-want +got):\n%s", diff)
	}

	dadResolutionDuration := time.Duration(dadConfigs.DupAddrDetectTransmits) * dadConfigs.RetransmitTimer
	clock.Advance(dadResolutionDuration)
	if diff := cmp.Diff(dadResult{Addr: addr3, R: &stack.DADSucceeded{}}, <-ch); diff != "" {
		t.Errorf("dad result mismatch (-want +got):\n%s", diff)
	}

	// Should be able to restart DAD for an address we stopped DAD on.
	if res := dad.checkDuplicateAddress(addr1, handler(ch, addr1)); res != stack.DADStarting {
		t.Errorf("got dad.checkDuplicateAddress(%s, _) = %d, want = %d", addr1, res, stack.DADStarting)
	}
	clock.RunImmediatelyScheduledJobs()
	if diff := dad.check([]tcpip.Address{addr1}); diff != "" {
		t.Errorf("dad check mismatch (-want +got):\n%s", diff)
	}
	clock.Advance(dadResolutionDuration)
	if diff := cmp.Diff(dadResult{Addr: addr1, R: &stack.DADSucceeded{}}, <-ch); diff != "" {
		t.Errorf("dad result mismatch (-want +got):\n%s", diff)
	}

	// Should not have anymore updates.
	select {
	case r := <-ch:
		t.Fatalf("unexpectedly got an extra DAD result; r = %#v", r)
	default:
	}
}

func TestNonce(t *testing.T) {
	const (
		nonceSize = 2

		extendRequestAttempts = 2

		dupAddrDetectTransmits = 2
		extendTransmits        = 5
	)

	var secureRNGBytes [nonceSize * (dupAddrDetectTransmits + extendTransmits)]byte
	for i := range secureRNGBytes {
		secureRNGBytes[i] = byte(i)
	}

	tests := []struct {
		name                string
		mockedReceivedNonce []byte
		expectedResults     [extendRequestAttempts]ip.ExtendIfNonceEqualLockedDisposition
		expectedTransmits   int
	}{
		{
			name:                "not matching",
			mockedReceivedNonce: []byte{0, 0},
			expectedResults:     [extendRequestAttempts]ip.ExtendIfNonceEqualLockedDisposition{ip.NonceNotEqual, ip.NonceNotEqual},
			expectedTransmits:   dupAddrDetectTransmits,
		},
		{
			name:                "matching nonce",
			mockedReceivedNonce: secureRNGBytes[:nonceSize],
			expectedResults:     [extendRequestAttempts]ip.ExtendIfNonceEqualLockedDisposition{ip.Extended, ip.AlreadyExtended},
			expectedTransmits:   dupAddrDetectTransmits + extendTransmits,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var dad mockDADProtocol
			clock := faketime.NewManualClock()
			dadConfigs := stack.DADConfigurations{
				DupAddrDetectTransmits: dupAddrDetectTransmits,
				RetransmitTimer:        time.Second,
			}

			var secureRNG bytes.Reader
			secureRNG.Reset(secureRNGBytes[:])
			dad.init(t, dadConfigs, ip.DADOptions{
				Clock:              clock,
				SecureRNG:          &secureRNG,
				NonceSize:          nonceSize,
				ExtendDADTransmits: extendTransmits,
			})

			ch := make(chan dadResult, 1)
			if res := dad.checkDuplicateAddress(addr1, handler(ch, addr1)); res != stack.DADStarting {
				t.Errorf("got dad.checkDuplicateAddress(%s, _) = %d, want = %d", addr1, res, stack.DADStarting)
			}

			clock.RunImmediatelyScheduledJobs()
			for i, want := range test.expectedResults {
				if got := dad.extendIfNonceEqual(addr1, test.mockedReceivedNonce); got != want {
					t.Errorf("(i=%d) got dad.extendIfNonceEqual(%s, _) = %d, want = %d", i, addr1, got, want)
				}
			}

			for i := 0; i < test.expectedTransmits; i++ {
				if diff := dad.checkWithNonce(map[tcpip.Address][][]byte{
					addr1: {
						secureRNGBytes[nonceSize*i:][:nonceSize],
					},
				}); diff != "" {
					t.Errorf("(i=%d) dad check mismatch (-want +got):\n%s", i, diff)
				}

				clock.Advance(dadConfigs.RetransmitTimer)
			}

			if diff := cmp.Diff(dadResult{Addr: addr1, R: &stack.DADSucceeded{}}, <-ch); diff != "" {
				t.Errorf("dad result mismatch (-want +got):\n%s", diff)
			}

			// Should not have anymore updates.
			select {
			case r := <-ch:
				t.Fatalf("unexpectedly got an extra DAD result; r = %#v", r)
			default:
			}
		})
	}
}

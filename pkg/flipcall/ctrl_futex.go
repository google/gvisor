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

//go:build go1.1
// +build go1.1

package flipcall

import (
	"encoding/json"
	"fmt"
	"math"
	"sync/atomic"

	"gvisor.dev/gvisor/pkg/log"
)

type endpointControlImpl struct {
	state int32
}

// Bits in endpointControlImpl.state.
const (
	epsBlocked = 1 << iota
	epsShutdown
)

func (ep *Endpoint) ctrlInit(opts ...EndpointOption) error {
	if len(opts) != 0 {
		return fmt.Errorf("unknown EndpointOption: %T", opts[0])
	}
	return nil
}

func (ep *Endpoint) ctrlConnect() error {
	if err := ep.enterFutexWait(); err != nil {
		return err
	}
	defer ep.exitFutexWait()

	// Write the connection request.
	w := ep.NewWriter()
	if err := json.NewEncoder(w).Encode(struct{}{}); err != nil {
		return fmt.Errorf("error writing connection request: %v", err)
	}
	*ep.dataLen() = w.Len()

	// Exchange control with the server.
	if err := ep.futexSetPeerActive(); err != nil {
		return err
	}
	if err := ep.futexWakePeer(); err != nil {
		return err
	}
	if err := ep.futexWaitUntilActive(); err != nil {
		return err
	}

	// Read the connection response.
	var resp struct{}
	respLen := atomic.LoadUint32(ep.dataLen())
	if respLen > ep.dataCap {
		return fmt.Errorf("invalid connection response length %d (maximum %d)", respLen, ep.dataCap)
	}
	if err := json.NewDecoder(ep.NewReader(respLen)).Decode(&resp); err != nil {
		return fmt.Errorf("error reading connection response: %v", err)
	}

	return nil
}

func (ep *Endpoint) ctrlWaitFirst() error {
	if err := ep.enterFutexWait(); err != nil {
		return err
	}
	defer ep.exitFutexWait()

	// Wait for the connection request.
	if err := ep.futexWaitUntilActive(); err != nil {
		return err
	}

	// Read the connection request.
	reqLen := atomic.LoadUint32(ep.dataLen())
	if reqLen > ep.dataCap {
		return fmt.Errorf("invalid connection request length %d (maximum %d)", reqLen, ep.dataCap)
	}
	var req struct{}
	if err := json.NewDecoder(ep.NewReader(reqLen)).Decode(&req); err != nil {
		return fmt.Errorf("error reading connection request: %v", err)
	}

	// Write the connection response.
	w := ep.NewWriter()
	if err := json.NewEncoder(w).Encode(struct{}{}); err != nil {
		return fmt.Errorf("error writing connection response: %v", err)
	}
	*ep.dataLen() = w.Len()

	// Return control to the client.
	raceBecomeInactive()
	if err := ep.futexSetPeerActive(); err != nil {
		return err
	}
	if err := ep.futexWakePeer(); err != nil {
		return err
	}

	// Wait for the first non-connection message.
	return ep.futexWaitUntilActive()
}

func (ep *Endpoint) ctrlRoundTrip(mayRetainP bool) error {
	if err := ep.enterFutexWait(); err != nil {
		return err
	}
	defer ep.exitFutexWait()

	if err := ep.futexSetPeerActive(); err != nil {
		return err
	}
	if err := ep.futexWakePeer(); err != nil {
		return err
	}
	// Since we don't know if the peer Endpoint is in the same process as this
	// one (in which case it may need our P to run), we allow our P to be
	// retaken regardless of mayRetainP.
	return ep.futexWaitUntilActive()
}

func (ep *Endpoint) ctrlWakeLast() error {
	if err := ep.futexSetPeerActive(); err != nil {
		return err
	}
	return ep.futexWakePeer()
}

func (ep *Endpoint) enterFutexWait() error {
	switch eps := atomic.AddInt32(&ep.ctrl.state, epsBlocked); eps {
	case epsBlocked:
		return nil
	case epsBlocked | epsShutdown:
		atomic.AddInt32(&ep.ctrl.state, -epsBlocked)
		return ShutdownError{}
	default:
		// Most likely due to ep.enterFutexWait() being called concurrently
		// from multiple goroutines.
		panic(fmt.Sprintf("invalid flipcall.Endpoint.ctrl.state before flipcall.Endpoint.enterFutexWait(): %v", eps-epsBlocked))
	}
}

func (ep *Endpoint) exitFutexWait() {
	switch eps := atomic.AddInt32(&ep.ctrl.state, -epsBlocked); eps {
	case 0:
		return
	case epsShutdown:
		// ep.ctrlShutdown() was called while we were blocked, so we are
		// repsonsible for indicating connection shutdown.
		ep.shutdownConn()
	default:
		panic(fmt.Sprintf("invalid flipcall.Endpoint.ctrl.state after flipcall.Endpoint.exitFutexWait(): %v", eps+epsBlocked))
	}
}

func (ep *Endpoint) ctrlShutdown() {
	// Set epsShutdown to ensure that future calls to ep.enterFutexWait() fail.
	if atomic.AddInt32(&ep.ctrl.state, epsShutdown)&epsBlocked != 0 {
		// Wake the blocked thread. This must loop because it's possible that
		// FUTEX_WAKE occurs after the waiter sets epsBlocked, but before it
		// blocks in FUTEX_WAIT.
		for {
			// Wake MaxInt32 threads to prevent a broken or malicious peer from
			// swallowing our wakeup by FUTEX_WAITing from multiple threads.
			if err := ep.futexWakeConnState(math.MaxInt32); err != nil {
				log.Warningf("failed to FUTEX_WAKE Endpoints: %v", err)
				break
			}
			yieldThread()
			if atomic.LoadInt32(&ep.ctrl.state)&epsBlocked == 0 {
				break
			}
		}
	} else {
		// There is no blocked thread, so we are responsible for indicating
		// connection shutdown.
		ep.shutdownConn()
	}
}

func (ep *Endpoint) shutdownConn() {
	switch cs := atomic.SwapUint32(ep.connState(), csShutdown); cs {
	case ep.activeState:
		if err := ep.futexWakeConnState(1); err != nil {
			log.Warningf("failed to FUTEX_WAKE peer Endpoint for shutdown: %v", err)
		}
	case ep.inactiveState:
		// The peer is currently active and will detect shutdown when it tries
		// to update the connection state.
	case csShutdown:
		// The peer also called Endpoint.Shutdown().
	default:
		log.Warningf("unexpected connection state before Endpoint.shutdownConn(): %v", cs)
	}
}

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

type ctrlHandshakeRequest struct{}

type ctrlHandshakeResponse struct{}

func (ep *Endpoint) ctrlConnect() error {
	if err := ep.enterFutexWait(); err != nil {
		return err
	}
	_, err := ep.futexConnect(&ctrlHandshakeRequest{})
	ep.exitFutexWait()
	return err
}

func (ep *Endpoint) ctrlWaitFirst() error {
	if err := ep.enterFutexWait(); err != nil {
		return err
	}
	defer ep.exitFutexWait()

	// Wait for the handshake request.
	if err := ep.futexSwitchFromPeer(); err != nil {
		return err
	}

	// Read the handshake request.
	reqLen := atomic.LoadUint32(ep.dataLen())
	if reqLen > ep.dataCap {
		return fmt.Errorf("invalid handshake request length %d (maximum %d)", reqLen, ep.dataCap)
	}
	var req ctrlHandshakeRequest
	if err := json.NewDecoder(ep.NewReader(reqLen)).Decode(&req); err != nil {
		return fmt.Errorf("error reading handshake request: %v", err)
	}

	// Write the handshake response.
	w := ep.NewWriter()
	if err := json.NewEncoder(w).Encode(ctrlHandshakeResponse{}); err != nil {
		return fmt.Errorf("error writing handshake response: %v", err)
	}
	*ep.dataLen() = w.Len()

	// Return control to the client.
	if err := ep.futexSwitchToPeer(); err != nil {
		return err
	}

	// Wait for the first non-handshake message.
	return ep.futexSwitchFromPeer()
}

func (ep *Endpoint) ctrlRoundTrip() error {
	if err := ep.futexSwitchToPeer(); err != nil {
		return err
	}
	if err := ep.enterFutexWait(); err != nil {
		return err
	}
	err := ep.futexSwitchFromPeer()
	ep.exitFutexWait()
	return err
}

func (ep *Endpoint) ctrlWakeLast() error {
	return ep.futexSwitchToPeer()
}

func (ep *Endpoint) enterFutexWait() error {
	switch eps := atomic.AddInt32(&ep.ctrl.state, epsBlocked); eps {
	case epsBlocked:
		return nil
	case epsBlocked | epsShutdown:
		atomic.AddInt32(&ep.ctrl.state, -epsBlocked)
		return shutdownError{}
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

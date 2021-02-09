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

// Package ip holds IPv4/IPv6 common utilities.
package ip

import (
	"fmt"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

type dadState struct {
	done  *bool
	timer tcpip.Timer

	completionHandlers []stack.DADCompletionHandler
}

// DADProtocol is a protocol whose core state machine can be represented by DAD.
type DADProtocol interface {
	// SendDADMessage attempts to send a DAD probe message.
	SendDADMessage(tcpip.Address) tcpip.Error
}

// DADOptions holds options for DAD.
type DADOptions struct {
	Clock    tcpip.Clock
	Protocol DADProtocol
	NICID    tcpip.NICID
}

// DAD performs duplicate address detection for addresses.
type DAD struct {
	opts    DADOptions
	configs stack.DADConfigurations

	protocolMU sync.Locker
	addresses  map[tcpip.Address]dadState
}

// Init initializes the DAD state.
//
// Must only be called once for the lifetime of d; Init will panic if it is
// called twice.
//
// The lock will only be taken when timers fire.
func (d *DAD) Init(protocolMU sync.Locker, configs stack.DADConfigurations, opts DADOptions) {
	if d.addresses != nil {
		panic("attempted to initialize DAD state twice")
	}

	*d = DAD{
		opts:       opts,
		configs:    configs,
		protocolMU: protocolMU,
		addresses:  make(map[tcpip.Address]dadState),
	}
}

// CheckDuplicateAddressLocked performs DAD for an address, calling the
// completion handler once DAD resolves.
//
// If DAD is already performing for the provided address, h will be called when
// the currently running process completes.
//
// Precondition: d.protocolMU must be locked.
func (d *DAD) CheckDuplicateAddressLocked(addr tcpip.Address, h stack.DADCompletionHandler) stack.DADCheckAddressDisposition {
	if d.configs.DupAddrDetectTransmits == 0 {
		return stack.DADDisabled
	}

	ret := stack.DADAlreadyRunning
	s, ok := d.addresses[addr]
	if !ok {
		ret = stack.DADStarting

		remaining := d.configs.DupAddrDetectTransmits

		// Protected by d.protocolMU.
		done := false

		s = dadState{
			done: &done,
			timer: d.opts.Clock.AfterFunc(0, func() {
				var err tcpip.Error
				dadDone := remaining == 0
				if !dadDone {
					err = d.opts.Protocol.SendDADMessage(addr)
				}

				d.protocolMU.Lock()
				defer d.protocolMU.Unlock()

				if done {
					return
				}

				s, ok := d.addresses[addr]
				if !ok {
					panic(fmt.Sprintf("dad: timer fired but missing state for %s on NIC(%d)", addr, d.opts.NICID))
				}

				if !dadDone && err == nil {
					remaining--
					s.timer.Reset(d.configs.RetransmitTimer)
					return
				}

				// At this point we know that either DAD has resolved or we hit an error
				// sending the last DAD message. Either way, clear the DAD state.
				done = false
				s.timer.Stop()
				delete(d.addresses, addr)

				r := stack.DADResult{Resolved: dadDone, Err: err}
				for _, h := range s.completionHandlers {
					h(r)
				}
			}),
		}
	}

	s.completionHandlers = append(s.completionHandlers, h)
	d.addresses[addr] = s
	return ret
}

// StopLocked stops a currently running DAD process.
//
// Precondition: d.protocolMU must be locked.
func (d *DAD) StopLocked(addr tcpip.Address, aborted bool) {
	s, ok := d.addresses[addr]
	if !ok {
		return
	}

	*s.done = true
	s.timer.Stop()
	delete(d.addresses, addr)

	var err tcpip.Error
	if aborted {
		err = &tcpip.ErrAborted{}
	}

	r := stack.DADResult{Resolved: false, Err: err}
	for _, h := range s.completionHandlers {
		h(r)
	}
}

// SetConfigsLocked sets the DAD configurations.
//
// Precondition: d.protocolMU must be locked.
func (d *DAD) SetConfigsLocked(c stack.DADConfigurations) {
	c.Validate()
	d.configs = c
}

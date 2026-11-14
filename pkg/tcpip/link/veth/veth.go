// Copyright 2024 The gVisor Authors.
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

// Package veth provides the implementation of virtual ethernet device pair.
package veth

import (
	"context"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// DefaultBacklogSize is the default size of a veth device's buffer.
const DefaultBacklogSize = 1000

var _ stack.LinkEndpoint = (*Endpoint)(nil)
var _ stack.PausableLinkEndpoint = (*Endpoint)(nil)
var _ stack.GSOEndpoint = (*Endpoint)(nil)

// +stateify savable
type savedVethBacklog struct {
	packets  []vethPacket
	capacity int
}

// +stateify savable
type veth struct {
	mu vethRWMutex `state:"nosave"`

	// +checklocks:mu
	closed bool

	// paused indicates that no worker goroutine is running (stopCh is closed
	// or nil).
	//
	// +checklocks:mu
	paused bool `state:"nosave"`

	backlogQueue chan vethPacket `state:".(savedVethBacklog)"`
	// stopCh signals the active worker to exit. Closed at most once per worker
	// instance and recreated in resume.
	stopCh chan struct{}  `state:"nosave"`
	wg     sync.WaitGroup `state:"nosave"`

	// +checklocks:mu
	mtu uint32

	endpoints [2]Endpoint
}

func (v *veth) worker(ch <-chan vethPacket, stopCh <-chan struct{}) {
	defer v.wg.Done()
	for {
		// Check stopCh first so stopping takes precedence over a ready packet
		// in ch.
		select {
		case <-stopCh:
			return
		default:
		}
		select {
		case <-stopCh:
			return
		case t := <-ch:
			t.e.InjectInbound(t.protocol, t.pkt)
			t.pkt.DecRef()
		}
	}
}

// pause stops the worker goroutine and waits for any in-flight InjectInbound
// call to finish.
//
// Callers must not hold any lock that the inbound delivery path can acquire
// (such as Stack.mu or BridgeEndpoint.mu), and pause must not run concurrently
// with resume (otherwise resume could start a new worker with an open stopCh
// before v.wg.Wait returns, causing pause to block indefinitely).
//
// +checklocksexclude:v.mu
func (v *veth) pause() {
	v.mu.Lock()
	if v.closed {
		v.mu.Unlock()
		return
	}
	if !v.paused {
		v.paused = true
		close(v.stopCh)
	}
	v.mu.Unlock()

	v.wg.Wait()
}

// resume starts a new worker goroutine to drain backlogQueue.
//
// resume must not run concurrently with pause; see pause.
//
// +checklocksexclude:v.mu
func (v *veth) resume() {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.closed || !v.paused {
		return
	}
	v.paused = false
	v.stopCh = make(chan struct{})
	v.wg.Add(1)
	go v.worker(v.backlogQueue, v.stopCh)
}

// close shuts down both endpoints, waiting for the worker goroutine to exit,
// discarding queued packets, and invoking close callbacks.
//
// Because close blocks on v.wg.Wait until the worker finishes InjectInbound,
// the caller must not hold any lock that the inbound delivery path can acquire
// (such as Stack.mu or BridgeEndpoint.mu), nor either endpoint's mutex.
// checklocks cannot name the endpoint mutexes through the endpoints array.
//
// +checklocksexclude:v.mu
func (v *veth) close() {
	v.mu.Lock()
	alreadyClosed := v.closed
	if !alreadyClosed {
		v.closed = true
		if !v.paused {
			close(v.stopCh)
		}
	}
	v.mu.Unlock()

	v.wg.Wait()

	v.mu.Lock()
	for len(v.backlogQueue) > 0 {
		pkt := <-v.backlogQueue
		pkt.pkt.DecRef()
	}
	v.mu.Unlock()

	if alreadyClosed {
		return
	}

	for i := range v.endpoints {
		e := &v.endpoints[i]
		e.mu.Lock()
		action := e.onCloseAction
		e.onCloseAction = nil
		e.mu.Unlock()
		if action != nil {
			action()
		}
	}
}

// +checklocksexclude:v.mu
func (v *veth) saveBacklogQueue() savedVethBacklog {
	v.mu.Lock()
	defer v.mu.Unlock()

	sb := savedVethBacklog{
		capacity: cap(v.backlogQueue),
	}
	if len(v.backlogQueue) == 0 {
		return sb
	}
	sb.packets = make([]vethPacket, 0, len(v.backlogQueue))
	for len(v.backlogQueue) > 0 {
		sb.packets = append(sb.packets, <-v.backlogQueue)
	}
	if !v.closed {
		for _, pkt := range sb.packets {
			v.backlogQueue <- pkt
		}
	} else {
		for _, pkt := range sb.packets {
			pkt.pkt.DecRef()
		}
		sb.packets = nil
	}
	return sb
}

// +checklocksexclude:v.mu
func (v *veth) loadBacklogQueue(_ context.Context, sb savedVethBacklog) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.backlogQueue = make(chan vethPacket, sb.capacity)
	for _, pkt := range sb.packets {
		v.backlogQueue <- pkt
	}
}

// afterLoad is invoked by stateify.
//
// +checklocksexclude:v.mu
func (v *veth) afterLoad(context.Context) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.paused = true
}

// +stateify savable
type vethPacket struct {
	e        *Endpoint
	protocol tcpip.NetworkProtocolNumber
	pkt      *stack.PacketBuffer
}

// Endpoint is link layer endpoint that redirects packets to a pair veth endpoint.
//
// +stateify savable
type Endpoint struct {
	peer *Endpoint

	veth *veth

	mu endpointRWMutex `state:"nosave"`
	// +checklocks:mu
	dispatcher stack.NetworkDispatcher
	// linkAddr is the local address of this endpoint.
	//
	// +checklocks:mu
	linkAddr tcpip.LinkAddress
	// +checklocks:mu
	onCloseAction func() `state:"nosave"`
}

// NewPair creates a new veth pair.
func NewPair(mtu, backlogQueueSize uint32) (*Endpoint, *Endpoint) {
	v := &veth{
		backlogQueue: make(chan vethPacket, backlogQueueSize),
		stopCh:       make(chan struct{}),
		mtu:          mtu,
		endpoints: [2]Endpoint{
			{
				linkAddr: tcpip.GetRandMacAddr(),
			},
			{
				linkAddr: tcpip.GetRandMacAddr(),
			},
		},
	}
	a := &v.endpoints[0]
	b := &v.endpoints[1]
	a.peer = b
	b.peer = a
	a.veth = v
	b.veth = v
	v.wg.Add(1)
	go v.worker(v.backlogQueue, v.stopCh)
	return a, b
}

// Close closes e. Further packet injections will return an error, and all
// pending packets are discarded. Close may be called concurrently with
// WritePackets, and blocks until the background worker finishes any in-flight
// InjectInbound delivery, so callers must not hold locks that inbound delivery
// can acquire (such as Stack.mu or BridgeEndpoint.mu).
//
// +checklocksexclude:e.veth.mu
// +checklocksexclude:e.mu
// +checklocksexclude:e.peer.mu
func (e *Endpoint) Close() {
	e.veth.close()
}

// InjectInbound injects an inbound packet. If the endpoint is not attached, the
// packet is not delivered.
//
// +checklocksexclude:e.mu
func (e *Endpoint) InjectInbound(protocol tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) {
	e.mu.RLock()
	d := e.dispatcher
	e.mu.RUnlock()
	if d != nil {
		d.DeliverNetworkPacket(protocol, pkt)
	}
}

// Attach saves the stack network-layer dispatcher for use later when packets
// are injected.
//
// +checklocksexclude:e.mu
func (e *Endpoint) Attach(dispatcher stack.NetworkDispatcher) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.dispatcher = dispatcher
}

// IsAttached implements stack.LinkEndpoint.IsAttached.
//
// +checklocksexclude:e.mu
func (e *Endpoint) IsAttached() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.dispatcher != nil
}

// MTU implements stack.LinkEndpoint.MTU.
//
// +checklocksexclude:e.veth.mu
func (e *Endpoint) MTU() uint32 {
	e.veth.mu.RLock()
	defer e.veth.mu.RUnlock()
	return e.veth.mtu
}

// SetMTU implements stack.LinkEndpoint.SetMTU.
//
// +checklocksexclude:e.veth.mu
func (e *Endpoint) SetMTU(mtu uint32) {
	e.veth.mu.Lock()
	defer e.veth.mu.Unlock()
	e.veth.mtu = mtu
}

// Capabilities implements stack.LinkEndpoint.Capabilities.
func (e *Endpoint) Capabilities() stack.LinkEndpointCapabilities {
	return stack.CapabilityRXChecksumOffload | stack.CapabilitySaveRestore | stack.CapabilityTXChecksumOffload
}

// GSOMaxSize implements stack.GSOEndpoint.
func (*Endpoint) GSOMaxSize() uint32 {
	return tcpip.GVisorGSOMaxSize
}

// SupportedGSO implements stack.GSOEndpoint.
func (e *Endpoint) SupportedGSO() stack.SupportedGSO {
	return stack.GVisorGSOSupported
}

// MaxHeaderLength returns the maximum size of the link layer header. Given it
// doesn't have a header, it just returns 0.
func (*Endpoint) MaxHeaderLength() uint16 {
	return 0
}

// LinkAddress returns the link address of this endpoint.
//
// +checklocksexclude:e.mu
func (e *Endpoint) LinkAddress() tcpip.LinkAddress {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.linkAddr
}

// SetLinkAddress implements stack.LinkEndpoint.SetLinkAddress.
//
// +checklocksexclude:e.mu
func (e *Endpoint) SetLinkAddress(addr tcpip.LinkAddress) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.linkAddr = addr
}

// WritePackets stores outbound packets into the channel.
// Multiple concurrent calls are permitted.
//
// +checklocksexclude:e.veth.mu
func (e *Endpoint) WritePackets(pkts stack.PacketBufferList) (int, tcpip.Error) {
	e.veth.mu.RLock()
	defer e.veth.mu.RUnlock()

	if e.veth.closed {
		return 0, nil
	}

	n := 0
	for _, pkt := range pkts.AsSlice() {
		// In order to properly loop back to the inbound side we must create a
		// fresh packet that only contains the underlying payload with no headers
		// or struct fields set. We must deep clone the payload to avoid
		// two goroutines writing to the same buffer.
		//
		// TODO(b/240580913): Remove this once IP headers use reference counted
		// views instead of raw byte slices.
		payload := pkt.ToBuffer()
		newPkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
			Payload: payload.DeepClone(),
		})
		payload.Release()
		select {
		case (e.veth.backlogQueue) <- vethPacket{
			e:        e.peer,
			protocol: pkt.NetworkProtocolNumber,
			pkt:      newPkt,
		}:
			n++
		default:
			newPkt.DecRef()
			return n, &tcpip.ErrNoBufferSpace{}
		}
	}
	return n, nil
}

// Wait implements stack.LinkEndpoint.Wait. It blocks until close or pause
// exits the worker.
func (e *Endpoint) Wait() {
	e.veth.wg.Wait()
}

// Pause implements stack.PausableLinkEndpoint.Pause.
func (e *Endpoint) Pause() {
	e.veth.pause()
}

// Resume implements stack.PausableLinkEndpoint.Resume.
func (e *Endpoint) Resume() {
	e.veth.resume()
}

// ARPHardwareType implements stack.LinkEndpoint.ARPHardwareType.
func (*Endpoint) ARPHardwareType() header.ARPHardwareType {
	return header.ARPHardwareNone
}

// AddHeader implements stack.LinkEndpoint.AddHeader.
func (e *Endpoint) AddHeader(pkt *stack.PacketBuffer) {}

// ParseHeader implements stack.LinkEndpoint.ParseHeader.
func (e *Endpoint) ParseHeader(pkt *stack.PacketBuffer) bool { return true }

// SetOnCloseAction implements stack.LinkEndpoint.
//
// +checklocksexclude:e.mu
func (e *Endpoint) SetOnCloseAction(action func()) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.onCloseAction = action
}

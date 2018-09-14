// Copyright 2018 Google Inc.
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

package stack_test

import (
	"testing"

	"gvisor.googlesource.com/gvisor/pkg/tcpip"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/buffer"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/link/channel"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/stack"
	"gvisor.googlesource.com/gvisor/pkg/waiter"
)

const (
	fakeTransNumber    tcpip.TransportProtocolNumber = 1
	fakeTransHeaderLen                               = 3
)

// fakeTransportEndpoint is a transport-layer protocol endpoint. It counts
// received packets; the counts of all endpoints are aggregated in the protocol
// descriptor.
//
// Headers of this protocol are fakeTransHeaderLen bytes, but we currently don't
// use it.
type fakeTransportEndpoint struct {
	id       stack.TransportEndpointID
	stack    *stack.Stack
	netProto tcpip.NetworkProtocolNumber
	proto    *fakeTransportProtocol
	peerAddr tcpip.Address
	route    stack.Route
}

func newFakeTransportEndpoint(stack *stack.Stack, proto *fakeTransportProtocol, netProto tcpip.NetworkProtocolNumber) tcpip.Endpoint {
	return &fakeTransportEndpoint{stack: stack, netProto: netProto, proto: proto}
}

func (f *fakeTransportEndpoint) Close() {
	f.route.Release()
}

func (*fakeTransportEndpoint) Readiness(mask waiter.EventMask) waiter.EventMask {
	return mask
}

func (*fakeTransportEndpoint) Read(*tcpip.FullAddress) (buffer.View, tcpip.ControlMessages, *tcpip.Error) {
	return buffer.View{}, tcpip.ControlMessages{}, nil
}

func (f *fakeTransportEndpoint) Write(p tcpip.Payload, opts tcpip.WriteOptions) (uintptr, *tcpip.Error) {
	if len(f.route.RemoteAddress) == 0 {
		return 0, tcpip.ErrNoRoute
	}

	hdr := buffer.NewPrependable(int(f.route.MaxHeaderLength()))
	v, err := p.Get(p.Size())
	if err != nil {
		return 0, err
	}
	if err := f.route.WritePacket(hdr, buffer.View(v).ToVectorisedView(), fakeTransNumber, 123); err != nil {
		return 0, err
	}

	return uintptr(len(v)), nil
}

func (f *fakeTransportEndpoint) Peek([][]byte) (uintptr, tcpip.ControlMessages, *tcpip.Error) {
	return 0, tcpip.ControlMessages{}, nil
}

// SetSockOpt sets a socket option. Currently not supported.
func (*fakeTransportEndpoint) SetSockOpt(interface{}) *tcpip.Error {
	return tcpip.ErrInvalidEndpointState
}

// GetSockOpt implements tcpip.Endpoint.GetSockOpt.
func (*fakeTransportEndpoint) GetSockOpt(opt interface{}) *tcpip.Error {
	switch opt.(type) {
	case tcpip.ErrorOption:
		return nil
	}
	return tcpip.ErrInvalidEndpointState
}

func (f *fakeTransportEndpoint) Connect(addr tcpip.FullAddress) *tcpip.Error {
	f.peerAddr = addr.Addr

	// Find the route.
	r, err := f.stack.FindRoute(addr.NIC, "", addr.Addr, fakeNetNumber)
	if err != nil {
		return tcpip.ErrNoRoute
	}
	defer r.Release()

	// Try to register so that we can start receiving packets.
	f.id.RemoteAddress = addr.Addr
	err = f.stack.RegisterTransportEndpoint(0, []tcpip.NetworkProtocolNumber{fakeNetNumber}, fakeTransNumber, f.id, f)
	if err != nil {
		return err
	}

	f.route = r.Clone()

	return nil
}

func (f *fakeTransportEndpoint) ConnectEndpoint(e tcpip.Endpoint) *tcpip.Error {
	return nil
}

func (*fakeTransportEndpoint) Shutdown(tcpip.ShutdownFlags) *tcpip.Error {
	return nil
}

func (*fakeTransportEndpoint) Reset() {
}

func (*fakeTransportEndpoint) Listen(int) *tcpip.Error {
	return nil
}

func (*fakeTransportEndpoint) Accept() (tcpip.Endpoint, *waiter.Queue, *tcpip.Error) {
	return nil, nil, nil
}

func (*fakeTransportEndpoint) Bind(_ tcpip.FullAddress, commit func() *tcpip.Error) *tcpip.Error {
	return commit()
}

func (*fakeTransportEndpoint) GetLocalAddress() (tcpip.FullAddress, *tcpip.Error) {
	return tcpip.FullAddress{}, nil
}

func (*fakeTransportEndpoint) GetRemoteAddress() (tcpip.FullAddress, *tcpip.Error) {
	return tcpip.FullAddress{}, nil
}

func (f *fakeTransportEndpoint) HandlePacket(*stack.Route, stack.TransportEndpointID, buffer.VectorisedView) {
	// Increment the number of received packets.
	f.proto.packetCount++
}

func (f *fakeTransportEndpoint) HandleControlPacket(stack.TransportEndpointID, stack.ControlType, uint32, buffer.VectorisedView) {
	// Increment the number of received control packets.
	f.proto.controlCount++
}

type fakeTransportGoodOption bool

type fakeTransportBadOption bool

type fakeTransportInvalidValueOption int

type fakeTransportProtocolOptions struct {
	good bool
}

// fakeTransportProtocol is a transport-layer protocol descriptor. It
// aggregates the number of packets received via endpoints of this protocol.
type fakeTransportProtocol struct {
	packetCount  int
	controlCount int
	opts         fakeTransportProtocolOptions
}

func (*fakeTransportProtocol) Number() tcpip.TransportProtocolNumber {
	return fakeTransNumber
}

func (f *fakeTransportProtocol) NewEndpoint(stack *stack.Stack, netProto tcpip.NetworkProtocolNumber, _ *waiter.Queue) (tcpip.Endpoint, *tcpip.Error) {
	return newFakeTransportEndpoint(stack, f, netProto), nil
}

func (*fakeTransportProtocol) MinimumPacketSize() int {
	return fakeTransHeaderLen
}

func (*fakeTransportProtocol) ParsePorts(buffer.View) (src, dst uint16, err *tcpip.Error) {
	return 0, 0, nil
}

func (*fakeTransportProtocol) HandleUnknownDestinationPacket(*stack.Route, stack.TransportEndpointID, buffer.VectorisedView) bool {
	return true
}

func (f *fakeTransportProtocol) SetOption(option interface{}) *tcpip.Error {
	switch v := option.(type) {
	case fakeTransportGoodOption:
		f.opts.good = bool(v)
		return nil
	case fakeTransportInvalidValueOption:
		return tcpip.ErrInvalidOptionValue
	default:
		return tcpip.ErrUnknownProtocolOption
	}
}

func (f *fakeTransportProtocol) Option(option interface{}) *tcpip.Error {
	switch v := option.(type) {
	case *fakeTransportGoodOption:
		*v = fakeTransportGoodOption(f.opts.good)
		return nil
	default:
		return tcpip.ErrUnknownProtocolOption
	}
}

func TestTransportReceive(t *testing.T) {
	id, linkEP := channel.New(10, defaultMTU, "")
	s := stack.New([]string{"fakeNet"}, []string{"fakeTrans"}, stack.Options{})
	if err := s.CreateNIC(1, id); err != nil {
		t.Fatalf("CreateNIC failed: %v", err)
	}

	s.SetRouteTable([]tcpip.Route{{"\x00", "\x00", "\x00", 1}})

	if err := s.AddAddress(1, fakeNetNumber, "\x01"); err != nil {
		t.Fatalf("AddAddress failed: %v", err)
	}

	// Create endpoint and connect to remote address.
	wq := waiter.Queue{}
	ep, err := s.NewEndpoint(fakeTransNumber, fakeNetNumber, &wq)
	if err != nil {
		t.Fatalf("NewEndpoint failed: %v", err)
	}

	if err := ep.Connect(tcpip.FullAddress{0, "\x02", 0}); err != nil {
		t.Fatalf("Connect failed: %v", err)
	}

	fakeTrans := s.TransportProtocolInstance(fakeTransNumber).(*fakeTransportProtocol)

	// Create buffer that will hold the packet.
	buf := buffer.NewView(30)

	// Make sure packet with wrong protocol is not delivered.
	buf[0] = 1
	buf[2] = 0
	linkEP.Inject(fakeNetNumber, buf.ToVectorisedView())
	if fakeTrans.packetCount != 0 {
		t.Errorf("packetCount = %d, want %d", fakeTrans.packetCount, 0)
	}

	// Make sure packet from the wrong source is not delivered.
	buf[0] = 1
	buf[1] = 3
	buf[2] = byte(fakeTransNumber)
	linkEP.Inject(fakeNetNumber, buf.ToVectorisedView())
	if fakeTrans.packetCount != 0 {
		t.Errorf("packetCount = %d, want %d", fakeTrans.packetCount, 0)
	}

	// Make sure packet is delivered.
	buf[0] = 1
	buf[1] = 2
	buf[2] = byte(fakeTransNumber)
	linkEP.Inject(fakeNetNumber, buf.ToVectorisedView())
	if fakeTrans.packetCount != 1 {
		t.Errorf("packetCount = %d, want %d", fakeTrans.packetCount, 1)
	}
}

func TestTransportControlReceive(t *testing.T) {
	id, linkEP := channel.New(10, defaultMTU, "")
	s := stack.New([]string{"fakeNet"}, []string{"fakeTrans"}, stack.Options{})
	if err := s.CreateNIC(1, id); err != nil {
		t.Fatalf("CreateNIC failed: %v", err)
	}

	s.SetRouteTable([]tcpip.Route{{"\x00", "\x00", "\x00", 1}})

	if err := s.AddAddress(1, fakeNetNumber, "\x01"); err != nil {
		t.Fatalf("AddAddress failed: %v", err)
	}

	// Create endpoint and connect to remote address.
	wq := waiter.Queue{}
	ep, err := s.NewEndpoint(fakeTransNumber, fakeNetNumber, &wq)
	if err != nil {
		t.Fatalf("NewEndpoint failed: %v", err)
	}

	if err := ep.Connect(tcpip.FullAddress{0, "\x02", 0}); err != nil {
		t.Fatalf("Connect failed: %v", err)
	}

	fakeTrans := s.TransportProtocolInstance(fakeTransNumber).(*fakeTransportProtocol)

	// Create buffer that will hold the control packet.
	buf := buffer.NewView(2*fakeNetHeaderLen + 30)

	// Outer packet contains the control protocol number.
	buf[0] = 1
	buf[1] = 0xfe
	buf[2] = uint8(fakeControlProtocol)

	// Make sure packet with wrong protocol is not delivered.
	buf[fakeNetHeaderLen+0] = 0
	buf[fakeNetHeaderLen+1] = 1
	buf[fakeNetHeaderLen+2] = 0
	linkEP.Inject(fakeNetNumber, buf.ToVectorisedView())
	if fakeTrans.controlCount != 0 {
		t.Errorf("controlCount = %d, want %d", fakeTrans.controlCount, 0)
	}

	// Make sure packet from the wrong source is not delivered.
	buf[fakeNetHeaderLen+0] = 3
	buf[fakeNetHeaderLen+1] = 1
	buf[fakeNetHeaderLen+2] = byte(fakeTransNumber)
	linkEP.Inject(fakeNetNumber, buf.ToVectorisedView())
	if fakeTrans.controlCount != 0 {
		t.Errorf("controlCount = %d, want %d", fakeTrans.controlCount, 0)
	}

	// Make sure packet is delivered.
	buf[fakeNetHeaderLen+0] = 2
	buf[fakeNetHeaderLen+1] = 1
	buf[fakeNetHeaderLen+2] = byte(fakeTransNumber)
	linkEP.Inject(fakeNetNumber, buf.ToVectorisedView())
	if fakeTrans.controlCount != 1 {
		t.Errorf("controlCount = %d, want %d", fakeTrans.controlCount, 1)
	}
}

func TestTransportSend(t *testing.T) {
	id, _ := channel.New(10, defaultMTU, "")
	s := stack.New([]string{"fakeNet"}, []string{"fakeTrans"}, stack.Options{})
	if err := s.CreateNIC(1, id); err != nil {
		t.Fatalf("CreateNIC failed: %v", err)
	}

	if err := s.AddAddress(1, fakeNetNumber, "\x01"); err != nil {
		t.Fatalf("AddAddress failed: %v", err)
	}

	s.SetRouteTable([]tcpip.Route{{"\x00", "\x00", "\x00", 1}})

	// Create endpoint and bind it.
	wq := waiter.Queue{}
	ep, err := s.NewEndpoint(fakeTransNumber, fakeNetNumber, &wq)
	if err != nil {
		t.Fatalf("NewEndpoint failed: %v", err)
	}

	if err := ep.Connect(tcpip.FullAddress{0, "\x02", 0}); err != nil {
		t.Fatalf("Connect failed: %v", err)
	}

	// Create buffer that will hold the payload.
	view := buffer.NewView(30)
	_, err = ep.Write(tcpip.SlicePayload(view), tcpip.WriteOptions{})
	if err != nil {
		t.Fatalf("write failed: %v", err)
	}

	fakeNet := s.NetworkProtocolInstance(fakeNetNumber).(*fakeNetworkProtocol)

	if fakeNet.sendPacketCount[2] != 1 {
		t.Errorf("sendPacketCount = %d, want %d", fakeNet.sendPacketCount[2], 1)
	}
}

func TestTransportOptions(t *testing.T) {
	s := stack.New([]string{"fakeNet"}, []string{"fakeTrans"}, stack.Options{})

	// Try an unsupported transport protocol.
	if err := s.SetTransportProtocolOption(tcpip.TransportProtocolNumber(99999), fakeTransportGoodOption(false)); err != tcpip.ErrUnknownProtocol {
		t.Fatalf("SetTransportProtocolOption(fakeTrans2, blah, false) = %v, want = tcpip.ErrUnknownProtocol", err)
	}

	testCases := []struct {
		option   interface{}
		wantErr  *tcpip.Error
		verifier func(t *testing.T, p stack.TransportProtocol)
	}{
		{fakeTransportGoodOption(true), nil, func(t *testing.T, p stack.TransportProtocol) {
			t.Helper()
			fakeTrans := p.(*fakeTransportProtocol)
			if fakeTrans.opts.good != true {
				t.Fatalf("fakeTrans.opts.good = false, want = true")
			}
			var v fakeTransportGoodOption
			if err := s.TransportProtocolOption(fakeTransNumber, &v); err != nil {
				t.Fatalf("s.TransportProtocolOption(fakeTransNumber, &v) = %v, want = nil, where v is option %T", v, err)
			}
			if v != true {
				t.Fatalf("s.TransportProtocolOption(fakeTransNumber, &v) returned v = %v, want = true", v)
			}

		}},
		{fakeTransportBadOption(true), tcpip.ErrUnknownProtocolOption, nil},
		{fakeTransportInvalidValueOption(1), tcpip.ErrInvalidOptionValue, nil},
	}
	for _, tc := range testCases {
		if got := s.SetTransportProtocolOption(fakeTransNumber, tc.option); got != tc.wantErr {
			t.Errorf("s.SetTransportProtocolOption(fakeTrans, %v) = %v, want = %v", tc.option, got, tc.wantErr)
		}
		if tc.verifier != nil {
			tc.verifier(t, s.TransportProtocolInstance(fakeTransNumber))
		}
	}
}

func init() {
	stack.RegisterTransportProtocolFactory("fakeTrans", func() stack.TransportProtocol {
		return &fakeTransportProtocol{}
	})
}

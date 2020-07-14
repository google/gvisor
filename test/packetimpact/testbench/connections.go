// Copyright 2020 The gVisor Authors.
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

// Package testbench has utilities to send and receive packets and also command
// the DUT to run POSIX functions.
package testbench

import (
	"fmt"
	"math/rand"
	"net"
	"testing"
	"time"

	"github.com/mohae/deepcopy"
	"go.uber.org/multierr"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/seqnum"
)

func portFromSockaddr(sa unix.Sockaddr) (uint16, error) {
	switch sa := sa.(type) {
	case *unix.SockaddrInet4:
		return uint16(sa.Port), nil
	case *unix.SockaddrInet6:
		return uint16(sa.Port), nil
	}
	return 0, fmt.Errorf("sockaddr type %T does not contain port", sa)
}

// pickPort makes a new socket and returns the socket FD and port. The domain should be AF_INET or AF_INET6. The caller must close the FD when done with
// the port if there is no error.
func pickPort(domain, typ int) (fd int, port uint16, err error) {
	fd, err = unix.Socket(domain, typ, 0)
	if err != nil {
		return -1, 0, fmt.Errorf("creating socket: %w", err)
	}
	defer func() {
		if err != nil {
			if cerr := unix.Close(fd); cerr != nil {
				err = multierr.Append(err, fmt.Errorf("failed to close socket %d: %w", fd, cerr))
			}
		}
	}()
	var sa unix.Sockaddr
	switch domain {
	case unix.AF_INET:
		var sa4 unix.SockaddrInet4
		copy(sa4.Addr[:], net.ParseIP(LocalIPv4).To4())
		sa = &sa4
	case unix.AF_INET6:
		sa6 := unix.SockaddrInet6{ZoneId: uint32(LocalInterfaceID)}
		copy(sa6.Addr[:], net.ParseIP(LocalIPv6).To16())
		sa = &sa6
	default:
		return -1, 0, fmt.Errorf("invalid domain %d, it should be one of unix.AF_INET or unix.AF_INET6", domain)
	}
	if err = unix.Bind(fd, sa); err != nil {
		return -1, 0, fmt.Errorf("binding to %+v: %w", sa, err)
	}
	sa, err = unix.Getsockname(fd)
	if err != nil {
		return -1, 0, fmt.Errorf("Getsocketname(%d): %w", fd, err)
	}
	port, err = portFromSockaddr(sa)
	if err != nil {
		return -1, 0, fmt.Errorf("extracting port from socket address %+v: %w", sa, err)
	}
	return fd, port, nil
}

// layerState stores the state of a layer of a connection.
type layerState interface {
	// outgoing returns an outgoing layer to be sent in a frame. It should not
	// update layerState, that is done in layerState.sent.
	outgoing() Layer

	// incoming creates an expected Layer for comparing against a received Layer.
	// Because the expectation can depend on values in the received Layer, it is
	// an input to incoming. For example, the ACK number needs to be checked in a
	// TCP packet but only if the ACK flag is set in the received packet. It
	// should not update layerState, that is done in layerState.received. The
	// caller takes ownership of the returned Layer.
	incoming(received Layer) Layer

	// sent updates the layerState based on the Layer that was sent. The input is
	// a Layer with all prev and next pointers populated so that the entire frame
	// as it was sent is available.
	sent(sent Layer) error

	// received updates the layerState based on a Layer that is receieved. The
	// input is a Layer with all prev and next pointers populated so that the
	// entire frame as it was receieved is available.
	received(received Layer) error

	// close frees associated resources held by the LayerState.
	close() error
}

// etherState maintains state about an Ethernet connection.
type etherState struct {
	out, in Ether
}

var _ layerState = (*etherState)(nil)

// newEtherState creates a new etherState.
func newEtherState(out, in Ether) (*etherState, error) {
	lMAC, err := tcpip.ParseMACAddress(LocalMAC)
	if err != nil {
		return nil, fmt.Errorf("parsing local MAC: %q: %w", LocalMAC, err)
	}

	rMAC, err := tcpip.ParseMACAddress(RemoteMAC)
	if err != nil {
		return nil, fmt.Errorf("parsing remote MAC: %q: %w", RemoteMAC, err)
	}
	s := etherState{
		out: Ether{SrcAddr: &lMAC, DstAddr: &rMAC},
		in:  Ether{SrcAddr: &rMAC, DstAddr: &lMAC},
	}
	if err := s.out.merge(&out); err != nil {
		return nil, err
	}
	if err := s.in.merge(&in); err != nil {
		return nil, err
	}
	return &s, nil
}

func (s *etherState) outgoing() Layer {
	return deepcopy.Copy(&s.out).(Layer)
}

// incoming implements layerState.incoming.
func (s *etherState) incoming(Layer) Layer {
	return deepcopy.Copy(&s.in).(Layer)
}

func (*etherState) sent(Layer) error {
	return nil
}

func (*etherState) received(Layer) error {
	return nil
}

func (*etherState) close() error {
	return nil
}

// ipv4State maintains state about an IPv4 connection.
type ipv4State struct {
	out, in IPv4
}

var _ layerState = (*ipv4State)(nil)

// newIPv4State creates a new ipv4State.
func newIPv4State(out, in IPv4) (*ipv4State, error) {
	lIP := tcpip.Address(net.ParseIP(LocalIPv4).To4())
	rIP := tcpip.Address(net.ParseIP(RemoteIPv4).To4())
	s := ipv4State{
		out: IPv4{SrcAddr: &lIP, DstAddr: &rIP},
		in:  IPv4{SrcAddr: &rIP, DstAddr: &lIP},
	}
	if err := s.out.merge(&out); err != nil {
		return nil, err
	}
	if err := s.in.merge(&in); err != nil {
		return nil, err
	}
	return &s, nil
}

func (s *ipv4State) outgoing() Layer {
	return deepcopy.Copy(&s.out).(Layer)
}

// incoming implements layerState.incoming.
func (s *ipv4State) incoming(Layer) Layer {
	return deepcopy.Copy(&s.in).(Layer)
}

func (*ipv4State) sent(Layer) error {
	return nil
}

func (*ipv4State) received(Layer) error {
	return nil
}

func (*ipv4State) close() error {
	return nil
}

// ipv6State maintains state about an IPv6 connection.
type ipv6State struct {
	out, in IPv6
}

var _ layerState = (*ipv6State)(nil)

// newIPv6State creates a new ipv6State.
func newIPv6State(out, in IPv6) (*ipv6State, error) {
	lIP := tcpip.Address(net.ParseIP(LocalIPv6).To16())
	rIP := tcpip.Address(net.ParseIP(RemoteIPv6).To16())
	s := ipv6State{
		out: IPv6{SrcAddr: &lIP, DstAddr: &rIP},
		in:  IPv6{SrcAddr: &rIP, DstAddr: &lIP},
	}
	if err := s.out.merge(&out); err != nil {
		return nil, err
	}
	if err := s.in.merge(&in); err != nil {
		return nil, err
	}
	return &s, nil
}

// outgoing returns an outgoing layer to be sent in a frame.
func (s *ipv6State) outgoing() Layer {
	return deepcopy.Copy(&s.out).(Layer)
}

func (s *ipv6State) incoming(Layer) Layer {
	return deepcopy.Copy(&s.in).(Layer)
}

func (s *ipv6State) sent(Layer) error {
	// Nothing to do.
	return nil
}

func (s *ipv6State) received(Layer) error {
	// Nothing to do.
	return nil
}

// close cleans up any resources held.
func (s *ipv6State) close() error {
	return nil
}

// tcpState maintains state about a TCP connection.
type tcpState struct {
	out, in                   TCP
	localSeqNum, remoteSeqNum *seqnum.Value
	synAck                    *TCP
	portPickerFD              int
	finSent                   bool
}

var _ layerState = (*tcpState)(nil)

// SeqNumValue is a helper routine that allocates a new seqnum.Value value to
// store v and returns a pointer to it.
func SeqNumValue(v seqnum.Value) *seqnum.Value {
	return &v
}

// newTCPState creates a new TCPState.
func newTCPState(domain int, out, in TCP) (*tcpState, error) {
	portPickerFD, localPort, err := pickPort(domain, unix.SOCK_STREAM)
	if err != nil {
		return nil, err
	}
	s := tcpState{
		out:          TCP{SrcPort: &localPort},
		in:           TCP{DstPort: &localPort},
		localSeqNum:  SeqNumValue(seqnum.Value(rand.Uint32())),
		portPickerFD: portPickerFD,
		finSent:      false,
	}
	if err := s.out.merge(&out); err != nil {
		return nil, err
	}
	if err := s.in.merge(&in); err != nil {
		return nil, err
	}
	return &s, nil
}

func (s *tcpState) outgoing() Layer {
	newOutgoing := deepcopy.Copy(s.out).(TCP)
	if s.localSeqNum != nil {
		newOutgoing.SeqNum = Uint32(uint32(*s.localSeqNum))
	}
	if s.remoteSeqNum != nil {
		newOutgoing.AckNum = Uint32(uint32(*s.remoteSeqNum))
	}
	return &newOutgoing
}

// incoming implements layerState.incoming.
func (s *tcpState) incoming(received Layer) Layer {
	tcpReceived, ok := received.(*TCP)
	if !ok {
		return nil
	}
	newIn := deepcopy.Copy(s.in).(TCP)
	if s.remoteSeqNum != nil {
		newIn.SeqNum = Uint32(uint32(*s.remoteSeqNum))
	}
	if s.localSeqNum != nil && (*tcpReceived.Flags&header.TCPFlagAck) != 0 {
		// The caller didn't specify an AckNum so we'll expect the calculated one,
		// but only if the ACK flag is set because the AckNum is not valid in a
		// header if ACK is not set.
		newIn.AckNum = Uint32(uint32(*s.localSeqNum))
	}
	return &newIn
}

func (s *tcpState) sent(sent Layer) error {
	tcp, ok := sent.(*TCP)
	if !ok {
		return fmt.Errorf("can't update tcpState with %T Layer", sent)
	}
	if !s.finSent {
		// update localSeqNum by the payload only when FIN is not yet sent by us
		for current := tcp.next(); current != nil; current = current.next() {
			s.localSeqNum.UpdateForward(seqnum.Size(current.length()))
		}
	}
	if tcp.Flags != nil && *tcp.Flags&(header.TCPFlagSyn|header.TCPFlagFin) != 0 {
		s.localSeqNum.UpdateForward(1)
	}
	if *tcp.Flags&(header.TCPFlagFin) != 0 {
		s.finSent = true
	}
	return nil
}

func (s *tcpState) received(l Layer) error {
	tcp, ok := l.(*TCP)
	if !ok {
		return fmt.Errorf("can't update tcpState with %T Layer", l)
	}
	s.remoteSeqNum = SeqNumValue(seqnum.Value(*tcp.SeqNum))
	if *tcp.Flags&(header.TCPFlagSyn|header.TCPFlagFin) != 0 {
		s.remoteSeqNum.UpdateForward(1)
	}
	for current := tcp.next(); current != nil; current = current.next() {
		s.remoteSeqNum.UpdateForward(seqnum.Size(current.length()))
	}
	return nil
}

// close frees the port associated with this connection.
func (s *tcpState) close() error {
	if err := unix.Close(s.portPickerFD); err != nil {
		return err
	}
	s.portPickerFD = -1
	return nil
}

// udpState maintains state about a UDP connection.
type udpState struct {
	out, in      UDP
	portPickerFD int
}

var _ layerState = (*udpState)(nil)

// newUDPState creates a new udpState.
func newUDPState(domain int, out, in UDP) (*udpState, error) {
	portPickerFD, localPort, err := pickPort(domain, unix.SOCK_DGRAM)
	if err != nil {
		return nil, fmt.Errorf("picking port: %w", err)
	}
	s := udpState{
		out:          UDP{SrcPort: &localPort},
		in:           UDP{DstPort: &localPort},
		portPickerFD: portPickerFD,
	}
	if err := s.out.merge(&out); err != nil {
		return nil, err
	}
	if err := s.in.merge(&in); err != nil {
		return nil, err
	}
	return &s, nil
}

func (s *udpState) outgoing() Layer {
	return deepcopy.Copy(&s.out).(Layer)
}

// incoming implements layerState.incoming.
func (s *udpState) incoming(Layer) Layer {
	return deepcopy.Copy(&s.in).(Layer)
}

func (*udpState) sent(l Layer) error {
	return nil
}

func (*udpState) received(l Layer) error {
	return nil
}

// close frees the port associated with this connection.
func (s *udpState) close() error {
	if err := unix.Close(s.portPickerFD); err != nil {
		return err
	}
	s.portPickerFD = -1
	return nil
}

// Connection holds a collection of layer states for maintaining a connection
// along with sockets for sniffer and injecting packets.
type Connection struct {
	layerStates []layerState
	injector    Injector
	sniffer     Sniffer
	t           *testing.T
}

// Returns the default incoming frame against which to match. If received is
// longer than layerStates then that may still count as a match. The reverse is
// never a match and nil is returned.
func (conn *Connection) incoming(received Layers) Layers {
	if len(received) < len(conn.layerStates) {
		return nil
	}
	in := Layers{}
	for i, s := range conn.layerStates {
		toMatch := s.incoming(received[i])
		if toMatch == nil {
			return nil
		}
		in = append(in, toMatch)
	}
	return in
}

func (conn *Connection) match(override, received Layers) bool {
	toMatch := conn.incoming(received)
	if toMatch == nil {
		return false // Not enough layers in gotLayers for matching.
	}
	if err := toMatch.merge(override); err != nil {
		return false // Failing to merge is not matching.
	}
	return toMatch.match(received)
}

// Close frees associated resources held by the Connection.
func (conn *Connection) Close() {
	errs := multierr.Combine(conn.sniffer.close(), conn.injector.close())
	for _, s := range conn.layerStates {
		if err := s.close(); err != nil {
			errs = multierr.Append(errs, fmt.Errorf("unable to close %+v: %s", s, err))
		}
	}
	if errs != nil {
		conn.t.Fatalf("unable to close %+v: %s", conn, errs)
	}
}

// CreateFrame builds a frame for the connection with defaults overriden
// from the innermost layer out, and additionalLayers added after it.
//
// Note that overrideLayers can have a length that is less than the number
// of layers in this connection, and in such cases the innermost layers are
// overriden first. As an example, valid values of overrideLayers for a TCP-
// over-IPv4-over-Ethernet connection are: nil, [TCP], [IPv4, TCP], and
// [Ethernet, IPv4, TCP].
func (conn *Connection) CreateFrame(overrideLayers Layers, additionalLayers ...Layer) Layers {
	var layersToSend Layers
	for i, s := range conn.layerStates {
		layer := s.outgoing()
		// overrideLayers and conn.layerStates have their tails aligned, so
		// to find the index we move backwards by the distance i is to the
		// end.
		if j := len(overrideLayers) - (len(conn.layerStates) - i); j >= 0 {
			if err := layer.merge(overrideLayers[j]); err != nil {
				conn.t.Fatalf("can't merge %+v into %+v: %s", layer, overrideLayers[j], err)
			}
		}
		layersToSend = append(layersToSend, layer)
	}
	layersToSend = append(layersToSend, additionalLayers...)
	return layersToSend
}

// SendFrameStateless sends a frame without updating any of the layer states.
//
// This method is useful for sending out-of-band control messages such as
// ICMP packets, where it would not make sense to update the transport layer's
// state using the ICMP header.
func (conn *Connection) SendFrameStateless(frame Layers) {
	outBytes, err := frame.ToBytes()
	if err != nil {
		conn.t.Fatalf("can't build outgoing packet: %s", err)
	}
	conn.injector.Send(outBytes)
}

// SendFrame sends a frame on the wire and updates the state of all layers.
func (conn *Connection) SendFrame(frame Layers) {
	outBytes, err := frame.ToBytes()
	if err != nil {
		conn.t.Fatalf("can't build outgoing packet: %s", err)
	}
	conn.injector.Send(outBytes)

	// frame might have nil values where the caller wanted to use default values.
	// sentFrame will have no nil values in it because it comes from parsing the
	// bytes that were actually sent.
	sentFrame := parse(parseEther, outBytes)
	// Update the state of each layer based on what was sent.
	for i, s := range conn.layerStates {
		if err := s.sent(sentFrame[i]); err != nil {
			conn.t.Fatalf("Unable to update the state of %+v with %s: %s", s, sentFrame[i], err)
		}
	}
}

// send sends a packet, possibly with layers of this connection overridden and
// additional layers added.
//
// Types defined with Connection as the underlying type should expose
// type-safe versions of this method.
func (conn *Connection) send(overrideLayers Layers, additionalLayers ...Layer) {
	conn.SendFrame(conn.CreateFrame(overrideLayers, additionalLayers...))
}

// recvFrame gets the next successfully parsed frame (of type Layers) within the
// timeout provided. If no parsable frame arrives before the timeout, it returns
// nil.
func (conn *Connection) recvFrame(timeout time.Duration) Layers {
	if timeout <= 0 {
		return nil
	}
	b := conn.sniffer.Recv(timeout)
	if b == nil {
		return nil
	}
	return parse(parseEther, b)
}

// layersError stores the Layers that we got and the Layers that we wanted to
// match.
type layersError struct {
	got, want Layers
}

func (e *layersError) Error() string {
	return e.got.diff(e.want)
}

// Expect expects a frame with the final layerStates layer matching the
// provided Layer within the timeout specified. If it doesn't arrive in time,
// an error is returned.
func (conn *Connection) Expect(layer Layer, timeout time.Duration) (Layer, error) {
	// Make a frame that will ignore all but the final layer.
	layers := make([]Layer, len(conn.layerStates))
	layers[len(layers)-1] = layer

	gotFrame, err := conn.ExpectFrame(layers, timeout)
	if err != nil {
		return nil, err
	}
	if len(conn.layerStates)-1 < len(gotFrame) {
		return gotFrame[len(conn.layerStates)-1], nil
	}
	conn.t.Fatal("the received frame should be at least as long as the expected layers")
	panic("unreachable")
}

// ExpectFrame expects a frame that matches the provided Layers within the
// timeout specified. If one arrives in time, the Layers is returned without an
// error. If it doesn't arrive in time, it returns nil and error is non-nil.
func (conn *Connection) ExpectFrame(layers Layers, timeout time.Duration) (Layers, error) {
	deadline := time.Now().Add(timeout)
	var errs error
	for {
		var gotLayers Layers
		if timeout = time.Until(deadline); timeout > 0 {
			gotLayers = conn.recvFrame(timeout)
		}
		if gotLayers == nil {
			if errs == nil {
				return nil, fmt.Errorf("got no frames matching %v during %s", layers, timeout)
			}
			return nil, fmt.Errorf("got no frames matching %v during %s: got %w", layers, timeout, errs)
		}
		if conn.match(layers, gotLayers) {
			for i, s := range conn.layerStates {
				if err := s.received(gotLayers[i]); err != nil {
					conn.t.Fatal(err)
				}
			}
			return gotLayers, nil
		}
		errs = multierr.Combine(errs, &layersError{got: gotLayers, want: conn.incoming(gotLayers)})
	}
}

// Drain drains the sniffer's receive buffer by receiving packets until there's
// nothing else to receive.
func (conn *Connection) Drain() {
	conn.sniffer.Drain()
}

// TCPIPv4 maintains the state for all the layers in a TCP/IPv4 connection.
type TCPIPv4 Connection

// NewTCPIPv4 creates a new TCPIPv4 connection with reasonable defaults.
func NewTCPIPv4(t *testing.T, outgoingTCP, incomingTCP TCP) TCPIPv4 {
	etherState, err := newEtherState(Ether{}, Ether{})
	if err != nil {
		t.Fatalf("can't make etherState: %s", err)
	}
	ipv4State, err := newIPv4State(IPv4{}, IPv4{})
	if err != nil {
		t.Fatalf("can't make ipv4State: %s", err)
	}
	tcpState, err := newTCPState(unix.AF_INET, outgoingTCP, incomingTCP)
	if err != nil {
		t.Fatalf("can't make tcpState: %s", err)
	}
	injector, err := NewInjector(t)
	if err != nil {
		t.Fatalf("can't make injector: %s", err)
	}
	sniffer, err := NewSniffer(t)
	if err != nil {
		t.Fatalf("can't make sniffer: %s", err)
	}

	return TCPIPv4{
		layerStates: []layerState{etherState, ipv4State, tcpState},
		injector:    injector,
		sniffer:     sniffer,
		t:           t,
	}
}

// Connect performs a TCP 3-way handshake. The input Connection should have a
// final TCP Layer.
func (conn *TCPIPv4) Connect() {
	conn.t.Helper()

	// Send the SYN.
	conn.Send(TCP{Flags: Uint8(header.TCPFlagSyn)})

	// Wait for the SYN-ACK.
	synAck, err := conn.Expect(TCP{Flags: Uint8(header.TCPFlagSyn | header.TCPFlagAck)}, time.Second)
	if err != nil {
		conn.t.Fatalf("didn't get synack during handshake: %s", err)
	}
	conn.layerStates[len(conn.layerStates)-1].(*tcpState).synAck = synAck

	// Send an ACK.
	conn.Send(TCP{Flags: Uint8(header.TCPFlagAck)})
}

// ConnectWithOptions performs a TCP 3-way handshake with given TCP options.
// The input Connection should have a final TCP Layer.
func (conn *TCPIPv4) ConnectWithOptions(options []byte) {
	conn.t.Helper()

	// Send the SYN.
	conn.Send(TCP{Flags: Uint8(header.TCPFlagSyn), Options: options})

	// Wait for the SYN-ACK.
	synAck, err := conn.Expect(TCP{Flags: Uint8(header.TCPFlagSyn | header.TCPFlagAck)}, time.Second)
	if err != nil {
		conn.t.Fatalf("didn't get synack during handshake: %s", err)
	}
	conn.layerStates[len(conn.layerStates)-1].(*tcpState).synAck = synAck

	// Send an ACK.
	conn.Send(TCP{Flags: Uint8(header.TCPFlagAck)})
}

// ExpectData is a convenient method that expects a Layer and the Layer after
// it. If it doens't arrive in time, it returns nil.
func (conn *TCPIPv4) ExpectData(tcp *TCP, payload *Payload, timeout time.Duration) (Layers, error) {
	expected := make([]Layer, len(conn.layerStates))
	expected[len(expected)-1] = tcp
	if payload != nil {
		expected = append(expected, payload)
	}
	return (*Connection)(conn).ExpectFrame(expected, timeout)
}

// ExpectNextData attempts to receive the next incoming segment for the
// connection and expects that to match the given layers.
//
// It differs from ExpectData() in that here we are only interested in the next
// received segment, while ExpectData() can receive multiple segments for the
// connection until there is a match with given layers or a timeout.
func (conn *TCPIPv4) ExpectNextData(tcp *TCP, payload *Payload, timeout time.Duration) (Layers, error) {
	// Receive the first incoming TCP segment for this connection.
	got, err := conn.ExpectData(&TCP{}, nil, timeout)
	if err != nil {
		return nil, err
	}

	expected := make([]Layer, len(conn.layerStates))
	expected[len(expected)-1] = tcp
	if payload != nil {
		expected = append(expected, payload)
		tcp.SeqNum = Uint32(uint32(*conn.RemoteSeqNum()) - uint32(payload.Length()))
	}
	if !(*Connection)(conn).match(expected, got) {
		return nil, fmt.Errorf("next frame is not matching %s during %s: got %s", expected, timeout, got)
	}
	return got, nil
}

// Send a packet with reasonable defaults. Potentially override the TCP layer in
// the connection with the provided layer and add additionLayers.
func (conn *TCPIPv4) Send(tcp TCP, additionalLayers ...Layer) {
	(*Connection)(conn).send(Layers{&tcp}, additionalLayers...)
}

// Close frees associated resources held by the TCPIPv4 connection.
func (conn *TCPIPv4) Close() {
	(*Connection)(conn).Close()
}

// Expect expects a frame with the TCP layer matching the provided TCP within
// the timeout specified. If it doesn't arrive in time, an error is returned.
func (conn *TCPIPv4) Expect(tcp TCP, timeout time.Duration) (*TCP, error) {
	layer, err := (*Connection)(conn).Expect(&tcp, timeout)
	if layer == nil {
		return nil, err
	}
	gotTCP, ok := layer.(*TCP)
	if !ok {
		conn.t.Fatalf("expected %s to be TCP", layer)
	}
	return gotTCP, err
}

func (conn *TCPIPv4) tcpState() *tcpState {
	state, ok := conn.layerStates[2].(*tcpState)
	if !ok {
		conn.t.Fatalf("got transport-layer state type=%T, expected tcpState", conn.layerStates[2])
	}
	return state
}

func (conn *TCPIPv4) ipv4State() *ipv4State {
	state, ok := conn.layerStates[1].(*ipv4State)
	if !ok {
		conn.t.Fatalf("expected network-layer state type=%T, expected ipv4State", conn.layerStates[1])
	}
	return state
}

// RemoteSeqNum returns the next expected sequence number from the DUT.
func (conn *TCPIPv4) RemoteSeqNum() *seqnum.Value {
	return conn.tcpState().remoteSeqNum
}

// LocalSeqNum returns the next sequence number to send from the testbench.
func (conn *TCPIPv4) LocalSeqNum() *seqnum.Value {
	return conn.tcpState().localSeqNum
}

// SynAck returns the SynAck that was part of the handshake.
func (conn *TCPIPv4) SynAck() *TCP {
	return conn.tcpState().synAck
}

// LocalAddr gets the local socket address of this connection.
func (conn *TCPIPv4) LocalAddr() *unix.SockaddrInet4 {
	sa := &unix.SockaddrInet4{Port: int(*conn.tcpState().out.SrcPort)}
	copy(sa.Addr[:], *conn.ipv4State().out.SrcAddr)
	return sa
}

// Drain drains the sniffer's receive buffer by receiving packets until there's
// nothing else to receive.
func (conn *TCPIPv4) Drain() {
	conn.sniffer.Drain()
}

// IPv6Conn maintains the state for all the layers in a IPv6 connection.
type IPv6Conn Connection

// NewIPv6Conn creates a new IPv6Conn connection with reasonable defaults.
func NewIPv6Conn(t *testing.T, outgoingIPv6, incomingIPv6 IPv6) IPv6Conn {
	etherState, err := newEtherState(Ether{}, Ether{})
	if err != nil {
		t.Fatalf("can't make EtherState: %s", err)
	}
	ipv6State, err := newIPv6State(outgoingIPv6, incomingIPv6)
	if err != nil {
		t.Fatalf("can't make IPv6State: %s", err)
	}

	injector, err := NewInjector(t)
	if err != nil {
		t.Fatalf("can't make injector: %s", err)
	}
	sniffer, err := NewSniffer(t)
	if err != nil {
		t.Fatalf("can't make sniffer: %s", err)
	}

	return IPv6Conn{
		layerStates: []layerState{etherState, ipv6State},
		injector:    injector,
		sniffer:     sniffer,
		t:           t,
	}
}

// Send sends a frame with ipv6 overriding the IPv6 layer defaults and
// additionalLayers added after it.
func (conn *IPv6Conn) Send(ipv6 IPv6, additionalLayers ...Layer) {
	(*Connection)(conn).send(Layers{&ipv6}, additionalLayers...)
}

// Close to clean up any resources held.
func (conn *IPv6Conn) Close() {
	(*Connection)(conn).Close()
}

// ExpectFrame expects a frame that matches the provided Layers within the
// timeout specified. If it doesn't arrive in time, an error is returned.
func (conn *IPv6Conn) ExpectFrame(frame Layers, timeout time.Duration) (Layers, error) {
	return (*Connection)(conn).ExpectFrame(frame, timeout)
}

// UDPIPv4 maintains the state for all the layers in a UDP/IPv4 connection.
type UDPIPv4 Connection

// NewUDPIPv4 creates a new UDPIPv4 connection with reasonable defaults.
func NewUDPIPv4(t *testing.T, outgoingUDP, incomingUDP UDP) UDPIPv4 {
	etherState, err := newEtherState(Ether{}, Ether{})
	if err != nil {
		t.Fatalf("can't make etherState: %s", err)
	}
	ipv4State, err := newIPv4State(IPv4{}, IPv4{})
	if err != nil {
		t.Fatalf("can't make ipv4State: %s", err)
	}
	udpState, err := newUDPState(unix.AF_INET, outgoingUDP, incomingUDP)
	if err != nil {
		t.Fatalf("can't make udpState: %s", err)
	}
	injector, err := NewInjector(t)
	if err != nil {
		t.Fatalf("can't make injector: %s", err)
	}
	sniffer, err := NewSniffer(t)
	if err != nil {
		t.Fatalf("can't make sniffer: %s", err)
	}

	return UDPIPv4{
		layerStates: []layerState{etherState, ipv4State, udpState},
		injector:    injector,
		sniffer:     sniffer,
		t:           t,
	}
}

func (conn *UDPIPv4) udpState() *udpState {
	state, ok := conn.layerStates[2].(*udpState)
	if !ok {
		conn.t.Fatalf("got transport-layer state type=%T, expected udpState", conn.layerStates[2])
	}
	return state
}

func (conn *UDPIPv4) ipv4State() *ipv4State {
	state, ok := conn.layerStates[1].(*ipv4State)
	if !ok {
		conn.t.Fatalf("got network-layer state type=%T, expected ipv4State", conn.layerStates[1])
	}
	return state
}

// LocalAddr gets the local socket address of this connection.
func (conn *UDPIPv4) LocalAddr() *unix.SockaddrInet4 {
	sa := &unix.SockaddrInet4{Port: int(*conn.udpState().out.SrcPort)}
	copy(sa.Addr[:], *conn.ipv4State().out.SrcAddr)
	return sa
}

// Send sends a packet with reasonable defaults, potentially overriding the UDP
// layer and adding additionLayers.
func (conn *UDPIPv4) Send(udp UDP, additionalLayers ...Layer) {
	(*Connection)(conn).send(Layers{&udp}, additionalLayers...)
}

// SendIP sends a packet with reasonable defaults, potentially overriding the
// UDP and IPv4 headers and adding additionLayers.
func (conn *UDPIPv4) SendIP(ip IPv4, udp UDP, additionalLayers ...Layer) {
	(*Connection)(conn).send(Layers{&ip, &udp}, additionalLayers...)
}

// Expect expects a frame with the UDP layer matching the provided UDP within
// the timeout specified. If it doesn't arrive in time, an error is returned.
func (conn *UDPIPv4) Expect(udp UDP, timeout time.Duration) (*UDP, error) {
	conn.t.Helper()
	layer, err := (*Connection)(conn).Expect(&udp, timeout)
	if err != nil {
		return nil, err
	}
	gotUDP, ok := layer.(*UDP)
	if !ok {
		conn.t.Fatalf("expected %s to be UDP", layer)
	}
	return gotUDP, nil
}

// ExpectData is a convenient method that expects a Layer and the Layer after
// it. If it doens't arrive in time, it returns nil.
func (conn *UDPIPv4) ExpectData(udp UDP, payload Payload, timeout time.Duration) (Layers, error) {
	conn.t.Helper()
	expected := make([]Layer, len(conn.layerStates))
	expected[len(expected)-1] = &udp
	if payload.length() != 0 {
		expected = append(expected, &payload)
	}
	return (*Connection)(conn).ExpectFrame(expected, timeout)
}

// Close frees associated resources held by the UDPIPv4 connection.
func (conn *UDPIPv4) Close() {
	(*Connection)(conn).Close()
}

// Drain drains the sniffer's receive buffer by receiving packets until there's
// nothing else to receive.
func (conn *UDPIPv4) Drain() {
	conn.sniffer.Drain()
}

// UDPIPv6 maintains the state for all the layers in a UDP/IPv6 connection.
type UDPIPv6 Connection

// NewUDPIPv6 creates a new UDPIPv6 connection with reasonable defaults.
func NewUDPIPv6(t *testing.T, outgoingUDP, incomingUDP UDP) UDPIPv6 {
	etherState, err := newEtherState(Ether{}, Ether{})
	if err != nil {
		t.Fatalf("can't make etherState: %s", err)
	}
	ipv6State, err := newIPv6State(IPv6{}, IPv6{})
	if err != nil {
		t.Fatalf("can't make IPv6State: %s", err)
	}
	udpState, err := newUDPState(unix.AF_INET6, outgoingUDP, incomingUDP)
	if err != nil {
		t.Fatalf("can't make udpState: %s", err)
	}
	injector, err := NewInjector(t)
	if err != nil {
		t.Fatalf("can't make injector: %s", err)
	}
	sniffer, err := NewSniffer(t)
	if err != nil {
		t.Fatalf("can't make sniffer: %s", err)
	}
	return UDPIPv6{
		layerStates: []layerState{etherState, ipv6State, udpState},
		injector:    injector,
		sniffer:     sniffer,
		t:           t,
	}
}

func (conn *UDPIPv6) udpState() *udpState {
	state, ok := conn.layerStates[2].(*udpState)
	if !ok {
		conn.t.Fatalf("got transport-layer state type=%T, expected udpState", conn.layerStates[2])
	}
	return state
}

func (conn *UDPIPv6) ipv6State() *ipv6State {
	state, ok := conn.layerStates[1].(*ipv6State)
	if !ok {
		conn.t.Fatalf("got network-layer state type=%T, expected ipv6State", conn.layerStates[1])
	}
	return state
}

// LocalAddr gets the local socket address of this connection.
func (conn *UDPIPv6) LocalAddr() *unix.SockaddrInet6 {
	sa := &unix.SockaddrInet6{
		Port: int(*conn.udpState().out.SrcPort),
		// Local address is in perspective to the remote host, so it's scoped to the
		// ID of the remote interface.
		ZoneId: uint32(RemoteInterfaceID),
	}
	copy(sa.Addr[:], *conn.ipv6State().out.SrcAddr)
	return sa
}

// Send sends a packet with reasonable defaults, potentially overriding the UDP
// layer and adding additionLayers.
func (conn *UDPIPv6) Send(udp UDP, additionalLayers ...Layer) {
	(*Connection)(conn).send(Layers{&udp}, additionalLayers...)
}

// SendIPv6 sends a packet with reasonable defaults, potentially overriding the
// UDP and IPv6 headers and adding additionLayers.
func (conn *UDPIPv6) SendIPv6(ip IPv6, udp UDP, additionalLayers ...Layer) {
	(*Connection)(conn).send(Layers{&ip, &udp}, additionalLayers...)
}

// Expect expects a frame with the UDP layer matching the provided UDP within
// the timeout specified. If it doesn't arrive in time, an error is returned.
func (conn *UDPIPv6) Expect(udp UDP, timeout time.Duration) (*UDP, error) {
	conn.t.Helper()
	layer, err := (*Connection)(conn).Expect(&udp, timeout)
	if err != nil {
		return nil, err
	}
	gotUDP, ok := layer.(*UDP)
	if !ok {
		conn.t.Fatalf("expected %s to be UDP", layer)
	}
	return gotUDP, nil
}

// ExpectData is a convenient method that expects a Layer and the Layer after
// it. If it doens't arrive in time, it returns nil.
func (conn *UDPIPv6) ExpectData(udp UDP, payload Payload, timeout time.Duration) (Layers, error) {
	conn.t.Helper()
	expected := make([]Layer, len(conn.layerStates))
	expected[len(expected)-1] = &udp
	if payload.length() != 0 {
		expected = append(expected, &payload)
	}
	return (*Connection)(conn).ExpectFrame(expected, timeout)
}

// Close frees associated resources held by the UDPIPv6 connection.
func (conn *UDPIPv6) Close() {
	(*Connection)(conn).Close()
}

// Drain drains the sniffer's receive buffer by receiving packets until there's
// nothing else to receive.
func (conn *UDPIPv6) Drain() {
	conn.sniffer.Drain()
}

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

package tcpip

import (
	"sync/atomic"

	"gvisor.dev/gvisor/pkg/sync"
)

// SocketOptionsHandler holds methods that help define endpoint specific
// behavior for socket level socket options. These must be implemented by
// endpoints to get notified when socket level options are set.
type SocketOptionsHandler interface {
	// OnReuseAddressSet is invoked when SO_REUSEADDR is set for an endpoint.
	OnReuseAddressSet(v bool)

	// OnReusePortSet is invoked when SO_REUSEPORT is set for an endpoint.
	OnReusePortSet(v bool)

	// OnKeepAliveSet is invoked when SO_KEEPALIVE is set for an endpoint.
	OnKeepAliveSet(v bool)

	// OnDelayOptionSet is invoked when TCP_NODELAY is set for an endpoint.
	// Note that v will be the inverse of TCP_NODELAY option.
	OnDelayOptionSet(v bool)

	// OnCorkOptionSet is invoked when TCP_CORK is set for an endpoint.
	OnCorkOptionSet(v bool)

	// LastError is invoked when SO_ERROR is read for an endpoint.
	LastError() *Error
}

// DefaultSocketOptionsHandler is an embeddable type that implements no-op
// implementations for SocketOptionsHandler methods.
type DefaultSocketOptionsHandler struct{}

var _ SocketOptionsHandler = (*DefaultSocketOptionsHandler)(nil)

// OnReuseAddressSet implements SocketOptionsHandler.OnReuseAddressSet.
func (*DefaultSocketOptionsHandler) OnReuseAddressSet(bool) {}

// OnReusePortSet implements SocketOptionsHandler.OnReusePortSet.
func (*DefaultSocketOptionsHandler) OnReusePortSet(bool) {}

// OnKeepAliveSet implements SocketOptionsHandler.OnKeepAliveSet.
func (*DefaultSocketOptionsHandler) OnKeepAliveSet(bool) {}

// OnDelayOptionSet implements SocketOptionsHandler.OnDelayOptionSet.
func (*DefaultSocketOptionsHandler) OnDelayOptionSet(bool) {}

// OnCorkOptionSet implements SocketOptionsHandler.OnCorkOptionSet.
func (*DefaultSocketOptionsHandler) OnCorkOptionSet(bool) {}

// LastError implements SocketOptionsHandler.LastError.
func (*DefaultSocketOptionsHandler) LastError() *Error {
	return nil
}

// SocketOptions contains all the variables which store values for SOL_SOCKET,
// SOL_IP, SOL_IPV6 and SOL_TCP level options.
//
// +stateify savable
type SocketOptions struct {
	handler SocketOptionsHandler

	// These fields are accessed and modified using atomic operations.

	// broadcastEnabled determines whether datagram sockets are allowed to
	// send packets to a broadcast address.
	broadcastEnabled uint32

	// passCredEnabled determines whether SCM_CREDENTIALS socket control
	// messages are enabled.
	passCredEnabled uint32

	// noChecksumEnabled determines whether UDP checksum is disabled while
	// transmitting for this socket.
	noChecksumEnabled uint32

	// reuseAddressEnabled determines whether Bind() should allow reuse of
	// local address.
	reuseAddressEnabled uint32

	// reusePortEnabled determines whether to permit multiple sockets to be
	// bound to an identical socket address.
	reusePortEnabled uint32

	// keepAliveEnabled determines whether TCP keepalive is enabled for this
	// socket.
	keepAliveEnabled uint32

	// multicastLoopEnabled determines whether multicast packets sent over a
	// non-loopback interface will be looped back. Analogous to inet->mc_loop.
	multicastLoopEnabled uint32

	// receiveTOSEnabled is used to specify if the TOS ancillary message is
	// passed with incoming packets.
	receiveTOSEnabled uint32

	// receiveTClassEnabled is used to specify if the IPV6_TCLASS ancillary
	// message is passed with incoming packets.
	receiveTClassEnabled uint32

	// receivePacketInfoEnabled is used to specify if more inforamtion is
	// provided with incoming packets such as interface index and address.
	receivePacketInfoEnabled uint32

	// hdrIncludeEnabled is used to indicate for a raw endpoint that all packets
	// being written have an IP header and the endpoint should not attach an IP
	// header.
	hdrIncludedEnabled uint32

	// v6OnlyEnabled is used to determine whether an IPv6 socket is to be
	// restricted to sending and receiving IPv6 packets only.
	v6OnlyEnabled uint32

	// quickAckEnabled is used to represent the value of TCP_QUICKACK option.
	// It currently does not have any effect on the TCP endpoint.
	quickAckEnabled uint32

	// delayOptionEnabled is used to specify if data should be sent out immediately
	// by the transport protocol. For TCP, it determines if the Nagle algorithm
	// is on or off.
	delayOptionEnabled uint32

	// corkOptionEnabled is used to specify if data should be held until segments
	// are full by the TCP transport protocol.
	corkOptionEnabled uint32

	// receiveOriginalDstAddress is used to specify if the original destination of
	// the incoming packet should be returned as an ancillary message.
	receiveOriginalDstAddress uint32

	// mu protects the access to the below fields.
	mu sync.Mutex `state:"nosave"`

	// linger determines the amount of time the socket should linger before
	// close. We currently implement this option for TCP socket only.
	linger LingerOption
}

// InitHandler initializes the handler. This must be called before using the
// socket options utility.
func (so *SocketOptions) InitHandler(handler SocketOptionsHandler) {
	so.handler = handler
}

func storeAtomicBool(addr *uint32, v bool) {
	var val uint32
	if v {
		val = 1
	}
	atomic.StoreUint32(addr, val)
}

// GetBroadcast gets value for SO_BROADCAST option.
func (so *SocketOptions) GetBroadcast() bool {
	return atomic.LoadUint32(&so.broadcastEnabled) != 0
}

// SetBroadcast sets value for SO_BROADCAST option.
func (so *SocketOptions) SetBroadcast(v bool) {
	storeAtomicBool(&so.broadcastEnabled, v)
}

// GetPassCred gets value for SO_PASSCRED option.
func (so *SocketOptions) GetPassCred() bool {
	return atomic.LoadUint32(&so.passCredEnabled) != 0
}

// SetPassCred sets value for SO_PASSCRED option.
func (so *SocketOptions) SetPassCred(v bool) {
	storeAtomicBool(&so.passCredEnabled, v)
}

// GetNoChecksum gets value for SO_NO_CHECK option.
func (so *SocketOptions) GetNoChecksum() bool {
	return atomic.LoadUint32(&so.noChecksumEnabled) != 0
}

// SetNoChecksum sets value for SO_NO_CHECK option.
func (so *SocketOptions) SetNoChecksum(v bool) {
	storeAtomicBool(&so.noChecksumEnabled, v)
}

// GetReuseAddress gets value for SO_REUSEADDR option.
func (so *SocketOptions) GetReuseAddress() bool {
	return atomic.LoadUint32(&so.reuseAddressEnabled) != 0
}

// SetReuseAddress sets value for SO_REUSEADDR option.
func (so *SocketOptions) SetReuseAddress(v bool) {
	storeAtomicBool(&so.reuseAddressEnabled, v)
	so.handler.OnReuseAddressSet(v)
}

// GetReusePort gets value for SO_REUSEPORT option.
func (so *SocketOptions) GetReusePort() bool {
	return atomic.LoadUint32(&so.reusePortEnabled) != 0
}

// SetReusePort sets value for SO_REUSEPORT option.
func (so *SocketOptions) SetReusePort(v bool) {
	storeAtomicBool(&so.reusePortEnabled, v)
	so.handler.OnReusePortSet(v)
}

// GetKeepAlive gets value for SO_KEEPALIVE option.
func (so *SocketOptions) GetKeepAlive() bool {
	return atomic.LoadUint32(&so.keepAliveEnabled) != 0
}

// SetKeepAlive sets value for SO_KEEPALIVE option.
func (so *SocketOptions) SetKeepAlive(v bool) {
	storeAtomicBool(&so.keepAliveEnabled, v)
	so.handler.OnKeepAliveSet(v)
}

// GetMulticastLoop gets value for IP_MULTICAST_LOOP option.
func (so *SocketOptions) GetMulticastLoop() bool {
	return atomic.LoadUint32(&so.multicastLoopEnabled) != 0
}

// SetMulticastLoop sets value for IP_MULTICAST_LOOP option.
func (so *SocketOptions) SetMulticastLoop(v bool) {
	storeAtomicBool(&so.multicastLoopEnabled, v)
}

// GetReceiveTOS gets value for IP_RECVTOS option.
func (so *SocketOptions) GetReceiveTOS() bool {
	return atomic.LoadUint32(&so.receiveTOSEnabled) != 0
}

// SetReceiveTOS sets value for IP_RECVTOS option.
func (so *SocketOptions) SetReceiveTOS(v bool) {
	storeAtomicBool(&so.receiveTOSEnabled, v)
}

// GetReceiveTClass gets value for IPV6_RECVTCLASS option.
func (so *SocketOptions) GetReceiveTClass() bool {
	return atomic.LoadUint32(&so.receiveTClassEnabled) != 0
}

// SetReceiveTClass sets value for IPV6_RECVTCLASS option.
func (so *SocketOptions) SetReceiveTClass(v bool) {
	storeAtomicBool(&so.receiveTClassEnabled, v)
}

// GetReceivePacketInfo gets value for IP_PKTINFO option.
func (so *SocketOptions) GetReceivePacketInfo() bool {
	return atomic.LoadUint32(&so.receivePacketInfoEnabled) != 0
}

// SetReceivePacketInfo sets value for IP_PKTINFO option.
func (so *SocketOptions) SetReceivePacketInfo(v bool) {
	storeAtomicBool(&so.receivePacketInfoEnabled, v)
}

// GetHeaderIncluded gets value for IP_HDRINCL option.
func (so *SocketOptions) GetHeaderIncluded() bool {
	return atomic.LoadUint32(&so.hdrIncludedEnabled) != 0
}

// SetHeaderIncluded sets value for IP_HDRINCL option.
func (so *SocketOptions) SetHeaderIncluded(v bool) {
	storeAtomicBool(&so.hdrIncludedEnabled, v)
}

// GetV6Only gets value for IPV6_V6ONLY option.
func (so *SocketOptions) GetV6Only() bool {
	return atomic.LoadUint32(&so.v6OnlyEnabled) != 0
}

// SetV6Only sets value for IPV6_V6ONLY option.
//
// Preconditions: the backing TCP or UDP endpoint must be in initial state.
func (so *SocketOptions) SetV6Only(v bool) {
	storeAtomicBool(&so.v6OnlyEnabled, v)
}

// GetQuickAck gets value for TCP_QUICKACK option.
func (so *SocketOptions) GetQuickAck() bool {
	return atomic.LoadUint32(&so.quickAckEnabled) != 0
}

// SetQuickAck sets value for TCP_QUICKACK option.
func (so *SocketOptions) SetQuickAck(v bool) {
	storeAtomicBool(&so.quickAckEnabled, v)
}

// GetDelayOption gets inverted value for TCP_NODELAY option.
func (so *SocketOptions) GetDelayOption() bool {
	return atomic.LoadUint32(&so.delayOptionEnabled) != 0
}

// SetDelayOption sets inverted value for TCP_NODELAY option.
func (so *SocketOptions) SetDelayOption(v bool) {
	storeAtomicBool(&so.delayOptionEnabled, v)
	so.handler.OnDelayOptionSet(v)
}

// GetCorkOption gets value for TCP_CORK option.
func (so *SocketOptions) GetCorkOption() bool {
	return atomic.LoadUint32(&so.corkOptionEnabled) != 0
}

// SetCorkOption sets value for TCP_CORK option.
func (so *SocketOptions) SetCorkOption(v bool) {
	storeAtomicBool(&so.corkOptionEnabled, v)
	so.handler.OnCorkOptionSet(v)
}

// GetReceiveOriginalDstAddress gets value for IP(V6)_RECVORIGDSTADDR option.
func (so *SocketOptions) GetReceiveOriginalDstAddress() bool {
	return atomic.LoadUint32(&so.receiveOriginalDstAddress) != 0
}

// SetReceiveOriginalDstAddress sets value for IP(V6)_RECVORIGDSTADDR option.
func (so *SocketOptions) SetReceiveOriginalDstAddress(v bool) {
	storeAtomicBool(&so.receiveOriginalDstAddress, v)
}

// GetLastError gets value for SO_ERROR option.
func (so *SocketOptions) GetLastError() *Error {
	return so.handler.LastError()
}

// GetOutOfBandInline gets value for SO_OOBINLINE option.
func (*SocketOptions) GetOutOfBandInline() bool {
	return true
}

// SetOutOfBandInline sets value for SO_OOBINLINE option. We currently do not
// support disabling this option.
func (*SocketOptions) SetOutOfBandInline(bool) {}

// GetLinger gets value for SO_LINGER option.
func (so *SocketOptions) GetLinger() LingerOption {
	so.mu.Lock()
	linger := so.linger
	so.mu.Unlock()
	return linger
}

// SetLinger sets value for SO_LINGER option.
func (so *SocketOptions) SetLinger(linger LingerOption) {
	so.mu.Lock()
	so.linger = linger
	so.mu.Unlock()
}

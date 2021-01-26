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

package arp

import (
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

var _ stack.NetworkEndpointStats = (*Stats)(nil)

// Stats holds statistics related to ARP.
type Stats struct {
	// ARP holds ARP statistics.
	ARP tcpip.ARPStats
}

// IsNetworkEndpointStats implements stack.NetworkEndpointStats.
func (*Stats) IsNetworkEndpointStats() {}

type sharedStats struct {
	localStats Stats
	arp        multiCounterARPStats
}

// LINT.IfChange(multiCounterARPStats)

type multiCounterARPStats struct {
	packetsReceived                                 tcpip.MultiCounterStat
	disabledPacketsReceived                         tcpip.MultiCounterStat
	malformedPacketsReceived                        tcpip.MultiCounterStat
	requestsReceived                                tcpip.MultiCounterStat
	requestsReceivedUnknownTargetAddress            tcpip.MultiCounterStat
	outgoingRequestInterfaceHasNoLocalAddressErrors tcpip.MultiCounterStat
	outgoingRequestBadLocalAddressErrors            tcpip.MultiCounterStat
	outgoingRequestsDropped                         tcpip.MultiCounterStat
	outgoingRequestsSent                            tcpip.MultiCounterStat
	repliesReceived                                 tcpip.MultiCounterStat
	outgoingRepliesDropped                          tcpip.MultiCounterStat
	outgoingRepliesSent                             tcpip.MultiCounterStat
}

func (m *multiCounterARPStats) init(a, b *tcpip.ARPStats) {
	m.packetsReceived.Init(a.PacketsReceived, b.PacketsReceived)
	m.disabledPacketsReceived.Init(a.DisabledPacketsReceived, b.DisabledPacketsReceived)
	m.malformedPacketsReceived.Init(a.MalformedPacketsReceived, b.MalformedPacketsReceived)
	m.requestsReceived.Init(a.RequestsReceived, b.RequestsReceived)
	m.requestsReceivedUnknownTargetAddress.Init(a.RequestsReceivedUnknownTargetAddress, b.RequestsReceivedUnknownTargetAddress)
	m.outgoingRequestInterfaceHasNoLocalAddressErrors.Init(a.OutgoingRequestInterfaceHasNoLocalAddressErrors, b.OutgoingRequestInterfaceHasNoLocalAddressErrors)
	m.outgoingRequestBadLocalAddressErrors.Init(a.OutgoingRequestBadLocalAddressErrors, b.OutgoingRequestBadLocalAddressErrors)
	m.outgoingRequestsDropped.Init(a.OutgoingRequestsDropped, b.OutgoingRequestsDropped)
	m.outgoingRequestsSent.Init(a.OutgoingRequestsSent, b.OutgoingRequestsSent)
	m.repliesReceived.Init(a.RepliesReceived, b.RepliesReceived)
	m.outgoingRepliesDropped.Init(a.OutgoingRepliesDropped, b.OutgoingRepliesDropped)
	m.outgoingRepliesSent.Init(a.OutgoingRepliesSent, b.OutgoingRepliesSent)
}

// LINT.ThenChange(../../tcpip.go:ARPStats)

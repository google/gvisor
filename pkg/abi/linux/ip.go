// Copyright 2018 Google LLC
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

package linux

// IP protocols
const (
	IPPROTO_IP      = 0
	IPPROTO_ICMP    = 1
	IPPROTO_IGMP    = 2
	IPPROTO_IPIP    = 4
	IPPROTO_TCP     = 6
	IPPROTO_EGP     = 8
	IPPROTO_PUP     = 12
	IPPROTO_UDP     = 17
	IPPROTO_IDP     = 22
	IPPROTO_TP      = 29
	IPPROTO_DCCP    = 33
	IPPROTO_IPV6    = 41
	IPPROTO_RSVP    = 46
	IPPROTO_GRE     = 47
	IPPROTO_ESP     = 50
	IPPROTO_AH      = 51
	IPPROTO_MTP     = 92
	IPPROTO_BEETPH  = 94
	IPPROTO_ENCAP   = 98
	IPPROTO_PIM     = 103
	IPPROTO_COMP    = 108
	IPPROTO_SCTP    = 132
	IPPROTO_UDPLITE = 136
	IPPROTO_MPLS    = 137
	IPPROTO_RAW     = 255
)

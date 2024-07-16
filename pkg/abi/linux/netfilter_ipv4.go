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

package linux

import "math"

// Netfilter IPv4 Standard Hook Priorities, from uapi/linux/netfilter_ipv4.h.
const (
	NF_IP_PRI_FIRST             = math.MinInt
	NF_IP_PRI_RAW_BEFORE_DEFRAG = -450
	NF_IP_PRI_CONNTRACK_DEFRAG  = -400
	NF_IP_PRI_RAW               = -300
	NF_IP_PRI_SELINUX_FIRST     = -225
	NF_IP_PRI_CONNTRACK         = -200
	NF_IP_PRI_MANGLE            = -150
	NF_IP_PRI_NAT_DST           = -100
	NF_IP_PRI_FILTER            = 0
	NF_IP_PRI_SECURITY          = 50
	NF_IP_PRI_NAT_SRC           = 100
	NF_IP_PRI_SELINUX_LAST      = 225
	NF_IP_PRI_CONNTRACK_HELPER  = 300
	NF_IP_PRI_CONNTRACK_CONFIRM = math.MaxInt
	NF_IP_PRI_LAST              = math.MaxInt
)

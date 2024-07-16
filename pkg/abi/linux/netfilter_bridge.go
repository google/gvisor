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

// Netfilter Bridge Standard Hook Priorities, from
// uapi/linux/netfilter_bridge.h.
const (
	NF_BR_PRI_FIRST           = math.MinInt
	NF_BR_PRI_NAT_DST_BRIDGED = -300
	NF_BR_PRI_FILTER_BRIDGED  = -200
	NF_BR_PRI_BRNF            = 0
	NF_BR_PRI_NAT_DST_OTHER   = 100
	NF_BR_PRI_FILTER_OTHER    = 200
	NF_BR_PRI_NAT_SRC         = 300
	NF_BR_PRI_LAST            = math.MaxInt
)

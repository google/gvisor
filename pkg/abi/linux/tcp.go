// Copyright 2018 The gVisor Authors.
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

// Socket options from uapi/linux/tcp.h.
const (
	TCP_NODELAY              = 1
	TCP_MAXSEG               = 2
	TCP_CORK                 = 3
	TCP_KEEPIDLE             = 4
	TCP_KEEPINTVL            = 5
	TCP_KEEPCNT              = 6
	TCP_SYNCNT               = 7
	TCP_LINGER2              = 8
	TCP_DEFER_ACCEPT         = 9
	TCP_WINDOW_CLAMP         = 10
	TCP_INFO                 = 11
	TCP_QUICKACK             = 12
	TCP_CONGESTION           = 13
	TCP_MD5SIG               = 14
	TCP_THIN_LINEAR_TIMEOUTS = 16
	TCP_THIN_DUPACK          = 17
	TCP_USER_TIMEOUT         = 18
	TCP_REPAIR               = 19
	TCP_REPAIR_QUEUE         = 20
	TCP_QUEUE_SEQ            = 21
	TCP_REPAIR_OPTIONS       = 22
	TCP_FASTOPEN             = 23
	TCP_TIMESTAMP            = 24
	TCP_NOTSENT_LOWAT        = 25
	TCP_CC_INFO              = 26
	TCP_SAVE_SYN             = 27
	TCP_SAVED_SYN            = 28
	TCP_REPAIR_WINDOW        = 29
	TCP_FASTOPEN_CONNECT     = 30
	TCP_ULP                  = 31
	TCP_MD5SIG_EXT           = 32
	TCP_FASTOPEN_KEY         = 33
	TCP_FASTOPEN_NO_COOKIE   = 34
	TCP_ZEROCOPY_RECEIVE     = 35
	TCP_INQ                  = 36
)

// Socket constants from include/net/tcp.h.
const (
	MAX_TCP_KEEPIDLE  = 32767
	MAX_TCP_KEEPINTVL = 32767
)

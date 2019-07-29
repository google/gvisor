// Copyright 2019 The gVisor Authors.
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

// There are a number of structs and values that we can't #include because of a
// difference between C and C++ (C++ won't let you implicitly cast from void* to
// struct something*). We re-define them here.

#ifndef GVISOR_TEST_SYSCALLS_IPTABLES_TYPES_H_
#define GVISOR_TEST_SYSCALLS_IPTABLES_TYPES_H_

// Netfilter headers require some headers to preceed them.
// clang-format off
#include <netinet/in.h>
#include <stddef.h>
// clang-format on

#include <linux/netfilter/x_tables.h>
#include <linux/netfilter_ipv4.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <stdint.h>

#define ipt_standard_target xt_standard_target
#define ipt_entry_target xt_entry_target
#define ipt_error_target xt_error_target

enum SockOpts {
  // For setsockopt.
  BASE_CTL = 64,
  SO_SET_REPLACE = BASE_CTL,
  SO_SET_ADD_COUNTERS,
  SO_SET_MAX = SO_SET_ADD_COUNTERS,

  // For getsockopt.
  SO_GET_INFO = BASE_CTL,
  SO_GET_ENTRIES,
  SO_GET_REVISION_MATCH,
  SO_GET_REVISION_TARGET,
  SO_GET_MAX = SO_GET_REVISION_TARGET
};

// ipt_ip specifies basic matching criteria that can be applied by examining
// only the IP header of a packet.
struct ipt_ip {
  // Source IP address.
  struct in_addr src;

  // Destination IP address.
  struct in_addr dst;

  // Source IP address mask.
  struct in_addr smsk;

  // Destination IP address mask.
  struct in_addr dmsk;

  // Input interface.
  char iniface[IFNAMSIZ];

  // Output interface.
  char outiface[IFNAMSIZ];

  // Input interface mask.
  unsigned char iniface_mask[IFNAMSIZ];

  // Output interface mask.
  unsigned char outiface_mask[IFNAMSIZ];

  // Transport protocol.
  uint16_t proto;

  // Flags.
  uint8_t flags;

  // Inverse flags.
  uint8_t invflags;
};

// ipt_entry is an iptables rule. It contains information about what packets the
// rule matches and what action (target) to perform for matching packets.
struct ipt_entry {
  // Basic matching information used to match a packet's IP header.
  struct ipt_ip ip;

  // A caching field that isn't used by userspace.
  unsigned int nfcache;

  // The number of bytes between the start of this ipt_entry struct and the
  // rule's target.
  uint16_t target_offset;

  // The total size of this rule, from the beginning of the entry to the end of
  // the target.
  uint16_t next_offset;

  // A return pointer not used by userspace.
  unsigned int comefrom;

  // Counters for packets and bytes, which we don't yet implement.
  struct xt_counters counters;

  // The data for all this rules matches followed by the target. This runs
  // beyond the value of sizeof(struct ipt_entry).
  unsigned char elems[0];
};

// Passed to getsockopt(SO_GET_INFO).
struct ipt_getinfo {
  // The name of the table. The user only fills this in, the rest is filled in
  // when returning from getsockopt. Currently "nat" and "mangle" are supported.
  char name[XT_TABLE_MAXNAMELEN];

  // A bitmap of which hooks apply to the table. For example, a table with hooks
  // PREROUTING and FORWARD has the value
  // (1 << NF_IP_PRE_REOUTING) | (1 << NF_IP_FORWARD).
  unsigned int valid_hooks;

  // The offset into the entry table for each valid hook. The entry table is
  // returned by getsockopt(SO_GET_ENTRIES).
  unsigned int hook_entry[NF_IP_NUMHOOKS];

  // For each valid hook, the underflow is the offset into the entry table to
  // jump to in case traversing the table yields no verdict (although I have no
  // clue how that could happen - builtin chains always end with a policy, and
  // user-defined chains always end with a RETURN.
  //
  // The entry referred to must be an "unconditional" entry, meaning it has no
  // matches, specifies no IP criteria, and either DROPs or ACCEPTs packets.  It
  // basically has to be capable of making a definitive decision no matter what
  // it's passed.
  unsigned int underflow[NF_IP_NUMHOOKS];

  // The number of entries in the entry table returned by
  // getsockopt(SO_GET_ENTRIES).
  unsigned int num_entries;

  // The size of the entry table returned by getsockopt(SO_GET_ENTRIES).
  unsigned int size;
};

// Passed to getsockopt(SO_GET_ENTRIES).
struct ipt_get_entries {
  // The name of the table. The user fills this in. Currently "nat" and "mangle"
  // are supported.
  char name[XT_TABLE_MAXNAMELEN];

  // The size of the entry table in bytes. The user fills this in with the value
  // from struct ipt_getinfo.size.
  unsigned int size;

  // The entries for the given table. This will run past the size defined by
  // sizeof(struct ipt_get_entries).
  struct ipt_entry entrytable[0];
};

// Passed to setsockopt(SO_SET_REPLACE).
struct ipt_replace {
  // The name of the table.
  char name[XT_TABLE_MAXNAMELEN];

  // The same as struct ipt_getinfo.valid_hooks. Users don't change this.
  unsigned int valid_hooks;

  // The same as struct ipt_getinfo.num_entries.
  unsigned int num_entries;

  // The same as struct ipt_getinfo.size.
  unsigned int size;

  // The same as struct ipt_getinfo.hook_entry.
  unsigned int hook_entry[NF_IP_NUMHOOKS];

  // The same as struct ipt_getinfo.underflow.
  unsigned int underflow[NF_IP_NUMHOOKS];

  // The number of counters, which should equal the number of entries.
  unsigned int num_counters;

  // The unchanged values from each ipt_entry's counters.
  struct xt_counters *counters;

  // The entries to write to the table. This will run past the size defined by
  // sizeof(srtuct ipt_replace);
  struct ipt_entry entries[0];
};

#endif  // GVISOR_TEST_SYSCALLS_IPTABLES_TYPES_H_

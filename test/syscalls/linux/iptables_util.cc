// Copyright 2026 The gVisor Authors.
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

#include "test/syscalls/linux/iptables_util.h"

#include <stdio.h>
#include <string.h>

#include <vector>

#include "test/syscalls/linux/iptables.h"

namespace gvisor {
namespace testing {

namespace {

template <typename ReplaceType, typename EntryType>
std::vector<char> MakeUserChainTargetReplacePayloadImpl(int local_in_hook,
                                                        int forward_hook,
                                                        int local_out_hook) {
  const size_t kEmptyErrorEntrySize =
      sizeof(EntryType) + sizeof(struct xt_error_target);
  const size_t kEmptyStandardEntrySize =
      sizeof(EntryType) + sizeof(struct xt_standard_target);

  const size_t num_entries = 4;
  const size_t total_entries_size =
      2 * kEmptyErrorEntrySize + 2 * kEmptyStandardEntrySize;
  const size_t replace_size = sizeof(ReplaceType) + total_entries_size;
  std::vector<char> buf(replace_size, 0);

  ReplaceType* repl = reinterpret_cast<ReplaceType*>(buf.data());
  snprintf(repl->name, sizeof(repl->name), "filter");
  repl->valid_hooks =
      (1 << local_in_hook) | (1 << forward_hook) | (1 << local_out_hook);
  repl->num_entries = num_entries;
  repl->size = total_entries_size;
  repl->num_counters = num_entries;

  // Both LOCAL_IN and LOCAL_OUT hook entries point to Entry 0
  // (UserChainTarget). Their underflows point to Entry 1 (ACCEPT).
  repl->hook_entry[local_in_hook] = 0;
  repl->underflow[local_in_hook] = kEmptyErrorEntrySize;

  repl->hook_entry[local_out_hook] = 0;
  repl->underflow[local_out_hook] = kEmptyErrorEntrySize;

  repl->hook_entry[forward_hook] = kEmptyErrorEntrySize;
  repl->underflow[forward_hook] = kEmptyErrorEntrySize;

  char* dst = buf.data() + sizeof(ReplaceType);
  size_t offset = 0;

  // Entry 0 (LOCAL_IN hook): An XT_ERROR_TARGET with errorname = "my_chain"
  // (which is parsed by gVisor as a UserChainTarget).
  {
    EntryType* e = reinterpret_cast<EntryType*>(dst + offset);
    e->target_offset = sizeof(EntryType);
    e->next_offset = kEmptyErrorEntrySize;
    struct xt_error_target* t =
        reinterpret_cast<struct xt_error_target*>(e->elems);
    t->target.u.user.target_size = sizeof(*t);
    snprintf(t->target.u.user.name, sizeof(t->target.u.user.name), "ERROR");
    snprintf(t->errorname, sizeof(t->errorname), "my_chain");
    offset += e->next_offset;
  }

  // Entry 1 (FORWARD hook): Standard ACCEPT target.
  {
    EntryType* e = reinterpret_cast<EntryType*>(dst + offset);
    e->target_offset = sizeof(EntryType);
    e->next_offset = kEmptyStandardEntrySize;
    struct xt_standard_target* t =
        reinterpret_cast<struct xt_standard_target*>(e->elems);
    t->target.u.user.target_size = sizeof(*t);
    t->verdict = -NF_ACCEPT - 1;
    offset += e->next_offset;
  }

  // Entry 2 (LOCAL_OUT hook): Standard ACCEPT target.
  {
    EntryType* e = reinterpret_cast<EntryType*>(dst + offset);
    e->target_offset = sizeof(EntryType);
    e->next_offset = kEmptyStandardEntrySize;
    struct xt_standard_target* t =
        reinterpret_cast<struct xt_standard_target*>(e->elems);
    t->target.u.user.target_size = sizeof(*t);
    t->verdict = -NF_ACCEPT - 1;
    offset += e->next_offset;
  }

  // Entry 3 (Final error entry): Mandatory table end sentinel ("ERROR").
  {
    EntryType* e = reinterpret_cast<EntryType*>(dst + offset);
    e->target_offset = sizeof(EntryType);
    e->next_offset = kEmptyErrorEntrySize;
    struct xt_error_target* t =
        reinterpret_cast<struct xt_error_target*>(e->elems);
    t->target.u.user.target_size = sizeof(*t);
    snprintf(t->target.u.user.name, sizeof(t->target.u.user.name), "ERROR");
    snprintf(t->errorname, sizeof(t->errorname), "ERROR");
    offset += e->next_offset;
  }

  return buf;
}

}  // namespace

std::vector<char> MakeUserChainTargetReplacePayload4() {
  return MakeUserChainTargetReplacePayloadImpl<struct ipt_replace,
                                               struct ipt_entry>(
      NF_IP_LOCAL_IN, NF_IP_FORWARD, NF_IP_LOCAL_OUT);
}

std::vector<char> MakeUserChainTargetReplacePayload6() {
  return MakeUserChainTargetReplacePayloadImpl<struct ip6t_replace,
                                               struct ip6t_entry>(
      NF_IP6_LOCAL_IN, NF_IP6_FORWARD, NF_IP6_LOCAL_OUT);
}

}  // namespace testing
}  // namespace gvisor

// Copyright 2023 The gVisor Authors.
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

#ifndef THIRD_PARTY_GVISOR_PKG_SENTRY_PLATFORM_SYSTRAP_SYSMSG_ATOMIC_H_
#define THIRD_PARTY_GVISOR_PKG_SENTRY_PLATFORM_SYSTRAP_SYSMSG_ATOMIC_H_

#define atomic_load(p) __atomic_load_n(p, __ATOMIC_ACQUIRE)
#define atomic_store(p, val) __atomic_store_n(p, val, __ATOMIC_RELEASE)
#define atomic_compare_exchange(p, old, val)                        \
  __atomic_compare_exchange_n(p, old, val, false, __ATOMIC_ACQ_REL, \
                              __ATOMIC_ACQUIRE)
#define atomic_add(p, val) __atomic_add_fetch(p, val, __ATOMIC_ACQ_REL)
#define atomic_sub(p, val) __atomic_sub_fetch(p, val, __ATOMIC_ACQ_REL)

#endif  // THIRD_PARTY_GVISOR_PKG_SENTRY_PLATFORM_SYSTRAP_SYSMSG_ATOMIC_H_

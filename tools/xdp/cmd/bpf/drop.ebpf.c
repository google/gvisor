// Copyright 2022 The gVisor Authors.
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

#include <linux/bpf.h>

#define section(secname) __attribute__((section(secname), used))

char __license[] section("license") = "Apache-2.0";

// You probably shouldn't change the section or function name. Each is used by
// BPF tooling, and so changes can cause runtime failures.
section("xdp") int xdp_prog(struct xdp_md *ctx) { return XDP_DROP; }

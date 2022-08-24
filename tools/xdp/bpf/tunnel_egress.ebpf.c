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
#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <netinet/ip.h>

#define section(secname) __attribute__((section(secname), used))

char __license[] section("license") = "Apache-2.0";

// Helper functions are defined positionally in <linux/bpf.h>, and their
// signatures are scattered throughout the kernel. They can be found via the
// defining macro BPF_CALL_[0-5].
// TODO(b/240191988): Use vmlinux instead of this.
static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)1;
static int (*bpf_trace_printk)(const char *fmt, __u32 fmt_size,
                               ...) = (void *)6;
static int (*bpf_redirect_map)(void *bpf_map, __u32 iface_index,
                               __u64 flags) = (void *)51;

struct bpf_map_def {
  unsigned int type;
  unsigned int key_size;
  unsigned int value_size;
  unsigned int max_entries;
  unsigned int map_flags;
};

// A map of devices to redirect to. We only ever use one key: 0.
struct bpf_map_def section("maps") dev_map = {
    .type = BPF_MAP_TYPE_DEVMAP,
    .key_size = sizeof(int),
    .value_size = sizeof(int),
    .max_entries = 1,
};

// In the egress path, all traffic is redirected out the other NIC.
// TODO(b/240191988): We can probably replace rx_queue_index with 0.
section("xdp") int xdp_prog(struct xdp_md *ctx) {
  int *dev;
  int key = 0;

  const char fmt1[] = "found device %d";
  const char fmt2[] = "failed to find device";

  const char fmt12[] = "got packet with size %u";
  bpf_trace_printk(fmt12, sizeof(fmt12), ctx->data_end - ctx->data);

  dev = bpf_map_lookup_elem(&dev_map, &key);
  if (dev) {
    bpf_trace_printk(fmt1, sizeof(fmt1), *dev);
  } else {
    bpf_trace_printk(fmt2, sizeof(fmt2));
  }

  // Redirect everything to the other device.
  return bpf_redirect_map(&dev_map, ctx->rx_queue_index, XDP_DROP);
}

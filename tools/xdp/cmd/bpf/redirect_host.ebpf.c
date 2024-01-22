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

// clang-format off
// Contains types needed by later headers.
#include <linux/types.h>
// clang-format on
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#define section(secname) __attribute__((section(secname), used))

char __license[] section("license") = "Apache-2.0";

// Note: bpf_helpers.h includes a struct definition for bpf_map_def in some, but
// not all, environments. Define our own equivalent struct to avoid issues with
// multiple declarations.
struct gvisor_bpf_map_def {
  unsigned int type;
  unsigned int key_size;
  unsigned int value_size;
  unsigned int max_entries;
  unsigned int map_flags;
};

struct gvisor_bpf_map_def section("maps") sock_map = {
    .type = BPF_MAP_TYPE_XSKMAP,  // Note: "XSK" means AF_XDP socket.
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u32),
    .max_entries = 1,
};

// Redirect almost all incoming traffic to an AF_XDP socket. Certain packets are
// allowed through to the Linux network stack:
//
//   - SSH (IPv4 TCP port 22) traffic.
//   - Some obviously broken packets.
section("xdp") int xdp_prog(struct xdp_md *ctx) {
  void *cursor = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;

  // Ensure there's space for an ethernet header.
  struct ethhdr *eth = cursor;
  if ((void *)(eth + 1) > data_end) {
    return XDP_PASS;
  }
  cursor += sizeof(*eth);

  // Send all non-IPv4 traffic to the socket.
  if (eth->h_proto != bpf_htons(ETH_P_IP)) {
    return bpf_redirect_map(&sock_map, ctx->rx_queue_index, XDP_PASS);
  }

  // IP packets get inspected to allow SSH traffic to the host.
  struct iphdr *ip = cursor;
  if ((void *)(ip + 1) > data_end) {
    return XDP_PASS;
  }
  cursor += sizeof(*ip);

  if (ip->protocol != IPPROTO_TCP) {
    return bpf_redirect_map(&sock_map, ctx->rx_queue_index, XDP_PASS);
  }
  struct tcphdr *tcp = cursor;
  if ((void *)(tcp + 1) > data_end) {
    return XDP_PASS;
  }

  // Allow port 22 traffic for SSH debugging.
  if (tcp->th_dport == bpf_htons(22)) {
    return XDP_PASS;
  }

  return bpf_redirect_map(&sock_map, ctx->rx_queue_index, XDP_PASS);
}

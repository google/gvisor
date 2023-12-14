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

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <netinet/tcp.h>

#define section(secname) __attribute__((section(secname), used))

char __license[] section("license") = "Apache-2.0";

// Helper functions are defined positionally in <linux/bpf.h>, and their
// signatures are scattered throughout the kernel. They can be found via the
// defining macro BPF_CALL_[0-5].
// TODO(b/240191988): Use vmlinux instead of this.
static int (*bpf_redirect_map)(void *bpf_map, __u32 iface_index,
                               __u64 flags) = (void *)51;

struct bpf_map_def {
  unsigned int type;
  unsigned int key_size;
  unsigned int value_size;
  unsigned int max_entries;
  unsigned int map_flags;
};

struct bpf_map_def section("maps") sock_map = {
    .type = BPF_MAP_TYPE_XSKMAP,  // Note: "XSK" means AF_XDP socket.
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u32),
    .max_entries = 1,
};

// TODO(b/240191988): It would be better to use bfp_htons() in
// <bpf/bpf_endian.h>. However, we test on ARM64 and AMD64 with the same Docker
// image, and each architecture requires different packages to get that header.
const __u16 swapped_eth_p_ip = (__u16)((ETH_P_IP << 8) | (ETH_P_IP >> 8));

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
  if (eth->h_proto != swapped_eth_p_ip) {
    return bpf_redirect_map(&sock_map, ctx->rx_queue_index, XDP_PASS);
  }

  // IP packets get inspected to allow SSH traffic to the host.
  struct iphdr *ip = cursor;
  if ((void *)(ip + 1) > data_end) {
    return XDP_PASS;
  }
  cursor += sizeof(*ip);

  // TODO(b/240191988): It would be better to use IPPROTO_TCP in <netinet/in.h>.
  // However, we test on ARM64 and AMD64 with the same Docker image, and each
  // architecture requires different packages to get that header.
  if (ip->protocol != 6 /* IPPROTO_TCP */) {
    return bpf_redirect_map(&sock_map, ctx->rx_queue_index, XDP_PASS);
  }
  struct tcphdr *tcp = cursor;
  if ((void *)(tcp + 1) > data_end) {
    return XDP_PASS;
  }

  // Allow port 22 traffic for SSH debugging.
  // TODO(b/240191988): It would be better to use bfp_ntohs() in
  // <bpf/bpf_endian.h>. However, we test on ARM64 and AMD64 with the same
  // Docker image, and each architecture requires different packages to get that
  // header.
  if (__builtin_bswap16(tcp->th_dport) == 22) {
    return XDP_PASS;
  }

  return bpf_redirect_map(&sock_map, ctx->rx_queue_index, XDP_PASS);
}

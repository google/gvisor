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

// TODO:
// - There's no need to "bounce". This wasn't working because, I think, my NIC
//   just doesn't support XDP. So redirecting to it did nothing.
//   - Specifically: my NIC is using the e100e driver, which does not support
//     XDP. It does not implement ndo_xdp_xmit, so packets redirected to it were
//     immediately dropped. You could see this in the veth ethtool stats.
// - On my test client (a Mac), you run the following for ARP. Currently we
//   receive the packets, but the sent packets are (as described above) dropped.
//
//     sudo /Users/krakauer/homebrew/sbin/arping -i en0 172.17.0.2
//

#define section(secname) __attribute__((section(secname), used))

#define DEFAULT_ACTION XDP_PASS
#define HTONS_ETH_P_IP 0x8     // This is htons(ETH_P_IP).
#define HTONS_ETH_P_ARP 0x608  // This is htons(ETH_P_ARP).

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

// A map of destination IP addresses that should be redirected. We only ever use
// one key: 0.
struct bpf_map_def section("maps") ip_map = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(int),
    .value_size = sizeof(__u32),
    .max_entries = 1,
};

// An IPv4 ARP header.
struct arphdr_inet {
  struct arphdr arp_hdr;  // 8 bytes long.
  unsigned char sender_hw_addr[ETH_ALEN];
  unsigned char sender_ip_addr[4];  // *Not* 4-byte aligned. 2-byte aligned.
  unsigned char target_hw_addr[ETH_ALEN];
  unsigned char target_ip_addr[4];  // 4-byte aligned.
};

// In the ingress path, only packets meant for the container are redirected to
// the veth.
// TODO(b/240191988): A production version of this program should be heavily
// optimized to maximize throughput.
section("xdp") int xdp_prog(struct xdp_md *ctx) {
  /* const char fmt1[] = "got IPv4 packet with destination address: %u.%u.%u.";
   */
  const char fmt2[] = "%u\n";
  /* /1* unsigned char *dst_byte_ptr; *1/ */

  /* /1* const char fmt3[] = "found IP in map: %u.%u.%u."; *1/ */
  /* /1* const char fmt4[] = "redirecting!\n"; *1/ */

  const char fmt5[] = "redirecting packet with destination address: %u.%u.%u.";
  /* const char fmt6[] = "TXing packet with source address: %u.%u.%u."; */
  unsigned char *addr_ptr;

  const char fmt7[] = "got ARP packet with size %u";
  const char fmt8[] = "ARP packet has good size";
  const char fmt9[] = "ARP packet is for IPv4";
  const char fmt10[] = "ARP packet has source %u.%u.%u";
  const char fmt11[] = "ARP packet has destination %u.%u.%u";

  const char fmt12[] = "got SOME packet with size %u";

  int key = 0;
  void *end = (void *)(uint64_t)ctx->data_end;
  struct ethhdr *eth_hdr = (struct ethhdr *)(uint64_t)ctx->data;
  struct iphdr *ip_hdr;
  struct arphdr_inet *arp_hdr;
  __u32 src_addr;  // TODO: remove
  __u32 dst_addr;
  __u32 *map_addr;

  /* if (ctx->data_end - ctx->data == 42) { */
  bpf_trace_printk(fmt12, sizeof(fmt12), ctx->data_end - ctx->data);
  /* } */

  if (eth_hdr + 1 > (struct ethhdr *)end) {
    return DEFAULT_ACTION;
  }

  switch (eth_hdr->h_proto) {
    case HTONS_ETH_P_IP:
      ip_hdr = (struct iphdr *)(eth_hdr + 1);
      if (ip_hdr + 1 > (struct iphdr *)end) {
        return DEFAULT_ACTION;
      }
      src_addr = ip_hdr->saddr;
      dst_addr = ip_hdr->daddr;
      break;

    case HTONS_ETH_P_ARP:
      bpf_trace_printk(fmt7, sizeof(fmt7), ctx->data_end - ctx->data);
      arp_hdr = (struct arphdr_inet *)(eth_hdr + 1);
      if (arp_hdr + 1 > (struct arphdr_inet *)end) {
        return DEFAULT_ACTION;
      }
      bpf_trace_printk(fmt8, sizeof(fmt8));
      // Only allow IPv4 ARP.
      if (arp_hdr->arp_hdr.ar_pro != HTONS_ETH_P_IP) {
        return DEFAULT_ACTION;
      }
      src_addr = *(uint32_t *)&arp_hdr->sender_ip_addr;  // TODO: Unaligned.
      dst_addr = *(uint32_t *)&arp_hdr->target_ip_addr;
      bpf_trace_printk(fmt9, sizeof(fmt9));
      addr_ptr = (unsigned char *)&src_addr;
      bpf_trace_printk(fmt10, sizeof(fmt10), addr_ptr[0], addr_ptr[1],
                       addr_ptr[2]);
      bpf_trace_printk(fmt2, sizeof(fmt2), addr_ptr[3]);
      addr_ptr = (unsigned char *)&dst_addr;
      bpf_trace_printk(fmt11, sizeof(fmt11), addr_ptr[0], addr_ptr[1],
                       addr_ptr[2]);
      bpf_trace_printk(fmt2, sizeof(fmt2), addr_ptr[3]);
      break;

    default:
      return DEFAULT_ACTION;
  }

  // Get the selected IP.
  map_addr = bpf_map_lookup_elem(&ip_map, &key);
  if (!map_addr) {
    return DEFAULT_ACTION;
  }

  /* // Bounce the packet back out if the packet is from the container (and was
   */
  /* // redirected here by the other BPF program). */
  /* if (*map_addr == src_addr) { */
  /*   addr_ptr = (unsigned char *)&src_addr; */
  /*   bpf_trace_printk(fmt6, sizeof(fmt6), addr_ptr[0], addr_ptr[1],
   * addr_ptr[2]); */
  /*   bpf_trace_printk(fmt2, sizeof(fmt2), addr_ptr[3]); */
  /*   return XDP_TX; */
  /* } */

  // Redirect if this packet is destined for the container.
  if (*map_addr == dst_addr) {
    addr_ptr = (unsigned char *)&dst_addr;
    bpf_trace_printk(fmt5, sizeof(fmt5), addr_ptr[0], addr_ptr[1], addr_ptr[2]);
    bpf_trace_printk(fmt2, sizeof(fmt2), addr_ptr[3]);
    return bpf_redirect_map(&dev_map, key, XDP_DROP);
  }

  return DEFAULT_ACTION;
}

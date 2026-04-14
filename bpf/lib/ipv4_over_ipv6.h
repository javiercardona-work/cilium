/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#ifndef __LIB_IPV4_OVER_IPV6_H_
#define __LIB_IPV4_OVER_IPV6_H_

#include "common.h"
#include "ipv6.h"

/* BPF map: destination IPv4 prefix → node IPv6 address.
 * Populated by the Cilium agent from remote node podCIDRs and per-node IPv4
 * service addresses. Lookups use a /32 destination key so the trie returns
 * the most specific matching prefix.
 * For testing, populated via cilium-dbg bpf endpoint/map commands.
 */
struct ipv4_over_ipv6_key {
	struct bpf_lpm_trie_key lpm;
	__u8 addr[4];
};

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__type(key, struct ipv4_over_ipv6_key); /* destination IPv4 prefix */
	__type(value, union v6addr);	/* node IPv6 /128 address */
	__uint(max_entries, 16384);
	/* Keep trie allocation flags aligned with the userspace map spec so
	 * the datapath loader and syncer reuse the same pinned map instance.
	 */
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} cilium_ipv4_over_ipv6_nodes __section_maps_btf;

static __always_inline bool
ipv4_over_ipv6_lookup_node(__be32 dst_v4, union v6addr *node_v6)
{
	struct ipv4_over_ipv6_key key = {
		.lpm = { 32, {} },
	};
	union v6addr *val;

	memcpy(key.addr, &dst_v4, sizeof(dst_v4));
	val = map_lookup_elem(&cilium_ipv4_over_ipv6_nodes, &key);
	if (val) {
		*node_v6 = *val;
		return true;
	}
	return false;
}

#endif /* __LIB_IPV4_OVER_IPV6_H_ */

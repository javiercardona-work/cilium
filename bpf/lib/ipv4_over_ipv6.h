/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#ifndef __LIB_IPV4_OVER_IPV6_H_
#define __LIB_IPV4_OVER_IPV6_H_

#include "common.h"
#include "ipv6.h"

/* BPF map: tunnel endpoint IPv4 → node IPv6 address.
 * Populated by the Cilium agent from CiliumNode objects.
 * For testing, populated via cilium-dbg bpf endpoint/map commands.
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __be32);		/* tunnel endpoint IPv4 */
	__type(value, union v6addr);	/* node IPv6 /128 address */
	__uint(max_entries, 1024);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} cilium_ipv4_over_ipv6_nodes __section_maps_btf;

static __always_inline bool
ipv4_over_ipv6_lookup_node(__be32 tunnel_ep_v4, union v6addr *node_v6)
{
	union v6addr *val;

	val = map_lookup_elem(&cilium_ipv4_over_ipv6_nodes, &tunnel_ep_v4);
	if (val) {
		*node_v6 = *val;
		return true;
	}
	return false;
}

#endif /* __LIB_IPV4_OVER_IPV6_H_ */

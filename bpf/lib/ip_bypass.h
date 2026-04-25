/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#ifndef __LIB_IP_BYPASS_H_
#define __LIB_IP_BYPASS_H_

#include "common.h"
#include "ipv6.h"
#include "ipfrag.h"
#include "l4.h"
#include "lb.h"

#ifdef ENABLE_IP_BYPASS

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, union v6addr);
	__type(value, __u8);
	__uint(max_entries, 256);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} cilium_bypass_ips __section_maps_btf;

/* Check if an IPv6 packet's address is in the bypass map.
 * For egress (to-netdev): checks source address.
 * For ingress (from-netdev): checks destination address and ensures the
 *   destination port is NOT in the NodePort range (30000-32767), so that
 *   Cilium can still handle NodePort DNAT.
 */
static __always_inline bool
ip_bypass_check(struct __ctx_buff *ctx, bool is_egress)
{
	union v6addr addr;
	int ret;

	if (is_egress)
		ret = ipv6_load_saddr(ctx, ETH_HLEN, &addr);
	else
		ret = ipv6_load_daddr(ctx, ETH_HLEN, &addr);

	if (ret < 0)
		return false;

	if (!map_lookup_elem(&cilium_bypass_ips, &addr))
		return false;

	if (is_egress)
		return true;

	/* On ingress, let NodePort traffic through to Cilium for DNAT.
	 * Use fragment-safe header parsing to handle IPv6 fragments correctly.
	 */
	{
		__u8 nexthdr = 0;
		fraginfo_t fraginfo = 0;

		ret = ipv6_hdrlen_with_fraginfo(ctx, &nexthdr, &fraginfo);
		if (ret < 0)
			return false;

		if (lb_is_svc_proto(nexthdr)) {
			__be16 dport = 0;
			int l4_off = ETH_HLEN + ret;

			if (!ipfrag_has_l4_header(fraginfo))
				return false;

			if (l4_load_port(ctx, l4_off + UDP_DPORT_OFF, &dport) < 0)
				return false;

			if (bpf_ntohs(dport) >= NODEPORT_PORT_MIN &&
			    bpf_ntohs(dport) <= NODEPORT_PORT_MAX)
				return false;
		}
	}

	return true;
}

#endif /* ENABLE_IP_BYPASS */
#endif /* __LIB_IP_BYPASS_H_ */

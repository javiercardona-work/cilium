// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

/*
 * Unit tests for the IP bypass map feature in bpf_host.c.
 * Verifies that packets with source/destination IPs in the
 * cilium_bypass_ips map are passed through without Cilium processing.
 */

#include <bpf/ctx/skb.h>
#include "common.h"
#include "pktgen.h"
#include <node_config.h>

#include <lib/common.h>
#include <lib/ipv6.h>

/* Define the bypass map (same definition as in bpf_host.c) */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, union v6addr);
	__type(value, __u8);
	__uint(max_entries, 256);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} cilium_bypass_ips __section_maps_btf;

/* Re-declare the inline function under test */
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

	return map_lookup_elem(&cilium_bypass_ips, &addr) != NULL;
}

/* Test addresses */
static __u8 bypass_ip[] = {0x28, 0x03, 0x60, 0x86, 0x59, 0x91, 0x3c, 0x46,
			    0x8a, 0x38, 0xe9, 0xee, 0x14, 0x75, 0x0a, 0x00};
static __u8 normal_ip[] = {0x28, 0x03, 0x60, 0x86, 0x59, 0x91, 0x3c, 0x46,
			   0x8a, 0x38, 0xe9, 0xee, 0x14, 0x75, 0x0b, 0x00};
static __u8 other_ip[]  = {0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};

static __u8 mac_one[] = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x11};
static __u8 mac_two[] = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x22};

/* Test 1: Egress — source IP IS in bypass map → should bypass */
PKTGEN("tc", "ip_bypass_egress_match")
int test_egress_match_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct ipv6hdr *l3;

	pktgen__init(&builder, ctx);

	/* bypass_ip as source, other_ip as dest */
	l3 = pktgen__push_ipv6_packet(&builder, mac_one, mac_two,
				       bypass_ip, other_ip);
	if (!l3)
		return TEST_ERROR;

	pktgen__finish(&builder);
	return 0;
}

SETUP("tc", "ip_bypass_egress_match")
int test_egress_match_setup(struct __ctx_buff *ctx __maybe_unused)
{
	__u8 val = 1;

	/* Insert bypass_ip into the map */
	map_update_elem(&cilium_bypass_ips, bypass_ip, &val, BPF_ANY);
	return 0;
}

CHECK("tc", "ip_bypass_egress_match")
int test_egress_match_check(struct __ctx_buff *ctx)
{
	test_init();

	assert(ip_bypass_check(ctx, true));

	test_finish();
}

/* Test 2: Egress — source IP is NOT in bypass map → should not bypass */
PKTGEN("tc", "ip_bypass_egress_no_match")
int test_egress_no_match_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct ipv6hdr *l3;

	pktgen__init(&builder, ctx);

	/* normal_ip as source, other_ip as dest */
	l3 = pktgen__push_ipv6_packet(&builder, mac_one, mac_two,
				       normal_ip, other_ip);
	if (!l3)
		return TEST_ERROR;

	pktgen__finish(&builder);
	return 0;
}

CHECK("tc", "ip_bypass_egress_no_match")
int test_egress_no_match_check(struct __ctx_buff *ctx)
{
	test_init();

	assert(!ip_bypass_check(ctx, true));

	test_finish();
}

/* Test 3: Ingress — dest IP IS in bypass map → should bypass */
PKTGEN("tc", "ip_bypass_ingress_match")
int test_ingress_match_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct ipv6hdr *l3;

	pktgen__init(&builder, ctx);

	/* other_ip as source, bypass_ip as dest */
	l3 = pktgen__push_ipv6_packet(&builder, mac_one, mac_two,
				       other_ip, bypass_ip);
	if (!l3)
		return TEST_ERROR;

	pktgen__finish(&builder);
	return 0;
}

SETUP("tc", "ip_bypass_ingress_match")
int test_ingress_match_setup(struct __ctx_buff *ctx __maybe_unused)
{
	__u8 val = 1;

	map_update_elem(&cilium_bypass_ips, bypass_ip, &val, BPF_ANY);
	return 0;
}

CHECK("tc", "ip_bypass_ingress_match")
int test_ingress_match_check(struct __ctx_buff *ctx)
{
	test_init();

	/* is_egress=false → checks dest IP */
	assert(ip_bypass_check(ctx, false));

	test_finish();
}

/* Test 4: Ingress — dest IP is NOT in bypass map → should not bypass */
PKTGEN("tc", "ip_bypass_ingress_no_match")
int test_ingress_no_match_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct ipv6hdr *l3;

	pktgen__init(&builder, ctx);

	/* other_ip as source, normal_ip as dest */
	l3 = pktgen__push_ipv6_packet(&builder, mac_one, mac_two,
				       other_ip, normal_ip);
	if (!l3)
		return TEST_ERROR;

	pktgen__finish(&builder);
	return 0;
}

CHECK("tc", "ip_bypass_ingress_no_match")
int test_ingress_no_match_check(struct __ctx_buff *ctx)
{
	test_init();

	assert(!ip_bypass_check(ctx, false));

	test_finish();
}

/* Test 5: Empty map — no IPs bypass */
PKTGEN("tc", "ip_bypass_empty_map")
int test_empty_map_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct ipv6hdr *l3;

	pktgen__init(&builder, ctx);

	l3 = pktgen__push_ipv6_packet(&builder, mac_one, mac_two,
				       bypass_ip, bypass_ip);
	if (!l3)
		return TEST_ERROR;

	pktgen__finish(&builder);
	return 0;
}

CHECK("tc", "ip_bypass_empty_map")
int test_empty_map_check(struct __ctx_buff *ctx)
{
	test_init();

	/* Map has entries from previous tests but normal_ip was never added */
	assert(!ip_bypass_check(ctx, true) || !ip_bypass_check(ctx, false));

	test_finish();
}

BPF_LICENSE("Dual BSD/GPL");

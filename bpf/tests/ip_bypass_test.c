// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>
#include "common.h"
#include "pktgen.h"
#include <node_config.h>

#define ENABLE_IP_BYPASS	1
#define ENABLE_IPV6		1

#include <lib/ip_bypass.h>

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

/* Test 3: Ingress — dest IP in map, non-service port → should bypass */
PKTGEN("tc", "ip_bypass_ingress_match")
int test_ingress_match_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct udphdr *l4;

	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv6_udp_packet(&builder, mac_one, mac_two,
					    other_ip, bypass_ip,
					    bpf_htons(12345),
					    bpf_htons(8080));
	if (!l4)
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

	assert(ip_bypass_check(ctx, false));

	test_finish();
}

/* Test 4: Ingress — dest IP in map, NodePort range port → should NOT bypass */
PKTGEN("tc", "ip_bypass_ingress_nodeport")
int test_ingress_nodeport_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct udphdr *l4;

	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv6_udp_packet(&builder, mac_one, mac_two,
					    other_ip, bypass_ip,
					    bpf_htons(12345),
					    bpf_htons(NODEPORT_PORT_MIN));
	if (!l4)
		return TEST_ERROR;

	pktgen__finish(&builder);
	return 0;
}

SETUP("tc", "ip_bypass_ingress_nodeport")
int test_ingress_nodeport_setup(struct __ctx_buff *ctx __maybe_unused)
{
	__u8 val = 1;

	map_update_elem(&cilium_bypass_ips, bypass_ip, &val, BPF_ANY);
	return 0;
}

CHECK("tc", "ip_bypass_ingress_nodeport")
int test_ingress_nodeport_check(struct __ctx_buff *ctx)
{
	test_init();

	/* NodePort traffic must NOT be bypassed — Cilium needs to do DNAT */
	assert(!ip_bypass_check(ctx, false));

	test_finish();
}

/* Test 5: Ingress — dest IP in map, TCP NodePort → should NOT bypass */
PKTGEN("tc", "ip_bypass_ingress_nodeport_tcp")
int test_ingress_nodeport_tcp_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct tcphdr *l4;

	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv6_tcp_packet(&builder, mac_one, mac_two,
					    other_ip, bypass_ip,
					    bpf_htons(54321),
					    bpf_htons(NODEPORT_PORT_MAX));
	if (!l4)
		return TEST_ERROR;

	pktgen__finish(&builder);
	return 0;
}

SETUP("tc", "ip_bypass_ingress_nodeport_tcp")
int test_ingress_nodeport_tcp_setup(struct __ctx_buff *ctx __maybe_unused)
{
	__u8 val = 1;

	map_update_elem(&cilium_bypass_ips, bypass_ip, &val, BPF_ANY);
	return 0;
}

CHECK("tc", "ip_bypass_ingress_nodeport_tcp")
int test_ingress_nodeport_tcp_check(struct __ctx_buff *ctx)
{
	test_init();

	assert(!ip_bypass_check(ctx, false));

	test_finish();
}

/* Test 6: Ingress — dest IP is NOT in bypass map → should not bypass */
PKTGEN("tc", "ip_bypass_ingress_no_match")
int test_ingress_no_match_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct udphdr *l4;

	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv6_udp_packet(&builder, mac_one, mac_two,
					    other_ip, normal_ip,
					    bpf_htons(12345),
					    bpf_htons(8080));
	if (!l4)
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

BPF_LICENSE("Dual BSD/GPL");

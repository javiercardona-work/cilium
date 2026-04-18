// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>
#include "common.h"
#include "pktgen.h"

#define ENABLE_IPV4
#define ENABLE_NODEPORT
#define ENABLE_BPF_IPV4_OVER_IPV6
#define BPF_IPV4_OVER_IPV6_EXTERNAL_DECAP_MARK 0xbeef

#include "bpf_host.c"
#include "lib/endpoint.h"

#define SRC_MAC mac_one
#define ROUTER_MAC mac_three
#define POD_MAC mac_four

#define SRC_IPV4 v4_ext_one
#define DST_IPV4 v4_pod_one
#define SRC_PORT tcp_src_one
#define DST_PORT tcp_dst_one

static __always_inline int build_packet(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct tcphdr *l4;
	void *data;

	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv4_tcp_packet(&builder,
					  (__u8 *)SRC_MAC,
					  (__u8 *)ROUTER_MAC,
					  SRC_IPV4, DST_IPV4,
					  SRC_PORT, DST_PORT);
	if (!l4)
		return TEST_ERROR;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	pktgen__finish(&builder);
	return TEST_PASS;
}

static __always_inline int run_netdev_ipv4(struct __ctx_buff *ctx, bool marked)
{
	void *data, *data_end;
	struct iphdr *ip4;
	__u32 identity = UNKNOWN_ID;
	__u32 ipcache_srcid = 0;
	bool punt_to_stack = false;
	__s8 ext_err = 0;
	int ret;

	endpoint_v4_add_entry(DST_IPV4, 0, 100, 0, 0, 0,
			      (__u8 *)POD_MAC, (__u8 *)ROUTER_MAC);

	bpf_clear_meta(ctx);
	ctx_skip_nodeport_clear(ctx);
	ctx_store_meta(ctx, CB_FROM_TUNNEL, 0);
	ctx->mark = marked ? BPF_IPV4_OVER_IPV6_EXTERNAL_DECAP_MARK : 0;

	if (!revalidate_data_pull(ctx, &data, &data_end, &ip4))
		return TEST_ERROR;

	if (ipv4_over_ipv6_external_decap_marked(ctx))
		ipv4_over_ipv6_mark_external_decap(ctx);

	identity = resolve_srcid_ipv4(ctx, ip4, UNKNOWN_ID, &ipcache_srcid, false);
	ctx_store_meta(ctx, CB_SRC_LABEL, identity);

	ret = handle_ipv4(ctx, identity, ipcache_srcid, false, &punt_to_stack, &ext_err);
	if (ret != CTX_ACT_OK || punt_to_stack)
		return ret;

	return handle_ipv4_cont(ctx, identity, false, &ext_err);
}

PKTGEN("tc", "01_unmarked_ipv4")
int external_decap_unmarked_pktgen(struct __ctx_buff *ctx)
{
	return build_packet(ctx);
}

SETUP("tc", "01_unmarked_ipv4")
int external_decap_unmarked_setup(struct __ctx_buff *ctx)
{
	return run_netdev_ipv4(ctx, false);
}

CHECK("tc", "01_unmarked_ipv4")
int external_decap_unmarked_check(struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__s32 *status_code;
	struct tcphdr *l4;
	struct ethhdr *l2;
	struct iphdr *l3;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;
	if (*status_code != CTX_ACT_OK)
		test_fatal("unexpected status code %d, want %d",
			   *status_code, CTX_ACT_OK);

	l2 = data + sizeof(__u32);
	if ((void *)l2 + sizeof(struct ethhdr) > data_end)
		test_fatal("l2 out of bounds");

	l3 = (void *)l2 + sizeof(struct ethhdr);
	if ((void *)l3 + sizeof(struct iphdr) > data_end)
		test_fatal("l3 out of bounds");

	l4 = (void *)l3 + sizeof(struct iphdr);
	if ((void *)l4 + sizeof(struct tcphdr) > data_end)
		test_fatal("l4 out of bounds");

	if (memcmp(l2->h_source, (__u8 *)SRC_MAC, ETH_ALEN) != 0)
		test_fatal("unexpected source MAC");

	if (memcmp(l2->h_dest, (__u8 *)ROUTER_MAC, ETH_ALEN) != 0)
		test_fatal("unexpected destination MAC");

	if (l2->h_proto != bpf_htons(ETH_P_IP))
		test_fatal("unexpected l2 protocol");

	if (l3->saddr != SRC_IPV4)
		test_fatal("unexpected source IPv4");

	if (l3->daddr != DST_IPV4)
		test_fatal("unexpected destination IPv4");

	if (l4->source != SRC_PORT)
		test_fatal("unexpected TCP source port");

	if (l4->dest != DST_PORT)
		test_fatal("unexpected TCP destination port");

	if (ctx_load_meta(ctx, CB_DELIVERY_REDIRECT) != 0)
		test_fatal("unexpected delivery redirect metadata");

	if (ctx_load_meta(ctx, CB_FROM_TUNNEL) != 0)
		test_fatal("unexpected from-tunnel metadata");

	test_finish();
}

PKTGEN("tc", "02_marked_ipv4")
int external_decap_marked_pktgen(struct __ctx_buff *ctx)
{
	return build_packet(ctx);
}

SETUP("tc", "02_marked_ipv4")
int external_decap_marked_setup(struct __ctx_buff *ctx)
{
	return run_netdev_ipv4(ctx, true);
}

CHECK("tc", "02_marked_ipv4")
int external_decap_marked_check(struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__s32 *status_code;
	struct tcphdr *l4;
	struct ethhdr *l2;
	struct iphdr *l3;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;
	if (*status_code != DROP_EP_NOT_READY)
		test_fatal("unexpected status code %d, want %d",
			   *status_code, DROP_EP_NOT_READY);

	l2 = data + sizeof(__u32);
	if ((void *)l2 + sizeof(struct ethhdr) > data_end)
		test_fatal("l2 out of bounds");

	l3 = (void *)l2 + sizeof(struct ethhdr);
	if ((void *)l3 + sizeof(struct iphdr) > data_end)
		test_fatal("l3 out of bounds");

	l4 = (void *)l3 + sizeof(struct iphdr);
	if ((void *)l4 + sizeof(struct tcphdr) > data_end)
		test_fatal("l4 out of bounds");

	if (memcmp(l2->h_source, (__u8 *)ROUTER_MAC, ETH_ALEN) != 0)
		test_fatal("unexpected source MAC");

	if (memcmp(l2->h_dest, (__u8 *)POD_MAC, ETH_ALEN) != 0)
		test_fatal("unexpected destination MAC");

	if (l2->h_proto != bpf_htons(ETH_P_IP))
		test_fatal("unexpected l2 protocol");

	if (l3->saddr != SRC_IPV4)
		test_fatal("unexpected source IPv4");

	if (l3->daddr != DST_IPV4)
		test_fatal("unexpected destination IPv4");

	if (l4->source != SRC_PORT)
		test_fatal("unexpected TCP source port");

	if (l4->dest != DST_PORT)
		test_fatal("unexpected TCP destination port");

	if (ctx_load_meta(ctx, CB_DELIVERY_REDIRECT) != 1)
		test_fatal("expected delivery redirect metadata");

	if (ctx_load_meta(ctx, CB_FROM_TUNNEL) != 1)
		test_fatal("expected from-tunnel metadata");

	if (ctx_load_meta(ctx, CB_FROM_HOST) != 0)
		test_fatal("unexpected from-host metadata");

	if (ctx_load_meta(ctx, CB_CLUSTER_ID_INGRESS) != 0)
		test_fatal("unexpected cluster-id metadata");

	test_finish();
}

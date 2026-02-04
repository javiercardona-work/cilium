/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include <bpf/api.h>

/* Events ring buffer size - 8MB for events with packet capture data.
 * Events include packet capture data (128-192 bytes per event) and
 * high-throughput environments can generate many events.
 */
#define EVENTS_RINGBUF_SIZE (8 * 1024 * 1024)

/* Maximum packet capture length for ringbuf events */
#define MAX_CAPTURE_LEN 256

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, EVENTS_RINGBUF_SIZE);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} cilium_events __section_maps_btf;

/*
 * send_event sends an event to the cilium_events ringbuf.
 * Note: With ringbuf, packet capture is not currently supported due to
 * verifier constraints on dynamic sizes. Only the message header is sent.
 * The cap_len parameter is accepted for API compatibility but ignored.
 *
 * @ctx: packet context (skb or xdp) - unused with ringbuf
 * @msg: pointer to message struct
 * @msg_len: size of message struct
 * @cap_len: ignored (kept for API compatibility)
 */
#define send_event(ctx, msg, msg_len, cap_len) \
	ringbuf_output(&cilium_events, msg, msg_len, 0)

/*
 * send_event_simple sends an event without packet capture (e.g., debug messages).
 * For socket context events that don't have packet data.
 */
#define send_event_simple(msg, msg_len) \
	ringbuf_output(&cilium_events, msg, msg_len, 0)

#ifdef EVENTS_MAP_RATE_LIMIT
#ifndef EVENTS_MAP_BURST_LIMIT
#define EVENTS_MAP_BURST_LIMIT EVENTS_MAP_RATE_LIMIT
#endif
#endif


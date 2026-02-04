/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include <bpf/api.h>

/* Events ring buffer size - 8MB for events with packet capture data.
 * Events include packet capture data (128-192 bytes per event) and
 * high-throughput environments can generate many events.
 */
#define EVENTS_RINGBUF_SIZE (8 * 1024 * 1024)

/* Maximum notify struct size - covers trace_notify, drop_notify, etc.
 * trace_notify is the largest at ~72 bytes, we use 64 for alignment.
 */
#define NOTIFY_MAX_SIZE 64

/* Maximum packet capture length for ringbuf events.
 * This is the maximum amount of packet data appended after the notify header.
 * Using 192 to make total size a power of 2 (64 + 192 = 256).
 */
#define MAX_CAPTURE_LEN 192

/* Total fixed size for ringbuf reservation.
 * Must be a power of 2 for efficient memset.
 */
#define RINGBUF_ENTRY_SIZE 256

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, EVENTS_RINGBUF_SIZE);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} cilium_events __section_maps_btf;

/*
 * __copy_notify_header copies the notify struct to the ringbuf entry.
 * Uses a switch on common sizes to provide constant-size memcpy operations
 * that the verifier can handle.
 */
static __always_inline void
__copy_notify_header(void *dst, const void *src, __u64 len)
{
	/* Use explicit size cases for verifier - these are compile-time constants */
	switch (len) {
	case 24:
		memcpy(dst, src, 24);
		break;
	case 32:
		memcpy(dst, src, 32);
		break;
	case 40:
		memcpy(dst, src, 40);
		break;
	case 48:
		memcpy(dst, src, 48);
		break;
	case 56:
		memcpy(dst, src, 56);
		break;
	case 64:
		memcpy(dst, src, 64);
		break;
	case 72:
		memcpy(dst, src, 72);
		break;
	case 80:
		memcpy(dst, src, 80);
		break;
	default:
		/* Fallback: copy up to max size */
		if (len <= NOTIFY_MAX_SIZE)
			memcpy(dst, src, NOTIFY_MAX_SIZE);
		break;
	}
}

/*
 * __send_event_capture sends an event with packet capture to the ringbuf.
 * Reserves a fixed-size entry, copies the notify header and packet data,
 * then submits to the ringbuf.
 *
 * @ctx: packet context (skb or xdp) for reading packet data
 * @msg: pointer to notify struct
 * @msg_len: size of notify struct (should be sizeof(struct xxx_notify))
 * @cap_len: bytes of packet data to capture (clamped to MAX_CAPTURE_LEN)
 */
static __always_inline int
__send_event_capture(struct __ctx_buff *ctx, const void *msg, __u64 msg_len, __u64 cap_len)
{
	void *entry;

	/* Reserve fixed size in ringbuf - verifier requires constant size */
	entry = ringbuf_reserve(&cilium_events, RINGBUF_ENTRY_SIZE, 0);
	if (!entry)
		return -1;

	/* Clamp sizes to our limits */
	if (msg_len > NOTIFY_MAX_SIZE)
		msg_len = NOTIFY_MAX_SIZE;
	if (cap_len > MAX_CAPTURE_LEN)
		cap_len = MAX_CAPTURE_LEN;

	/* Copy notify header */
	__copy_notify_header(entry, msg, msg_len);

	/* Copy packet data if requested */
	if (cap_len > 0) {
		/* ctx_load_bytes copies from packet to our buffer */
		if (ctx_load_bytes(ctx, 0, entry + msg_len, (__u32)cap_len) < 0) {
			/* Failed to load packet data, submit without it */
			cap_len = 0;
		}
	}

	ringbuf_submit(entry, 0);
	return 0;
}

/*
 * send_event sends an event to the cilium_events ringbuf with optional
 * packet capture data appended after the notify header.
 *
 * @ctx: packet context (skb or xdp)
 * @msg: pointer to notify struct
 * @msg_len: size of notify struct
 * @cap_len: bytes of packet data to capture
 */
#define send_event(ctx, msg, msg_len, cap_len) \
	__send_event_capture(ctx, msg, msg_len, cap_len)

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

/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include <bpf/api.h>

/* Use an 8 MiB ring buffer for events and packet data. */
#define EVENTS_RINGBUF_SIZE (8 * 1024 * 1024)

/* The largest notification must fit in this size. */
#define NOTIFY_MAX_SIZE 64

/* Limit the packet data so one record fits in RINGBUF_ENTRY_SIZE. */
#define MAX_CAPTURE_LEN 192

/* Use a fixed record size because the verifier requires a constant size. */
#define RINGBUF_ENTRY_SIZE 256

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, EVENTS_RINGBUF_SIZE);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} cilium_events __section_maps_btf;

/* XDP packet copies require a constant length on kernels without
 * BPF_FUNC_xdp_load_bytes. Send the notification without packet data.
 */
#if __ctx_is == __ctx_xdp
#define send_event(ctx, msg, msg_len, cap_len) ({				\
	(msg)->len_cap = 0;						\
	ringbuf_output(&cilium_events, msg, msg_len, 0);			\
})
#else
/* Send one notification and its packet data to the ring buffer.
 * Keep msg_len constant so the BPF compiler can expand memcpy.
 */
#define send_event(ctx, msg, msg_len, cap_len) ({				\
	void *__event_entry;						\
	__u64 __event_cap_len = (cap_len);				\
	int __event_ret = -1;						\
	_Static_assert((msg_len) <= NOTIFY_MAX_SIZE,			\
		       "event notification is too large");			\
	if (__event_cap_len > MAX_CAPTURE_LEN)				\
		__event_cap_len = MAX_CAPTURE_LEN;			\
	__event_entry = ringbuf_reserve(&cilium_events,			\
					RINGBUF_ENTRY_SIZE, 0);		\
	if (__event_entry) {						\
		memset(__event_entry, 0, RINGBUF_ENTRY_SIZE / 2);		\
		memset(__event_entry + RINGBUF_ENTRY_SIZE / 2, 0,	\
		       RINGBUF_ENTRY_SIZE / 2);				\
		memcpy(__event_entry, (msg), (msg_len));			\
		if (__event_cap_len > 0 &&				\
		    ctx_load_bytes((ctx), 0, __event_entry + (msg_len),	\
				   (__u32)__event_cap_len) < 0) {	\
			ringbuf_discard(__event_entry, 0);			\
		} else {							\
			ringbuf_submit(__event_entry, 0);			\
			__event_ret = 0;					\
		}							\
	}								\
	__event_ret;							\
})
#endif

/* Send one notification without packet data. */
#define send_event_simple(msg, msg_len) \
	ringbuf_output(&cilium_events, msg, msg_len, 0)

#ifdef EVENTS_MAP_RATE_LIMIT
#ifndef EVENTS_MAP_BURST_LIMIT
#define EVENTS_MAP_BURST_LIMIT EVENTS_MAP_RATE_LIMIT
#endif
#endif

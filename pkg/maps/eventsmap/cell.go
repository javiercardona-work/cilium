// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package eventsmap

import (
	"log/slog"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/bpf"
)

// Cell provides the Cilium events ring buffer map.
var Cell = cell.Module(
	"events-map",
	"eBPF ring buffer of cilium events",

	cell.Provide(newEventsMap),
)

// RingBufReader reads records from a BPF ring buffer.
type RingBufReader interface {
	Read() (ringbuf.Record, error)
	Close() error
}

type Map interface {
	NewReader() (RingBufReader, error)
	MapName() string
	EbpfMap() *ebpf.Map
}

func newEventsMap(lifecycle cell.Lifecycle, logger *slog.Logger) bpf.MapOut[Map] {
	eventsMap := initMap(logger)

	lifecycle.Append(cell.Hook{
		OnStart: func(startCtx cell.HookContext) error {
			return eventsMap.open()
		},
		OnStop: func(stopCtx cell.HookContext) error {
			return eventsMap.close()
		},
	})

	return bpf.NewMapOut(Map(eventsMap))
}

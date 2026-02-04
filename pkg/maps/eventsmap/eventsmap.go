// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package eventsmap

import (
	"errors"
	"fmt"
	"log/slog"
	"os"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"

	"github.com/cilium/cilium/pkg/bpf"
)

const (
	// MapName is the BPF map name.
	MapName = "cilium_events"

	// ringBufSize must match EVENTS_RINGBUF_SIZE in bpf/lib/events.h
	ringBufSize = 8 * 1024 * 1024
)

// Key is the index into the prog array map.
type Key struct {
	index uint32
}

// Value is the program ID in the prog array map.
type Value struct {
	progID uint32
}

// String converts the key into a human readable string format.
func (k *Key) String() string  { return fmt.Sprintf("%d", k.index) }
func (k *Key) New() bpf.MapKey { return &Key{} }

// String converts the value into a human readable string format.
func (v *Value) String() string    { return fmt.Sprintf("%d", v.progID) }
func (v *Value) New() bpf.MapValue { return &Value{} }

type eventsMap struct {
	logger  *slog.Logger
	ebpfMap *ebpf.Map
}

// initMap creates the signal map in the kernel.
func initMap(logger *slog.Logger) *eventsMap {
	return &eventsMap{
		logger: logger,
	}
}

func (e *eventsMap) open() error {
	// For ringbuf, the map is created by BPF loader when the program is loaded.
	// We just need to load the pinned map.
	path := bpf.MapPath(e.logger, MapName)

	var err error
	e.ebpfMap, err = ebpf.LoadPinnedMap(path, nil)
	if err != nil {
		// If the map doesn't exist yet, that's OK - the BPF programs haven't
		// been loaded yet. The monitor agent will handle this gracefully.
		if errors.Is(err, os.ErrNotExist) {
			e.logger.Info("Events map not found, will be created when BPF programs are loaded",
				"path", path)
			return nil
		}
		return err
	}

	// Verify the map type is RingBuf. If it's the old PerfEventArray type,
	// we need to delete it so the BPF loader can recreate it with the correct type.
	mapType := e.ebpfMap.Type()
	if mapType != ebpf.RingBuf {
		e.logger.Info("Events map has wrong type, unpinning for recreation by BPF loader",
			"expected", ebpf.RingBuf.String(),
			"actual", mapType.String(),
			"path", path)
		// Unpin the old map so BPF loader can create a new one
		if unpinErr := e.ebpfMap.Unpin(); unpinErr != nil {
			e.logger.Warn("Failed to unpin old events map", "error", unpinErr)
		}
		e.ebpfMap.Close()
		e.ebpfMap = nil
		// Return nil so startup continues - the BPF loader will create the correct map
		return nil
	}

	return nil
}

func (e *eventsMap) close() error {
	if e.ebpfMap != nil {
		return e.ebpfMap.Close()
	}
	return nil
}

func (e *eventsMap) NewReader() (RingBufReader, error) {
	if e.ebpfMap == nil {
		return nil, fmt.Errorf("events map not available")
	}
	return ringbuf.NewReader(e.ebpfMap)
}

func (e *eventsMap) MapName() string {
	return MapName
}

func (e *eventsMap) EbpfMap() *ebpf.Map {
	return e.ebpfMap
}

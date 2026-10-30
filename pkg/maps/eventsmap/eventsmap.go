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

	// ringBufSize must match EVENTS_RINGBUF_SIZE in bpf/lib/events.h.
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

// initMap creates an events map handle.
func initMap(logger *slog.Logger) *eventsMap {
	return &eventsMap{
		logger: logger,
	}
}

func (e *eventsMap) open() error {
	// The BPF loader creates the map when it loads the program.
	// Load the pinned map here.
	path := bpf.MapPath(e.logger, MapName)

	var err error
	e.ebpfMap, err = ebpf.LoadPinnedMap(path, nil)
	if err != nil {
		// A missing map means that the BPF loader has not loaded the program.
		// The monitor agent waits for the host datapath in this case.
		if errors.Is(err, os.ErrNotExist) {
			e.logger.Info("Events map not found, will be created when BPF programs are loaded",
				"path", path)
			return nil
		}
		return err
	}

	// Unpin an incompatible map. The BPF loader will create the correct map.
	mapType := e.ebpfMap.Type()
	if mapType != ebpf.RingBuf || e.ebpfMap.MaxEntries() != ringBufSize {
		e.logger.Info("Events map has an incompatible definition, unpinning for recreation by BPF loader",
			"expected", ebpf.RingBuf.String(),
			"actual", mapType.String(),
			"expectedSize", ringBufSize,
			"actualSize", e.ebpfMap.MaxEntries(),
			"path", path)
		if unpinErr := e.ebpfMap.Unpin(); unpinErr != nil {
			e.ebpfMap.Close()
			e.ebpfMap = nil
			return fmt.Errorf("unpinning old events map: %w", unpinErr)
		}
		e.ebpfMap.Close()
		e.ebpfMap = nil
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

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package metrics

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"slices"
	"strings"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/sync/singleflight"

	"github.com/cilium/cilium/pkg/logging/logfields"
)

// This file contains a Prometheus collector that collects the memory usage of
// BPF programs and maps. It iterates all BPF programs in the kernel, filters
// them by their name prefixes, and collects their memory usage and that of all
// related maps.
//
// While the approach taken may seem naive, the other obvious approach (finding
// entrypoints, recursively jumping through prog arrays to find tail calls)
// proved prohibitively slow beyond a small test cluster. Iterating prog arrays
// is expensive, and beyond a few dozen pods, syscall overhead started
// dominating and becoming slower than the bpftool-based implementation that was
// here before. Batch ops aren't implemented for prog arrays, so that's wasn't
// an option either.
//
// For now, settle on matching both the entrypoint and the tail call name
// prefixes and collecting associated maps.

// BPFUsageStats is the aggregated memory and object count returned by a BPF
// usage provider.
type BPFUsageStats struct {
	Programs     uint64
	ProgramBytes uint64
	Maps         uint64
	MapBytes     uint64
}

type bpfUsage = BPFUsageStats

// BPFUsageProvider returns a snapshot of BPF usage metrics.
type BPFUsageProvider func() (*BPFUsageStats, error)

var (
	bpfUsageProviderMu sync.RWMutex
	bpfUsageProvider   BPFUsageProvider

	defaultBPFUsageProvider = func() (*BPFUsageStats, error) {
		return newBPFVisitor([]string{"cil_", "tail_"}).Usage()
	}
)

// RegisterBPFUsageProvider installs an alternate BPF usage provider for the
// collector's scoped mode.
func RegisterBPFUsageProvider(provider BPFUsageProvider) {
	bpfUsageProviderMu.Lock()
	bpfUsageProvider = provider
	bpfUsageProviderMu.Unlock()
}

func getBPFUsageProvider() BPFUsageProvider {
	bpfUsageProviderMu.RLock()
	defer bpfUsageProviderMu.RUnlock()
	return bpfUsageProvider
}

func newBPFVisitor(progPrefixes []string) *bpfVisitor {
	return &bpfVisitor{
		progPrefixes:    progPrefixes,
		programsVisited: make(map[ebpf.ProgramID]struct{}),
		mapsVisited:     make(map[ebpf.MapID]struct{}),
	}
}

type bpfVisitor struct {
	bpfUsage

	progPrefixes []string

	programsVisited map[ebpf.ProgramID]struct{}
	mapsVisited     map[ebpf.MapID]struct{}
}

// Usage returns the memory usage of all BPF programs matching the filter
// specified in the constructor, as well as the memory usage of all maps
// associated with those programs.
func (v *bpfVisitor) Usage() (_ *bpfUsage, err error) {
	var id ebpf.ProgramID
	for {
		id, err = ebpf.ProgramGetNextID(id)
		if errors.Is(err, os.ErrNotExist) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("get next program: %w", err)
		}

		if err := v.visitProgram(id, v.progPrefixes); err != nil {
			return nil, fmt.Errorf("check program %d: %w", id, err)
		}
	}

	return &v.bpfUsage, nil
}

// visitProgram opens the given program by id and collects its memory usage and
// that of all maps it uses.
//
// If prefixes are specified, the program is only checked if its name starts
// with one of the prefixes. This is useful to omit programs that are not
// relevant for the caller.
func (v *bpfVisitor) visitProgram(id ebpf.ProgramID, prefixes []string) error {
	if _, ok := v.programsVisited[id]; ok {
		return nil
	}
	v.programsVisited[id] = struct{}{}

	prog, err := ebpf.NewProgramFromID(id)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("open program by id: %w", err)
	}
	defer prog.Close()

	info, err := prog.Info()
	if err != nil {
		return fmt.Errorf("get program info: %w", err)
	}

	// If a prefix is specified, check if the program name starts with at least
	// one of the prefixes. If not, skip the program.
	if len(prefixes) > 0 {
		hasPrefix := func(prefix string) bool { return strings.HasPrefix(info.Name, prefix) }
		if !slices.ContainsFunc(prefixes, hasPrefix) {
			return nil
		}
	}

	mem, ok := info.Memlock()
	if !ok {
		return fmt.Errorf("program %s has zero memlock", info.Name)
	}

	v.Programs++
	v.ProgramBytes += mem

	maps, _ := info.MapIDs()
	for _, mapID := range maps {
		if err := v.visitMap(mapID); err != nil {
			return fmt.Errorf("check map id %d for program %s: %w", mapID, info.Name, err)
		}
	}

	return nil
}

// visitMap opens the given map by id and collects its memory usage.
func (v *bpfVisitor) visitMap(id ebpf.MapID) error {
	if _, ok := v.mapsVisited[id]; ok {
		return nil
	}
	v.mapsVisited[id] = struct{}{}

	m, err := ebpf.NewMapFromID(id)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("open map by id: %w", err)
	}
	defer m.Close()

	info, err := m.Info()
	if err != nil {
		return fmt.Errorf("get map info: %w", err)
	}

	// Maps with BPF_F_NO_PREALLOC set (like LPMTrie) report a size of 0 when
	// empty. Zero memory usage can be valid for a map.
	mem, _ := info.Memlock()

	v.Maps++
	v.MapBytes += mem

	return nil
}

type bpfCollector struct {
	logger *slog.Logger
	sfg    singleflight.Group

	ciliumOwnedOnly bool

	bpfMapsCount      *prometheus.Desc
	bpfMapsMemory     *prometheus.Desc
	bpfProgramsCount  *prometheus.Desc
	bpfProgramsMemory *prometheus.Desc
}

func newbpfCollector(logger *slog.Logger, ciliumOwnedOnly bool) *bpfCollector {
	return &bpfCollector{
		logger:          logger,
		ciliumOwnedOnly: ciliumOwnedOnly,
		bpfMapsCount: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, "", "bpf_maps"),
			"Total count of BPF maps.",
			nil, nil,
		),
		bpfMapsMemory: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, "", "bpf_maps_virtual_memory_max_bytes"),
			"BPF maps kernel max memory usage size in bytes.",
			nil, nil,
		),
		bpfProgramsCount: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, "", "bpf_progs"),
			"Total count of BPF programs.",
			nil, nil,
		),
		bpfProgramsMemory: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, "", "bpf_progs_virtual_memory_max_bytes"),
			"BPF programs kernel max memory usage size in bytes.",
			nil, nil,
		),
	}
}

func (s *bpfCollector) Describe(ch chan<- *prometheus.Desc) {
	prometheus.DescribeByCollect(s, ch)
}

func (s *bpfCollector) usageProvider() BPFUsageProvider {
	if s.ciliumOwnedOnly {
		if provider := getBPFUsageProvider(); provider != nil {
			return provider
		}
	}

	return defaultBPFUsageProvider
}

func (s *bpfCollector) Collect(ch chan<- prometheus.Metric) {
	// Avoid querying BPF multiple times concurrently, if it happens, additional callers will wait for the
	// first one to finish and reuse its resulting values.
	results, err, _ := s.sfg.Do("collect", func() (any, error) {
		return s.usageProvider()()
	})

	if err != nil {
		s.logger.Error("retrieving BPF maps & programs usage", logfields.Error, err)
		return
	}

	ch <- prometheus.MustNewConstMetric(
		s.bpfMapsCount,
		prometheus.GaugeValue,
		float64(results.(*bpfUsage).Maps),
	)

	ch <- prometheus.MustNewConstMetric(
		s.bpfMapsMemory,
		prometheus.GaugeValue,
		float64(results.(*bpfUsage).MapBytes),
	)

	ch <- prometheus.MustNewConstMetric(
		s.bpfProgramsCount,
		prometheus.GaugeValue,
		float64(results.(*bpfUsage).Programs),
	)

	ch <- prometheus.MustNewConstMetric(
		s.bpfProgramsMemory,
		prometheus.GaugeValue,
		float64(results.(*bpfUsage).ProgramBytes),
	)
}

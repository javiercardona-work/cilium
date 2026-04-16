// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package metrics

import (
	"io"
	"log/slog"
	"os"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	prometheusdto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"

	"github.com/cilium/cilium/pkg/testutils"
)

func TestBPFCollectorUsesScopedProviderWhenEnabled(t *testing.T) {
	t.Cleanup(func() {
		RegisterBPFUsageProvider(nil)
	})

	RegisterBPFUsageProvider(func() (*BPFUsageStats, error) {
		return &BPFUsageStats{
			Programs:     7,
			ProgramBytes: 70,
			Maps:         3,
			MapBytes:     30,
		}, nil
	})

	collector := newbpfCollector(slogtest(t), true)
	metricsCh := make(chan prometheus.Metric, 4)
	collector.Collect(metricsCh)
	close(metricsCh)

	var values []float64
	for metric := range metricsCh {
		dtoMetric := &prometheusdto.Metric{}
		require.NoError(t, metric.Write(dtoMetric))
		values = append(values, dtoMetric.GetGauge().GetValue())
	}

	require.Len(t, values, 4)
	assert.ElementsMatch(t, []float64{3, 30, 7, 70}, values)
}

func slogtest(tb testing.TB) *slog.Logger {
	tb.Helper()
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{}))
}

func TestPrivilegedGetBPFUsage(t *testing.T) {
	testutils.PrivilegedTest(t)

	prefix := "_ciltest_"

	setupGetBPFUsage(t, prefix)

	usage, err := newBPFVisitor([]string{prefix + "1", prefix + "2"}).Usage()
	require.NoError(t, err)

	assert.EqualValues(t, 2, usage.Programs)
	assert.EqualValues(t, 2*os.Getpagesize(), usage.ProgramBytes) // one page per program
	assert.EqualValues(t, 1, usage.Maps)
	assert.NotEqualValues(t, 0, usage.MapBytes)

	usage, err = newBPFVisitor([]string{"no_match"}).Usage()
	require.NoError(t, err)
	assert.EqualValues(t, 0, usage.Programs)
	assert.EqualValues(t, 0, usage.ProgramBytes)
	assert.EqualValues(t, 0, usage.Maps)
	assert.EqualValues(t, 0, usage.MapBytes)

	usage, err = newBPFVisitor(nil).Usage()
	require.NoError(t, err)
	assert.NotEqualValues(t, 0, usage.Programs)
	assert.NotEqualValues(t, 0, usage.ProgramBytes)
	assert.NotEqualValues(t, 0, usage.Maps)
	assert.NotEqualValues(t, 0, usage.MapBytes)
}

func BenchmarkPrivilegedGetBPFUsage(b *testing.B) {
	testutils.PrivilegedTest(b)
	b.ReportAllocs()

	prefix := "_ciltest_"
	for range 1000 {
		setupGetBPFUsage(b, prefix)
	}

	b.ResetTimer()

	for b.Loop() {
		if _, err := newBPFVisitor([]string{prefix}).Usage(); err != nil {
			b.Fatal(err)
		}
	}
}

func setupGetBPFUsage(tb testing.TB, prefix string) {
	m, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.Array,
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: 1,
	})
	require.NoError(tb, err)

	p1, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Type: ebpf.SocketFilter,
		Name: prefix + "1",
		Instructions: asm.Instructions{
			asm.LoadMapPtr(asm.R1, m.FD()),
			asm.Mov.Imm(asm.R0, 0),
			asm.Return(),
		},
	})

	require.NoError(tb, err)
	p2, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Type: ebpf.SocketFilter,
		Name: prefix + "2",
		Instructions: asm.Instructions{
			asm.LoadMapPtr(asm.R1, m.FD()),
			asm.Mov.Imm(asm.R0, 0),
			asm.Return(),
		},
	})
	require.NoError(tb, err)

	tb.Cleanup(func() {
		m.Close()
		p1.Close()
		p2.Close()
	})
}

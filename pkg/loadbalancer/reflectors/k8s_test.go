// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reflectors

import (
	"log/slog"
	"maps"
	"slices"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/annotation"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/k8s"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_discovery_v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/discovery/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/k8s/testutils"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/source"
)

var (
	benchmarkExternalConfig = loadbalancer.ExternalConfig{
		EnableIPv4:           true,
		EnableIPv6:           true,
		KubeProxyReplacement: true,
	}
)

func BenchmarkConvertService(b *testing.B) {
	obj, err := testutils.DecodeFile("../benchmark/testdata/service.yaml")
	if err != nil {
		panic(err)
	}
	svc := obj.(*slim_corev1.Service)

	for b.Loop() {
		convertService(loadbalancer.DefaultConfig, benchmarkExternalConfig, slog.New(slog.DiscardHandler), nil, svc, source.Kubernetes)
	}
	b.ReportMetric(float64(b.N)/b.Elapsed().Seconds(), "services/sec")
}

func BenchmarkParseEndpointSlice(b *testing.B) {
	obj, err := testutils.DecodeFile("../benchmark/testdata/endpointslice.yaml")
	if err != nil {
		panic(err)
	}
	epSlice := obj.(*slim_discovery_v1.EndpointSlice)
	logger := hivetest.Logger(b)

	for b.Loop() {
		k8s.ParseEndpointSliceV1(logger, epSlice)
	}
	b.ReportMetric(float64(b.N)/b.Elapsed().Seconds(), "endpointslices/sec")
}

func BenchmarkConvertEndpoints(b *testing.B) {
	obj, err := testutils.DecodeFile("../benchmark/testdata/endpointslice.yaml")
	if err != nil {
		panic(err)
	}
	epSlice := obj.(*slim_discovery_v1.EndpointSlice)
	logger := hivetest.Logger(b)
	eps := k8s.ParseEndpointSliceV1(logger, epSlice)
	backends := maps.All(eps.Backends)

	for b.Loop() {
		convertEndpoints(logger, benchmarkExternalConfig, eps.ServiceName, backends)
	}
	b.ReportMetric(float64(b.N)/b.Elapsed().Seconds(), "endpoints/sec")
}

func TestConvertEndpointsRespectsEndpointSliceWeight(t *testing.T) {
	logger := hivetest.Logger(t)
	eps := k8s.ParseEndpointSliceV1(logger, &slim_discovery_v1.EndpointSlice{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:      "slice",
			Namespace: "default",
			Labels: map[string]string{
				slim_discovery_v1.LabelServiceName: "svc",
			},
			Annotations: map[string]string{
				annotation.EndpointSliceWeight: "42",
			},
		},
		AddressType: slim_discovery_v1.AddressTypeIPv4,
		Endpoints: []slim_discovery_v1.Endpoint{
			{Addresses: []string{"10.0.0.1"}},
		},
		Ports: []slim_discovery_v1.EndpointPort{
			{
				Name:     func() *string { a := "http"; return &a }(),
				Protocol: func() *slim_corev1.Protocol { a := slim_corev1.ProtocolTCP; return &a }(),
				Port:     func() *int32 { a := int32(80); return &a }(),
			},
		},
	})

	backends := slices.Collect(convertEndpoints(logger, benchmarkExternalConfig, eps.ServiceName, maps.All(eps.Backends)))
	require.Len(t, backends, 1)
	require.Equal(t, uint16(42), backends[0].Weight)
	require.Equal(t, loadbalancer.BackendStateActive, backends[0].State)
	require.Equal(t, cmtypes.MustParseAddrCluster("10.0.0.1"), backends[0].Address.AddrCluster())
}

func TestConvertEndpointsWeightZeroForcesMaintenance(t *testing.T) {
	logger := hivetest.Logger(t)
	eps := k8s.ParseEndpointSliceV1(logger, &slim_discovery_v1.EndpointSlice{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:      "slice",
			Namespace: "default",
			Labels: map[string]string{
				slim_discovery_v1.LabelServiceName: "svc",
			},
			Annotations: map[string]string{
				annotation.EndpointSliceWeight: "0",
			},
		},
		AddressType: slim_discovery_v1.AddressTypeIPv4,
		Endpoints: []slim_discovery_v1.Endpoint{
			{
				Addresses: []string{"10.0.0.1"},
				Conditions: slim_discovery_v1.EndpointConditions{
					Ready: func() *bool { b := true; return &b }(),
				},
			},
		},
		Ports: []slim_discovery_v1.EndpointPort{
			{
				Name:     func() *string { a := "http"; return &a }(),
				Protocol: func() *slim_corev1.Protocol { a := slim_corev1.ProtocolTCP; return &a }(),
				Port:     func() *int32 { a := int32(80); return &a }(),
			},
		},
	})

	backends := slices.Collect(convertEndpoints(logger, benchmarkExternalConfig, eps.ServiceName, maps.All(eps.Backends)))
	require.Len(t, backends, 1)
	require.Zero(t, backends[0].Weight)
	require.Equal(t, loadbalancer.BackendStateMaintenance, backends[0].State)
}

func testBackendWithPorts(ports ...uint16) *k8s.Backend {
	backend := &k8s.Backend{Ports: map[loadbalancer.L4Addr][]string{}}
	for _, port := range ports {
		backend.Ports[loadbalancer.L4Addr{
			Protocol: loadbalancer.TCP,
			Port:     port,
		}] = nil
	}
	return backend
}

func testEndpointEvent(serviceName loadbalancer.ServiceName, name string, backends map[cmtypes.AddrCluster]*k8s.Backend) endpointsEvent {
	return endpointsEvent{
		name:     "default/" + name,
		svcName:  serviceName,
		backends: backends,
	}
}

func collectOrphanBackends(current []endpointsEvent, updated ...endpointsEvent) []loadbalancer.L3n4Addr {
	cache := newEndpointCache()
	for _, ep := range current {
		cache.update(ep)
	}
	batch := allEndpoints{}
	for _, ep := range updated {
		if batch.head.name == "" {
			batch.head = ep
		} else {
			batch.tail = append(batch.tail, ep)
		}
	}
	return slices.Collect(cache.orphans(batch, updated[0].svcName))
}

func TestOrphanBackendsAcrossEndpointSlices(t *testing.T) {
	serviceName := loadbalancer.NewServiceName("default", "test")
	otherServiceName := loadbalancer.NewServiceName("default", "other")
	ip1 := cmtypes.MustParseAddrCluster("10.0.0.1")
	ip2 := cmtypes.MustParseAddrCluster("10.0.0.2")
	address := func(ip cmtypes.AddrCluster, port uint16) loadbalancer.L3n4Addr {
		return loadbalancer.NewL3n4Addr(
			loadbalancer.TCP,
			ip,
			port,
			loadbalancer.ScopeExternal,
		)
	}

	t.Run("delete one of two slices with a shared backend", func(t *testing.T) {
		slice1 := testEndpointEvent(serviceName, "slice-1",
			map[cmtypes.AddrCluster]*k8s.Backend{ip1: testBackendWithPorts(80)})
		slice2 := testEndpointEvent(serviceName, "slice-2",
			map[cmtypes.AddrCluster]*k8s.Backend{ip1: testBackendWithPorts(80)})
		current := []endpointsEvent{slice1, slice2}

		deletedSlice1 := testEndpointEvent(serviceName, "slice-1", nil)
		require.Empty(t, collectOrphanBackends(current, deletedSlice1))
	})

	t.Run("delete the unique backend of one slice", func(t *testing.T) {
		slice1 := testEndpointEvent(serviceName, "slice-1",
			map[cmtypes.AddrCluster]*k8s.Backend{
				ip1: testBackendWithPorts(80),
				ip2: testBackendWithPorts(80),
			})
		slice2 := testEndpointEvent(serviceName, "slice-2",
			map[cmtypes.AddrCluster]*k8s.Backend{ip1: testBackendWithPorts(80)})
		current := []endpointsEvent{slice1, slice2}

		deletedSlice1 := testEndpointEvent(serviceName, "slice-1", nil)
		require.Equal(t,
			[]loadbalancer.L3n4Addr{address(ip2, 80)},
			collectOrphanBackends(current, deletedSlice1),
		)
	})

	t.Run("remove a backend from the only slice", func(t *testing.T) {
		slice1 := testEndpointEvent(serviceName, "slice-1",
			map[cmtypes.AddrCluster]*k8s.Backend{ip1: testBackendWithPorts(80)})
		current := []endpointsEvent{slice1}

		deletedSlice1 := testEndpointEvent(serviceName, "slice-1", nil)
		require.Equal(t,
			[]loadbalancer.L3n4Addr{address(ip1, 80)},
			collectOrphanBackends(current, deletedSlice1),
		)
	})

	t.Run("keep a port that another slice references", func(t *testing.T) {
		slice1 := testEndpointEvent(serviceName, "slice-1",
			map[cmtypes.AddrCluster]*k8s.Backend{ip1: testBackendWithPorts(80, 443)})
		slice2 := testEndpointEvent(serviceName, "slice-2",
			map[cmtypes.AddrCluster]*k8s.Backend{ip1: testBackendWithPorts(443)})
		current := []endpointsEvent{slice1, slice2}

		updatedSlice1 := testEndpointEvent(serviceName, "slice-1",
			map[cmtypes.AddrCluster]*k8s.Backend{ip1: testBackendWithPorts(80)})
		require.Empty(t, collectOrphanBackends(current, updatedSlice1))
	})

	t.Run("ignore backends from another service", func(t *testing.T) {
		slice1 := testEndpointEvent(serviceName, "slice-1",
			map[cmtypes.AddrCluster]*k8s.Backend{ip1: testBackendWithPorts(80)})
		otherSlice := testEndpointEvent(otherServiceName, "slice-9",
			map[cmtypes.AddrCluster]*k8s.Backend{ip1: testBackendWithPorts(80)})
		current := []endpointsEvent{slice1, otherSlice}

		deletedSlice1 := testEndpointEvent(serviceName, "slice-1", nil)
		require.Equal(t,
			[]loadbalancer.L3n4Addr{address(ip1, 80)},
			collectOrphanBackends(current, deletedSlice1),
		)
	})
}

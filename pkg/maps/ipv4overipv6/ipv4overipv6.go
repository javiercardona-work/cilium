// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipv4overipv6

import (
	"net"
	"sync"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/ebpf"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/types"
)

const (
	// Name is the canonical name for the tunnel endpoint IPv4 -> node IPv6 map
	// used by the pure BPF ipip6 pod-forwarding path.
	Name = "cilium_ipv4_over_ipv6_nodes"

	// MaxEntries is the maximum number of nodes we expect to track.
	MaxEntries = 1024
)

// Key must stay in sync with the BPF definition in bpf/lib/ipv4_over_ipv6.h.
type Key struct {
	TunnelEndpoint types.IPv4
}

func (k Key) String() string {
	return k.TunnelEndpoint.String()
}

func (k *Key) New() bpf.MapKey { return &Key{} }

func NewKey(ip net.IP) Key {
	var key Key

	if ip4 := ip.To4(); ip4 != nil {
		copy(key.TunnelEndpoint[:], ip4)
	}

	return key
}

// Value must stay in sync with the BPF definition in bpf/lib/ipv4_over_ipv6.h.
type Value struct {
	NodeIPv6 types.IPv6
}

func (v Value) String() string {
	return v.NodeIPv6.String()
}

func (v *Value) New() bpf.MapValue { return &Value{} }

func NewValue(ip net.IP) Value {
	var value Value

	if ip6 := ip.To16(); ip6 != nil {
		copy(value.NodeIPv6[:], ip6)
	}

	return value
}

type Map struct {
	bpf.Map
}

func NewMap(registry *metrics.Registry, name string) *Map {
	return &Map{
		Map: *bpf.NewMap(
			name,
			ebpf.Hash,
			&Key{},
			&Value{},
			MaxEntries,
			0,
		).WithCache().WithPressureMetric(registry).
			WithEvents(option.Config.GetEventBufferConfig(name)),
	}
}

var (
	nodeMap     *Map
	nodeMapInit = &sync.Once{}
)

func IPv4OverIPv6Map(registry *metrics.Registry) *Map {
	nodeMapInit.Do(func() {
		nodeMap = NewMap(registry, Name)
	})
	return nodeMap
}

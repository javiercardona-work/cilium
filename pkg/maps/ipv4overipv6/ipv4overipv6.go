// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipv4overipv6

import (
	"net"
	"net/netip"
	"sync"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/ebpf"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/types"
	"golang.org/x/sys/unix"
)

const (
	// Name is the canonical name for the destination IPv4 -> node IPv6 map
	// used by the pure BPF ipip6 pod-forwarding path.
	Name = "cilium_ipv4_over_ipv6_nodes"

	// MaxEntries is the maximum number of destination prefixes we expect to
	// track. Each node can contribute an alloc CIDR plus optional per-node /32
	// health and ingress entries.
	MaxEntries = 16384
)

// Key must stay in sync with the BPF definition in bpf/lib/ipv4_over_ipv6.h.
type Key struct {
	PrefixLen uint32
	Address   types.IPv4
}

func (k Key) String() string {
	addr := netip.AddrFrom4(k.Address)
	return netip.PrefixFrom(addr, int(k.PrefixLen)).String()
}

func (k *Key) New() bpf.MapKey { return &Key{} }

func NewKey(ip net.IP, mask net.IPMask) Key {
	var key Key

	if ip4 := ip.To4(); ip4 != nil {
		if mask == nil {
			mask = net.CIDRMask(net.IPv4len*8, net.IPv4len*8)
		}
		ip4 = ip4.Mask(mask)
		ones, _ := mask.Size()
		key.PrefixLen = uint32(ones)
		copy(key.Address[:], ip4)
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
			ebpf.LPMTrie,
			&Key{},
			&Value{},
			MaxEntries,
			unix.BPF_F_NO_PREALLOC,
		).WithCache().WithPressureMetric(registry).
			WithEvents(option.Config.GetEventBufferConfig(name)),
	}
}

func PrefixKey(prefix *net.IPNet) Key {
	if prefix == nil {
		return Key{}
	}

	return NewKey(prefix.IP, prefix.Mask)
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

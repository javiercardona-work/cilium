// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipv4overipv6

import (
	"net"

	"github.com/cilium/cilium/pkg/bpf"
	datapath "github.com/cilium/cilium/pkg/datapath/types"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
)

const syncerName = "ipv4-over-ipv6-destination-map-sync"

type mapOps interface {
	OpenOrCreate() error
	Close() error
	Update(key bpf.MapKey, value bpf.MapValue) error
	Delete(key bpf.MapKey) error
	DeleteAll() error
}

type nodeMapSyncer struct {
	bpfMap  mapOps
	enabled bool
}

func newNodeMapSyncer(m mapOps) *nodeMapSyncer {
	return &nodeMapSyncer{
		bpfMap:  m,
		enabled: option.Config.EnableBPFIPv4OverIPv6 && option.Config.EnableIPv4 && option.Config.EnableIPv6,
	}
}

var _ datapath.NodeHandler = (*nodeMapSyncer)(nil)

func (s *nodeMapSyncer) Name() string {
	return syncerName
}

func (s *nodeMapSyncer) startupReconcile() error {
	if !s.enabled {
		return nil
	}

	/* This map is fully derived from node state. Drop any stale pinned
	 * entries first, then rely on node-manager subscription replay to
	 * rebuild the desired contents for this agent.
	 */
	return s.bpfMap.DeleteAll()
}

func (s *nodeMapSyncer) NodeAdd(newNode nodeTypes.Node) error {
	return s.upsertNode(newNode)
}

func (s *nodeMapSyncer) NodeUpdate(oldNode, newNode nodeTypes.Node) error {
	if !s.enabled {
		return nil
	}

	oldEntries, okOld := remoteNodeEntries(oldNode)
	newEntries, okNew := remoteNodeEntries(newNode)
	if okOld {
		for _, oldEntry := range oldEntries {
			if okNew && containsEntry(newEntries, oldEntry) {
				continue
			}
			oldKey := PrefixKey(oldEntry.destinationIPv4)
			if err := s.bpfMap.Delete(&oldKey); err != nil {
				return err
			}
		}
	}

	return s.upsertNode(newNode)
}

func (s *nodeMapSyncer) NodeDelete(node nodeTypes.Node) error {
	if !s.enabled {
		return nil
	}

	entries, ok := remoteNodeEntries(node)
	if !ok {
		return nil
	}

	for _, entry := range entries {
		key := PrefixKey(entry.destinationIPv4)
		if err := s.bpfMap.Delete(&key); err != nil {
			return err
		}
	}

	return nil
}

func (s *nodeMapSyncer) AllNodeValidateImplementation() {}

func (s *nodeMapSyncer) NodeValidateImplementation(node nodeTypes.Node) error {
	return s.upsertNode(node)
}

func (s *nodeMapSyncer) upsertNode(node nodeTypes.Node) error {
	if !s.enabled {
		return nil
	}

	entries, ok := remoteNodeEntries(node)
	if !ok {
		return nil
	}

	for _, entry := range entries {
		key := PrefixKey(entry.destinationIPv4)
		value := NewValue(entry.nodeIPv6)
		if err := s.bpfMap.Update(&key, &value); err != nil {
			return err
		}
	}

	return nil
}

type remoteNodeEntry struct {
	destinationIPv4 *net.IPNet
	nodeIPv6        net.IP
}

func remoteNodeEntries(node nodeTypes.Node) ([]remoteNodeEntry, bool) {
	if node.IsLocal() {
		return nil, false
	}

	ipv6 := node.GetNodeInternalIPv6()
	if ipv6 == nil {
		return nil, false
	}

	entries := make([]remoteNodeEntry, 0, len(node.GetIPv4AllocCIDRs())+2)
	appendIP := func(ip net.IP) {
		if ip4 := ip.To4(); ip4 != nil {
			entries = append(entries, remoteNodeEntry{
				destinationIPv4: &net.IPNet{
					IP:   append(net.IP(nil), ip4...),
					Mask: net.CIDRMask(net.IPv4len*8, net.IPv4len*8),
				},
				nodeIPv6: ipv6,
			})
		}
	}

	for _, allocCIDR := range node.GetIPv4AllocCIDRs() {
		if allocCIDR == nil || allocCIDR.IPNet == nil {
			continue
		}
		entries = append(entries, remoteNodeEntry{
			destinationIPv4: allocCIDR.IPNet,
			nodeIPv6:        ipv6,
		})
	}
	appendIP(node.IPv4HealthIP)
	appendIP(node.IPv4IngressIP)

	if len(entries) == 0 {
		return nil, false
	}

	return entries, true
}

func containsEntry(entries []remoteNodeEntry, target remoteNodeEntry) bool {
	for _, entry := range entries {
		if entry.nodeIPv6.Equal(target.nodeIPv6) &&
			entry.destinationIPv4 != nil &&
			target.destinationIPv4 != nil &&
			entry.destinationIPv4.IP.Equal(target.destinationIPv4.IP) &&
			net.IP(entry.destinationIPv4.Mask).Equal(net.IP(target.destinationIPv4.Mask)) {
			return true
		}
	}
	return false
}

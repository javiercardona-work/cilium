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

const syncerName = "ipv4-over-ipv6-node-map-sync"

type mapOps interface {
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

	oldIPv4, _, okOld := remoteNodeIPs(oldNode)
	newIPv4, _, okNew := remoteNodeIPs(newNode)
	if okOld && (!okNew || !oldIPv4.Equal(newIPv4)) {
		oldKey := NewKey(oldIPv4)
		if err := s.bpfMap.Delete(&oldKey); err != nil {
			return err
		}
	}

	return s.upsertNode(newNode)
}

func (s *nodeMapSyncer) NodeDelete(node nodeTypes.Node) error {
	if !s.enabled {
		return nil
	}

	ipv4, _, ok := remoteNodeIPs(node)
	if !ok {
		return nil
	}

	key := NewKey(ipv4)
	return s.bpfMap.Delete(&key)
}

func (s *nodeMapSyncer) AllNodeValidateImplementation() {}

func (s *nodeMapSyncer) NodeValidateImplementation(node nodeTypes.Node) error {
	return s.upsertNode(node)
}

func (s *nodeMapSyncer) upsertNode(node nodeTypes.Node) error {
	if !s.enabled {
		return nil
	}

	ipv4, ipv6, ok := remoteNodeIPs(node)
	if !ok {
		return nil
	}

	key := NewKey(ipv4)
	value := NewValue(ipv6)
	return s.bpfMap.Update(&key, &value)
}

func remoteNodeIPs(node nodeTypes.Node) (net.IP, net.IP, bool) {
	if node.IsLocal() {
		return nil, nil, false
	}

	ipv4 := node.GetNodeInternalIPv4()
	ipv6 := node.GetNodeInternalIPv6()
	if ipv4 == nil || ipv6 == nil {
		return nil, nil, false
	}

	return ipv4, ipv6, true
}

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipv4overipv6

import (
	"net"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/cidr"
	"github.com/cilium/cilium/pkg/node/addressing"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/types"
)

type fakeMap struct {
	updates    []fakeUpdate
	deletes    []Key
	deleteAlls int
	openCalls  int
	closeCalls int
}

type fakeUpdate struct {
	key   Key
	value Value
}

func (m *fakeMap) Update(key bpf.MapKey, value bpf.MapValue) error {
	m.updates = append(m.updates, fakeUpdate{
		key:   *(key.(*Key)),
		value: *(value.(*Value)),
	})
	return nil
}

func (m *fakeMap) OpenOrCreate() error {
	m.openCalls++
	return nil
}

func (m *fakeMap) Close() error {
	m.closeCalls++
	return nil
}

func (m *fakeMap) Delete(key bpf.MapKey) error {
	m.deletes = append(m.deletes, *(key.(*Key)))
	return nil
}

func (m *fakeMap) DeleteAll() error {
	m.deleteAlls++
	return nil
}

func TestNodeMapSyncerStartupReconcileClearsPinnedState(t *testing.T) {
	m := &fakeMap{}
	s := &nodeMapSyncer{bpfMap: m, enabled: true}

	err := s.startupReconcile()
	require.NoError(t, err)
	require.Equal(t, 1, m.deleteAlls)
}

func TestNodeMapSyncerNodeAdd(t *testing.T) {
	m := &fakeMap{}
	s := &nodeMapSyncer{bpfMap: m, enabled: true}

	err := s.NodeAdd(testRemoteNode("remote-a", "10.244.82.0/24", "10.1.1.10", "10.1.1.11", "2803:6084:70cc:857f:c04e:75ed:1452:a00"))
	require.NoError(t, err)

	require.Len(t, m.updates, 3)
	_, allocCIDR, err := net.ParseCIDR("10.244.82.0/24")
	require.NoError(t, err)
	require.Equal(t, PrefixKey(allocCIDR), m.updates[0].key)
	require.Equal(t, NewKey(net.ParseIP("10.1.1.10"), net.CIDRMask(32, 32)), m.updates[1].key)
	require.Equal(t, NewKey(net.ParseIP("10.1.1.11"), net.CIDRMask(32, 32)), m.updates[2].key)
	for _, update := range m.updates {
		require.Equal(t, NewValue(net.ParseIP("2803:6084:70cc:857f:c04e:75ed:1452:a00")), update.value)
	}
}

func TestNodeMapSyncerNodeUpdateDeletesOldKey(t *testing.T) {
	m := &fakeMap{}
	s := &nodeMapSyncer{bpfMap: m, enabled: true}

	err := s.NodeUpdate(
		testRemoteNode("remote-a", "10.244.82.0/24", "", "", "2803:6084:70cc:857f:c04e:75ed:1452:a00"),
		testRemoteNode("remote-a", "10.244.83.0/24", "10.1.1.10", "", "2803:6084:70cc:857f:c04e:75ed:1452:a00"),
	)
	require.NoError(t, err)

	require.Len(t, m.deletes, 1)
	_, oldAllocCIDR, err := net.ParseCIDR("10.244.82.0/24")
	require.NoError(t, err)
	require.Equal(t, PrefixKey(oldAllocCIDR), m.deletes[0])
	require.Len(t, m.updates, 2)
	_, newAllocCIDR, err := net.ParseCIDR("10.244.83.0/24")
	require.NoError(t, err)
	require.Equal(t, PrefixKey(newAllocCIDR), m.updates[0].key)
	require.Equal(t, NewKey(net.ParseIP("10.1.1.10"), net.CIDRMask(32, 32)), m.updates[1].key)
}

func TestNodeMapSyncerNodeUpdateDeletesOnlyStaleAuxiliaryEntry(t *testing.T) {
	m := &fakeMap{}
	s := &nodeMapSyncer{bpfMap: m, enabled: true}

	err := s.NodeUpdate(
		testRemoteNode("remote-a", "10.244.82.0/24", "10.1.1.10", "", "2803:6084:70cc:857f:c04e:75ed:1452:a00"),
		testRemoteNode("remote-a", "10.244.82.0/24", "10.1.1.11", "", "2803:6084:70cc:857f:c04e:75ed:1452:a00"),
	)
	require.NoError(t, err)

	require.Len(t, m.deletes, 1)
	require.Equal(t, NewKey(net.ParseIP("10.1.1.10"), net.CIDRMask(32, 32)), m.deletes[0])
	require.Len(t, m.updates, 2)
	_, allocCIDR, err := net.ParseCIDR("10.244.82.0/24")
	require.NoError(t, err)
	require.Equal(t, PrefixKey(allocCIDR), m.updates[0].key)
	require.Equal(t, NewKey(net.ParseIP("10.1.1.11"), net.CIDRMask(32, 32)), m.updates[1].key)
}

func TestNewKeyMasksPrefixAddress(t *testing.T) {
	require.Equal(
		t,
		Key{
			PrefixLen: 24,
			Address:   types.IPv4{10, 244, 82, 0},
		},
		NewKey(net.ParseIP("10.244.82.123"), net.CIDRMask(24, 32)),
	)
}

func TestNodeMapSyncerSkipsLocalNode(t *testing.T) {
	m := &fakeMap{}
	s := &nodeMapSyncer{bpfMap: m, enabled: true}

	err := s.NodeAdd(nodeTypes.Node{
		Name:    nodeTypes.GetName(),
		Cluster: option.Config.ClusterName,
		IPAddresses: []nodeTypes.Address{
			{Type: addressing.NodeInternalIP, IP: net.ParseIP("10.244.207.106")},
			{Type: addressing.NodeInternalIP, IP: net.ParseIP("2803:6084:28e4:2a1e:7f2d:7ceb:14cf:a00")},
		},
	})
	require.NoError(t, err)
	require.Empty(t, m.updates)
	require.Empty(t, m.deletes)
}

func testRemoteNode(name, podCIDR, healthIPv4, ingressIPv4, ipv6 string) nodeTypes.Node {
	node := nodeTypes.Node{
		Name:    name,
		Cluster: option.Config.ClusterName,
		IPAddresses: []nodeTypes.Address{
			{Type: addressing.NodeInternalIP, IP: net.ParseIP(ipv6)},
		},
	}

	if podCIDR != "" {
		_, ipv4AllocCIDR, err := net.ParseCIDR(podCIDR)
		if err != nil {
			panic(err)
		}
		node.IPv4AllocCIDR = cidr.NewCIDR(ipv4AllocCIDR)
	}
	if healthIPv4 != "" {
		node.IPv4HealthIP = net.ParseIP(healthIPv4)
	}
	if ingressIPv4 != "" {
		node.IPv4IngressIP = net.ParseIP(ingressIPv4)
	}

	return node
}

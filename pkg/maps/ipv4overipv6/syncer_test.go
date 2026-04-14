// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipv4overipv6

import (
	"net"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/node/addressing"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
)

type fakeMap struct {
	updates    []fakeUpdate
	deletes    []Key
	deleteAlls int
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

	err := s.NodeAdd(testRemoteNode("remote-a", "10.244.82.120", "2803:6084:70cc:857f:c04e:75ed:1452:a00"))
	require.NoError(t, err)

	require.Len(t, m.updates, 1)
	require.Equal(t, NewKey(net.ParseIP("10.244.82.120")), m.updates[0].key)
	require.Equal(t, NewValue(net.ParseIP("2803:6084:70cc:857f:c04e:75ed:1452:a00")), m.updates[0].value)
}

func TestNodeMapSyncerNodeUpdateDeletesOldKey(t *testing.T) {
	m := &fakeMap{}
	s := &nodeMapSyncer{bpfMap: m, enabled: true}

	err := s.NodeUpdate(
		testRemoteNode("remote-a", "10.244.82.96", "2803:6084:70cc:857f:c04e:75ed:1452:a00"),
		testRemoteNode("remote-a", "10.244.82.120", "2803:6084:70cc:857f:c04e:75ed:1452:a00"),
	)
	require.NoError(t, err)

	require.Len(t, m.deletes, 1)
	require.Equal(t, NewKey(net.ParseIP("10.244.82.96")), m.deletes[0])
	require.Len(t, m.updates, 1)
	require.Equal(t, NewKey(net.ParseIP("10.244.82.120")), m.updates[0].key)
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

func testRemoteNode(name, ipv4, ipv6 string) nodeTypes.Node {
	return nodeTypes.Node{
		Name:    name,
		Cluster: option.Config.ClusterName,
		IPAddresses: []nodeTypes.Address{
			{Type: addressing.NodeInternalIP, IP: net.ParseIP(ipv6)},
			{Type: addressing.NodeInternalIP, IP: net.ParseIP(ipv4)},
		},
	}
}

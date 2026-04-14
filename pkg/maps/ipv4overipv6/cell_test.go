// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipv4overipv6

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/hive/cell"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	datapath "github.com/cilium/cilium/pkg/datapath/types"
	nodeManager "github.com/cilium/cilium/pkg/node/manager"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/time"
)

var _ nodeManager.NodeManager = (*fakeNodeManager)(nil)

type fakeNodeManager struct {
	subscribed   datapath.NodeHandler
	subscribeCnt int
	unsubscribe  int
}

func (m *fakeNodeManager) Subscribe(h datapath.NodeHandler) {
	m.subscribed = h
	m.subscribeCnt++
}

func (m *fakeNodeManager) Unsubscribe(h datapath.NodeHandler) {
	if m.subscribed == h {
		m.subscribed = nil
	}
	m.unsubscribe++
}

func (m *fakeNodeManager) GetNodes() map[nodeTypes.Identity]nodeTypes.Node {
	return nil
}

func (m *fakeNodeManager) GetNodeIdentities() []nodeTypes.Identity {
	return nil
}

func (m *fakeNodeManager) NodeUpdated(nodeTypes.Node) {}

func (m *fakeNodeManager) NodeDeleted(nodeTypes.Node) {}

func (m *fakeNodeManager) NodeSync() {}

func (m *fakeNodeManager) MeshNodeSync() {}

func (m *fakeNodeManager) ClusterSizeDependantInterval(baseInterval time.Duration) time.Duration {
	return baseInterval
}

func (m *fakeNodeManager) SetPrefixClusterMutatorFn(func(*nodeTypes.Node) []cmtypes.PrefixClusterOpts) {
}

func TestRegisterNodeMapSyncerLifecycle(t *testing.T) {
	lifecycle := cell.NewDefaultLifecycle(nil, 0, 0)
	nodeMgr := &fakeNodeManager{}
	m := &fakeMap{}
	syncer := &nodeMapSyncer{
		bpfMap:  m,
		enabled: true,
	}

	registerNodeMapSyncer(lifecycle, nodeMgr, syncer)

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	err := lifecycle.Start(logger, context.Background())
	require.NoError(t, err)

	require.Equal(t, 1, m.openCalls)
	require.Equal(t, 1, m.deleteAlls)
	require.Equal(t, 1, nodeMgr.subscribeCnt)
	require.Same(t, syncer, nodeMgr.subscribed)

	err = lifecycle.Stop(logger, context.Background())
	require.NoError(t, err)

	require.Equal(t, 1, nodeMgr.unsubscribe)
	require.Nil(t, nodeMgr.subscribed)
	require.Equal(t, 1, m.closeCalls)
}

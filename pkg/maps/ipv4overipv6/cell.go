// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipv4overipv6

import (
	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/metrics"
	nodeManager "github.com/cilium/cilium/pkg/node/manager"
)

var Cell = cell.Module(
	"ipv4-over-ipv6-destination-map",
	"Populate the destination IPv4 to node IPv6 map for pure BPF ipip6",

	cell.Provide(newNodeMapSyncer),
	cell.ProvidePrivate(func(registry *metrics.Registry) mapOps {
		return IPv4OverIPv6Map(registry)
	}),
	cell.Invoke(registerNodeMapSyncer),
)

func registerNodeMapSyncer(lifecycle cell.Lifecycle, nodeManager nodeManager.NodeManager, syncer *nodeMapSyncer) {
	if !syncer.enabled {
		return
	}

	lifecycle.Append(cell.Hook{
		OnStart: func(cell.HookContext) error {
			if err := syncer.bpfMap.OpenOrCreate(); err != nil {
				return err
			}
			if err := syncer.startupReconcile(); err != nil {
				return err
			}
			nodeManager.Subscribe(syncer)
			return nil
		},
		OnStop: func(cell.HookContext) error {
			nodeManager.Unsubscribe(syncer)
			return syncer.bpfMap.Close()
		},
	})
}

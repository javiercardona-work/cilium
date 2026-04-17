// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package identitycachecell

import (
	"log/slog"
	"net"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
)

func TestGetNodeSuffixFallsBackToIPv6(t *testing.T) {
	oldEnableIPv4 := option.Config.EnableIPv4
	oldEnableIPv6 := option.Config.EnableIPv6
	defer func() {
		option.Config.EnableIPv4 = oldEnableIPv4
		option.Config.EnableIPv6 = oldEnableIPv6
	}()

	option.Config.EnableIPv4 = true
	option.Config.EnableIPv6 = true

	node.WithTestLocalNodeStore(func() {
		node.UpdateLocalNodeInTest(func(n *node.LocalNode) {
			n.SetNodeInternalIP(net.ParseIP("fd00::30"))
		})

		iao := &identityAllocatorOwner{logger: slog.Default()}
		require.Equal(t, "fd00::30", iao.GetNodeSuffix())
	})
}

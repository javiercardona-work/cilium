// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipamcell

import (
	"context"
	"net"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
)

func TestValidatePostInitAllowsIPv4OverIPv6WithoutExternalIPv4(t *testing.T) {
	localNode := node.LocalNode{}
	localNode.SetNodeInternalIP(net.ParseIP("fd00::10"))
	localNode.SetCiliumInternalIP(net.ParseIP("10.244.157.109"))

	initializer := &IPAMInitializer{
		daemonConfig: &option.DaemonConfig{
			EnableIPv4:            true,
			EnableIPv6:            true,
			EnableBPFIPv4OverIPv6: true,
		},
		localNodeStore: node.NewTestLocalNodeStore(localNode),
	}

	require.NoError(t, initializer.ValidatePostInit(context.Background()))
}

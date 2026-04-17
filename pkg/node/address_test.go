// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package node

import (
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/cilium/cilium/pkg/cidr"
	"github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
	"github.com/stretchr/testify/require"
)

func Test_getCiliumHostIPsFromFile(t *testing.T) {
	tmpDir := t.TempDir()
	allIPsCorrect := filepath.Join(tmpDir, "node_config.h")
	f, err := os.Create(allIPsCorrect)
	defer func(f *os.File) {
		require.NoError(t, f.Close())
	}(f)
	require.NoError(t, err)
	fmt.Fprintf(f, `/*
 cilium.v6.external.str fd01::b
 cilium.v6.internal.str f00d::a00:0:0:a4ad
 cilium.v6.nodeport.str []

 cilium.v4.external.str 192.168.60.11
 cilium.v4.internal.str 10.0.0.2
 cilium.v4.nodeport.str []

 cilium.v6.internal.raw 0xf0, 0xd, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xa, 0x0, 0x0, 0x0, 0x0, 0x0, 0xa4, 0xad
 cilium.v4.internal.raw 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xff, 0xff, 0xa, 0x0, 0x0, 0x2
 */

#define ENABLE_IPV4 1
#define IPV4_GATEWAY 0x100000a
#define IPV4_MASK 0xffff
#define HOST_IP 0xfd, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xb
#define HOST_ID 1
#define WORLD_ID 2
#define CILIUM_LB_MAP_MAX_ENTRIES 65536
#define ENDPOINTS_MAP_SIZE 65535
#define LPM_MAP_SIZE 16384
#define POLICY_MAP_SIZE 16384
#define IPCACHE_MAP_SIZE 512000
#define POLICY_PROG_MAP_SIZE 65535
#define TRACE_PAYLOAD_LEN 128ULL
#ifndef CILIUM_NET_MAC
#define CILIUM_NET_MAC { .addr = {0x26,0x11,0x70,0xcc,0xca,0x0c}}
#endif /* CILIUM_NET_MAC */
#define CILIUM_NET_IFINDEX 356
#define CILIUM_HOST_MAC { .addr = {0x3e,0x28,0xb4,0x4b,0x95,0x25}}
#define ENCAP_IFINDEX 358
`)

	type args struct {
		nodeConfig string
	}
	tests := []struct {
		name            string
		args            args
		wantIpv4GW      net.IP
		wantIpv6Router  net.IP
		wantIpv6Address net.IP
	}{
		{
			name: "every-ip-correct",
			args: args{
				nodeConfig: allIPsCorrect,
			},
			wantIpv4GW:      net.ParseIP("10.0.0.2"),
			wantIpv6Router:  net.ParseIP("f00d::a00:0:0:a4ad"),
			wantIpv6Address: net.ParseIP("fd01::b"),
		},
		{
			name: "file-not-present",
			args: args{
				nodeConfig: "",
			},
			wantIpv4GW:     nil,
			wantIpv6Router: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotIpv4GW, gotIpv6Router := getCiliumHostIPsFromFile(tt.args.nodeConfig)
			require.Equal(t, tt.wantIpv4GW, gotIpv4GW)
			require.Equal(t, tt.wantIpv6Router, gotIpv6Router)
		})
	}
}

func TestSetDefaultPrefixWithoutGlobalIPv4DoesNotSetNodeInternalIPv4(t *testing.T) {
	oldEnableIPv4 := option.Config.EnableIPv4
	oldEnableIPv6 := option.Config.EnableIPv6
	oldIPv6ClusterAllocCIDRBase := option.Config.IPv6ClusterAllocCIDRBase
	oldFirstGlobalV4AddrFn := firstGlobalV4AddrFn
	option.Config.EnableIPv4 = true
	option.Config.EnableIPv6 = false
	option.Config.IPv6ClusterAllocCIDRBase = "fd00::"
	firstGlobalV4AddrFn = func(string, net.IP, bool) (net.IP, error) {
		return nil, fmt.Errorf("no global ipv4")
	}
	defer func() {
		option.Config.EnableIPv4 = oldEnableIPv4
		option.Config.EnableIPv6 = oldEnableIPv6
		option.Config.IPv6ClusterAllocCIDRBase = oldIPv6ClusterAllocCIDRBase
		firstGlobalV4AddrFn = oldFirstGlobalV4AddrFn
	}()

	node := &LocalNode{
		Node: types.Node{
			IPv4AllocCIDR: cidr.MustParseCIDR("10.244.7.0/24"),
		},
	}

	setDefaultPrefix(slog.Default(), option.Config, "", node)

	require.Nil(t, node.GetNodeInternalIPv4())
	require.Equal(t, "10.244.7.0/24", node.IPv4AllocCIDR.String())
}

func TestSetDefaultPrefixPanicsWhenIPv4AllocCIDRAutogenNeedsMissingGlobalIPv4(t *testing.T) {
	oldEnableIPv4 := option.Config.EnableIPv4
	oldEnableIPv6 := option.Config.EnableIPv6
	oldIPv6ClusterAllocCIDRBase := option.Config.IPv6ClusterAllocCIDRBase
	oldFirstGlobalV4AddrFn := firstGlobalV4AddrFn
	option.Config.EnableIPv4 = true
	option.Config.EnableIPv6 = false
	option.Config.IPv6ClusterAllocCIDRBase = "fd00::"
	firstGlobalV4AddrFn = func(string, net.IP, bool) (net.IP, error) {
		return nil, fmt.Errorf("no global ipv4")
	}
	defer func() {
		option.Config.EnableIPv4 = oldEnableIPv4
		option.Config.EnableIPv6 = oldEnableIPv6
		option.Config.IPv6ClusterAllocCIDRBase = oldIPv6ClusterAllocCIDRBase
		firstGlobalV4AddrFn = oldFirstGlobalV4AddrFn
	}()

	node := &LocalNode{}

	require.PanicsWithValue(t,
		"can't auto generate ipv4 alloc cidr if no global 4 addr",
		func() {
			setDefaultPrefix(slog.Default(), option.Config, "", node)
		},
	)
}

func TestValidatePostInitAllowsIPv4OverIPv6WithoutExternalIPv4(t *testing.T) {
	oldEnableIPv4 := option.Config.EnableIPv4
	oldEnableIPv6 := option.Config.EnableIPv6
	oldEnableBPFIPv4OverIPv6 := option.Config.EnableBPFIPv4OverIPv6
	defer func() {
		option.Config.EnableIPv4 = oldEnableIPv4
		option.Config.EnableIPv6 = oldEnableIPv6
		option.Config.EnableBPFIPv4OverIPv6 = oldEnableBPFIPv4OverIPv6
	}()

	option.Config.EnableIPv4 = true
	option.Config.EnableIPv6 = true
	option.Config.EnableBPFIPv4OverIPv6 = true

	WithTestLocalNodeStore(func() {
		UpdateLocalNodeInTest(func(n *LocalNode) {
			n.SetNodeInternalIP(net.ParseIP("fd00::10"))
			n.SetCiliumInternalIP(net.ParseIP("10.244.157.109"))
		})

		require.NoError(t, ValidatePostInit(slog.Default()))
	})
}

func TestGetPreferredNodeIPFallsBackToIPv6(t *testing.T) {
	oldEnableIPv4 := option.Config.EnableIPv4
	oldEnableIPv6 := option.Config.EnableIPv6
	defer func() {
		option.Config.EnableIPv4 = oldEnableIPv4
		option.Config.EnableIPv6 = oldEnableIPv6
	}()

	option.Config.EnableIPv4 = true
	option.Config.EnableIPv6 = true

	WithTestLocalNodeStore(func() {
		UpdateLocalNodeInTest(func(n *LocalNode) {
			n.SetNodeInternalIP(net.ParseIP("fd00::20"))
		})

		require.Equal(t, "fd00::20", GetPreferredNodeIP(slog.Default()).String())
		require.Equal(t, "fd00::20", GetCiliumEndpointNodeIP(slog.Default()))
	})
}

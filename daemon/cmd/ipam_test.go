// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	agentK8s "github.com/cilium/cilium/daemon/k8s"
	"github.com/cilium/cilium/pkg/cidr"
	fakeTypes "github.com/cilium/cilium/pkg/datapath/fake/types"
	datapathTypes "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/ipam"
	ipamPkg "github.com/cilium/cilium/pkg/ipam"
	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
)

func TestCoalesceCIDRs(t *testing.T) {
	CIDR := []string{"10.0.0.0/8"}
	expectedCIDR := []string{"10.0.0.0/8"}
	newCIDR, err := coalesceCIDRs(CIDR)
	if err != nil || len(newCIDR) != len(expectedCIDR) || newCIDR[0] != expectedCIDR[0] {
		t.Errorf("got %v, want %v, err: %v\n", newCIDR, expectedCIDR, err)
	}

	CIDR = []string{"10.105.0.0/16", "10.0.0.0/8"}
	expectedCIDR = []string{"10.0.0.0/8"}
	newCIDR, err = coalesceCIDRs(CIDR)
	if err != nil || len(newCIDR) != len(expectedCIDR) || newCIDR[0] != expectedCIDR[0] {
		t.Errorf("got %v, want %v, err: %v\n", newCIDR, expectedCIDR, err)
	}

	CIDR = []string{"10.105.0.0/16", "10.104.0.0/19", "10.0.0.0/8"}
	expectedCIDR = []string{"10.0.0.0/8"}
	newCIDR, err = coalesceCIDRs(CIDR)
	if err != nil || len(newCIDR) != len(expectedCIDR) || newCIDR[0] != expectedCIDR[0] {
		t.Errorf("got %v, want %v, err: %v\n", newCIDR, expectedCIDR, err)
	}

	CIDR = []string{"10.105.0.0/16", "192.168.1.0/24"}
	expectedCIDR = []string{"10.105.0.0/16", "192.168.1.0/24"}
	newCIDR, err = coalesceCIDRs(CIDR)
	if err != nil || len(newCIDR) != len(expectedCIDR) || newCIDR[0] != expectedCIDR[0] || newCIDR[1] != expectedCIDR[1] {
		t.Errorf("got %v, want %v, err: %v\n", newCIDR, expectedCIDR, err)
	}

	CIDR = []string{"10.105.0.0/16", "192.168.1.0/24", "10.0.0.0/8"}
	expectedCIDR = []string{"10.0.0.0/8", "192.168.1.0/24"}
	newCIDR, err = coalesceCIDRs(CIDR)
	if err != nil || len(newCIDR) != len(expectedCIDR) || newCIDR[0] != expectedCIDR[0] || newCIDR[1] != expectedCIDR[1] {
		t.Errorf("got %v, want %v, err: %v\n", newCIDR, expectedCIDR, err)
	}

	CIDR = []string{"10.105.0.0/16", "192.168.1.0/24", "10.0.0.0/8", "f00d::a0f:0:0:0/96"}
	expectedCIDR = []string{"10.0.0.0/8", "192.168.1.0/24", "f00d::a0f:0:0:0/96"}
	newCIDR, err = coalesceCIDRs(CIDR)
	if err != nil || len(newCIDR) != len(expectedCIDR) || newCIDR[0] != expectedCIDR[0] || newCIDR[1] != expectedCIDR[1] || newCIDR[2] != expectedCIDR[2] {
		t.Errorf("got %v, want %v, err: %v\n", newCIDR, expectedCIDR, err)
	}

	CIDR = []string{"f00d::a0f:0:0:0/96", "10.105.0.0/16", "192.168.1.0/24", "10.0.0.0/8"}
	expectedCIDR = []string{"10.0.0.0/8", "192.168.1.0/24", "f00d::a0f:0:0:0/96"}
	newCIDR, err = coalesceCIDRs(CIDR)
	if err != nil || len(newCIDR) != len(expectedCIDR) || newCIDR[0] != expectedCIDR[0] || newCIDR[1] != expectedCIDR[1] || newCIDR[2] != expectedCIDR[2] {
		t.Errorf("got %v, want %v, err: %v\n", newCIDR, expectedCIDR, err)
	}

	CIDR = []string{"f00d::a0f:0:0:0/96"}
	expectedCIDR = []string{"f00d::a0f:0:0:0/96"}
	newCIDR, err = coalesceCIDRs(CIDR)
	if err != nil || len(newCIDR) != len(expectedCIDR) || newCIDR[0] != expectedCIDR[0] {
		t.Errorf("got %v, want %v, err: %v\n", newCIDR, expectedCIDR, err)
	}
}

type mockAllocateIP func(ip net.IP, owner string, pool ipam.Pool) (*ipam.AllocationResult, error)

func (m mockAllocateIP) AllocateIPWithoutSyncUpstream(ip net.IP, owner string, pool ipam.Pool) (*ipam.AllocationResult, error) {
	return m(ip, owner, pool)
}

type ownerMock struct{}

func (o *ownerMock) K8sEventReceived(resourceAPIGroup, scope string, action string, valid, equal bool) {
}

func (o *ownerMock) K8sEventProcessed(scope string, action string, status bool) {}

func (o *ownerMock) UpdateCiliumNodeResource() {}

type resourceMock struct{}

func (rm *resourceMock) Observe(ctx context.Context, next func(resource.Event[*ciliumv2.CiliumNode]), complete func(error)) {
}

func (rm *resourceMock) Events(ctx context.Context, opts ...resource.EventsOpt) <-chan resource.Event[*ciliumv2.CiliumNode] {
	return nil
}

func (rm *resourceMock) Store(context.Context) (resource.Store[*ciliumv2.CiliumNode], error) {
	return nil, errors.New("unimplemented")
}

type fakeMTU struct{}

func (f *fakeMTU) GetDeviceMTU() int { return 1500 }

var mtuMock = fakeMTU{}

func TestDaemon_reallocateDatapathIPs(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)

	allocCIDR := cidr.MustParseCIDR("10.20.30.0/24")
	alloc := mockAllocateIP(func(ip net.IP, owner string, pool ipam.Pool) (*ipam.AllocationResult, error) {
		if !allocCIDR.Contains(ip) {
			return nil, fmt.Errorf("cannot allocate IP %s", ip)
		}
		return &ipam.AllocationResult{IP: ip}, nil
	})

	fromFS := net.ParseIP("10.20.30.42")
	fromK8s := net.ParseIP("10.20.30.41")

	invalidFromFS := net.ParseIP("172.16.0.42")
	invalidFromK8s := net.ParseIP("172.16.0.41")

	// no restoration needed
	result := reallocateDatapathIPs(logger, alloc, nil, nil)
	assert.Nil(t, result)

	// fromK8s if fromFS is not available
	result = reallocateDatapathIPs(logger, alloc, fromK8s, nil)
	assert.NotNil(t, result)
	assert.Equal(t, result.IP, fromK8s)

	// fromFS if fromK8s is not available
	result = reallocateDatapathIPs(logger, alloc, nil, fromFS)
	assert.NotNil(t, result)
	assert.Equal(t, result.IP, fromFS)

	// fromFS should be preferred
	result = reallocateDatapathIPs(logger, alloc, fromK8s, fromFS)
	assert.NotNil(t, result)
	assert.Equal(t, result.IP, fromFS)

	// reject restoration if the IP is not in the allocation CIDR
	result = reallocateDatapathIPs(logger, alloc, invalidFromFS, invalidFromK8s)
	assert.Nil(t, result)

	// fromFS with invalid fromK8s
	result = reallocateDatapathIPs(logger, alloc, invalidFromK8s, fromFS)
	assert.NotNil(t, result)
	assert.Equal(t, result.IP, fromFS)

	// fromFS with invalid fromK8s
	result = reallocateDatapathIPs(logger, alloc, fromK8s, invalidFromFS)
	assert.NotNil(t, result)
	assert.Equal(t, result.IP, fromK8s)
}

type nilPrimaryExternalFamily struct {
	datapathTypes.NodeAddressingFamily
}

func (f nilPrimaryExternalFamily) PrimaryExternal() net.IP {
	return nil
}

func TestDaemon_allocateRouterIPv4WithoutPrimaryExternal(t *testing.T) {
	oldConfig := option.Config
	option.Config = &option.DaemonConfig{
		EnableIPv4:        true,
		EnableIPv6:        true,
		IPAM:              ipamOption.IPAMKubernetes,
		IPAMDefaultIPPool: "default",
	}
	t.Cleanup(func() {
		option.Config = oldConfig
	})

	fakeAddressing := fakeTypes.NewNodeAddressing()
	localNodeStore := node.NewTestLocalNodeStore(node.LocalNode{})
	ipamMgr := ipamPkg.NewIPAM(hivetest.Logger(t), fakeAddressing, option.Config, &ownerMock{}, localNodeStore, &ownerMock{}, agentK8s.LocalCiliumNodeResource(&resourceMock{}), &mtuMock, nil, nil, nil)
	ipamMgr.ConfigureAllocator()

	d := &Daemon{
		logger: hivetest.Logger(t),
		ipam:   ipamMgr,
	}

	routerIP, err := d.allocateRouterIPv4(nilPrimaryExternalFamily{fakeAddressing.IPv4()}, nil, nil)
	require.NoError(t, err)
	require.NotNil(t, routerIP)
	assert.NotNil(t, routerIP.To4())
	assert.True(t, fakeAddressing.IPv4().AllocationCIDR().Contains(routerIP))
}

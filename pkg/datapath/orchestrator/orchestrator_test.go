// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package orchestrator

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/node"
	testendpointmanager "github.com/cilium/cilium/pkg/testutils/endpointmanager"
)

type hostEndpointWaitManager struct {
	*testendpointmanager.MockEndpointManager
	available chan struct{}
	entered   chan struct{}
	once      sync.Once
}

func (m *hostEndpointWaitManager) HostEndpointAvailable() <-chan struct{} {
	m.once.Do(func() { close(m.entered) })
	return m.available
}

func TestWaitForHostEndpointBeforeInitialization(t *testing.T) {
	const (
		templateHostEndpointID = uint64(0xffff)
		realHostEndpointID     = uint64(1234)
	)

	originalHostEndpointID, _ := node.GetEndpointID()
	t.Cleanup(func() {
		node.SetEndpointID(originalHostEndpointID)
	})
	node.SetEndpointID(templateHostEndpointID)

	manager := &hostEndpointWaitManager{
		MockEndpointManager: testendpointmanager.NewMockEndpointManager(),
		available:           make(chan struct{}),
		entered:             make(chan struct{}),
	}
	orchestrator := &orchestrator{
		params: orchestratorParams{EndpointManager: manager},
	}

	var initialized atomic.Bool
	var initializedWithID atomic.Uint64
	done := make(chan error, 1)
	go func() {
		err := orchestrator.waitForHostEndpoint(context.Background())
		if err == nil {
			id, _ := node.GetEndpointID()
			initializedWithID.Store(id)
			initialized.Store(true)
		}
		done <- err
	}()

	<-manager.entered
	require.False(t, initialized.Load())

	node.SetEndpointID(realHostEndpointID)
	close(manager.available)

	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("host endpoint wait did not finish")
	}
	require.True(t, initialized.Load())
	require.Equal(t, realHostEndpointID, initializedWithID.Load())
}

func TestWaitForHostEndpointCancellation(t *testing.T) {
	manager := &hostEndpointWaitManager{
		MockEndpointManager: testendpointmanager.NewMockEndpointManager(),
		available:           make(chan struct{}),
		entered:             make(chan struct{}),
	}
	orchestrator := &orchestrator{
		params: orchestratorParams{EndpointManager: manager},
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- orchestrator.waitForHostEndpoint(ctx)
	}()

	<-manager.entered
	cancel()
	require.ErrorIs(t, <-done, context.Canceled)
}

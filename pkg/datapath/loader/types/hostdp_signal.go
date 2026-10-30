// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

// HostDPSignal reports when the host datapath has been initialized.
// Consumers can wait for maps from the host datapath without a dependency on
// the loader implementation.
type HostDPSignal struct {
	ch chan struct{}
}

// NewHostDPSignal creates a host datapath initialization signal.
func NewHostDPSignal() *HostDPSignal {
	return &HostDPSignal{ch: make(chan struct{})}
}

// Initialized returns a channel that closes after host datapath initialization.
func (s *HostDPSignal) Initialized() <-chan struct{} {
	return s.ch
}

// Close reports that host datapath initialization is complete.
// The loader calls this method through a sync.Once guard.
func (s *HostDPSignal) Close() {
	close(s.ch)
}

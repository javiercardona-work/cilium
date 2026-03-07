// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package loader

// HostDPSignal provides a channel that is closed when the host datapath
// has been initialized (i.e., BPF programs loaded on cilium_host).
// This allows components like the monitor agent to wait for the events map
// without depending on the full Loader interface, avoiding dependency cycles.
type HostDPSignal struct {
	ch   chan struct{}
}

// NewHostDPSignal creates a new HostDPSignal.
func NewHostDPSignal() *HostDPSignal {
	return &HostDPSignal{
		ch: make(chan struct{}),
	}
}

// Initialized returns a channel that is closed when the host datapath is ready.
func (s *HostDPSignal) Initialized() <-chan struct{} {
	return s.ch
}

// Close signals that the host datapath has been initialized.
// Safe to call multiple times (only the first call has effect via sync.Once in the caller).
func (s *HostDPSignal) Close() {
	close(s.ch)
}

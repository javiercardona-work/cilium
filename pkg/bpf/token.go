// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bpf

import (
	"log"

	"github.com/cilium/ebpf/features"

	"github.com/cilium/cilium/pkg/bpf/token"
)

// Re-export constants from token package
const (
	BPF_TOKEN_CREATE = token.BPF_TOKEN_CREATE
	BPF_F_TOKEN_FD   = token.BPF_F_TOKEN_FD
)

// init tries to initialize the BPF token as early as possible.
// This runs during package initialization, before main() starts.
// If the token cannot be obtained, we log and continue in privileged mode.
func init() {
	fd := token.GetGlobalToken()
	if fd <= 0 {
		// Token not available - continue in privileged mode
		log.Printf("BPF token not available, using privileged mode")
	} else {
		// Set it in the ebpf library's internal storage so that
		// library-level feature probes can use it
		features.SetGlobalToken(fd)
	}
}

// GetGlobalToken returns the global BPF token FD, opening it if necessary.
// Returns -1 if no token is available. Retries if previous attempt failed.
func GetGlobalToken() int {
	return token.GetGlobalToken()
}

// InRestrictedMode returns true if we're operating with a BPF token,
// indicating we're in a restricted environment (e.g., user namespace).
// In this mode, certain BPF syscalls like BPF_PROG_QUERY and program
// introspection may fail with EPERM.
func InRestrictedMode() bool {
	return token.InRestrictedMode()
}

// OpenBPFToken opens a BPF token from the configured or discovered path.
// Returns -1 if tokens are not available (graceful fallback).
// Returns the token file descriptor if successful.
func OpenBPFToken(configuredPath string) (int, error) {
	return token.OpenBPFToken(configuredPath)
}

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bpf

import (
	"github.com/cilium/cilium/pkg/bpf/token"
)

// Re-export constants from token package
const (
	BPF_TOKEN_CREATE = token.BPF_TOKEN_CREATE
	BPF_F_TOKEN_FD   = token.BPF_F_TOKEN_FD
)

// GetGlobalToken returns the global BPF token FD, opening it if necessary.
// Returns -1 if no token is available.
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

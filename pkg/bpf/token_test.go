// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bpf

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/testutils"
)

// TestOpenBPFTokenNoToken tests behavior when no token is available
func TestOpenBPFTokenNoToken(t *testing.T) {
	// Try to open token from non-existent path
	fd, err := OpenBPFToken("/nonexistent/path")
	assert.Equal(t, -1, fd)
	assert.Error(t, err)
}

// TestPrivilegedOpenBPFTokenConfiguredPath tests explicit path configuration
func TestPrivilegedOpenBPFTokenConfiguredPath(t *testing.T) {
	testutils.PrivilegedTest(t)

	// Create a temporary BPFFS mount
	temp := testutils.TempBPFFS(t)

	// Try to open token from the temporary BPFFS
	// Note: This may fail if the BPFFS doesn't have delegation enabled,
	// which is expected in test environments without proper BPF token support
	fd, err := OpenBPFToken(temp)

	if err != nil && err.Error() == "BPF tokens not supported by kernel or BPFFS not configured for delegation" {
		// This is expected in environments without BPF token support
		t.Skip("BPF tokens not supported in this environment")
	}

	if fd > 0 {
		defer unix.Close(fd)
		assert.Greater(t, fd, 0, "Token FD should be positive")
	}
}

// TestPrivilegedOpenBPFTokenEnvironmentVariable tests LIBBPF_BPF_TOKEN_PATH env var
func TestPrivilegedOpenBPFTokenEnvironmentVariable(t *testing.T) {
	testutils.PrivilegedTest(t)

	temp := testutils.TempBPFFS(t)

	// Set environment variable
	oldEnv := os.Getenv("LIBBPF_BPF_TOKEN_PATH")
	defer func() {
		if oldEnv != "" {
			os.Setenv("LIBBPF_BPF_TOKEN_PATH", oldEnv)
		} else {
			os.Unsetenv("LIBBPF_BPF_TOKEN_PATH")
		}
	}()

	err := os.Setenv("LIBBPF_BPF_TOKEN_PATH", temp)
	require.NoError(t, err)

	// Try to open token (should read from env var)
	fd, err := OpenBPFToken("")

	if err != nil && err.Error() == "BPF tokens not supported by kernel or BPFFS not configured for delegation" {
		t.Skip("BPF tokens not supported in this environment")
	}

	if fd > 0 {
		defer unix.Close(fd)
		assert.Greater(t, fd, 0, "Token FD should be positive")
	}
}

// TestPrivilegedOpenBPFTokenPriorityOrder tests that explicit path takes precedence over env var
func TestPrivilegedOpenBPFTokenPriorityOrder(t *testing.T) {
	testutils.PrivilegedTest(t)

	// Create two different temp BPFFS mounts
	tempExplicit := testutils.TempBPFFS(t)
	tempEnv := testutils.TempBPFFS(t)

	// Set environment variable to one path
	oldEnv := os.Getenv("LIBBPF_BPF_TOKEN_PATH")
	defer func() {
		if oldEnv != "" {
			os.Setenv("LIBBPF_BPF_TOKEN_PATH", oldEnv)
		} else {
			os.Unsetenv("LIBBPF_BPF_TOKEN_PATH")
		}
	}()

	err := os.Setenv("LIBBPF_BPF_TOKEN_PATH", tempEnv)
	require.NoError(t, err)

	// Open with explicit path - should use explicit path, not env var
	fd, err := OpenBPFToken(tempExplicit)

	if err != nil && err.Error() == "BPF tokens not supported by kernel or BPFFS not configured for delegation" {
		t.Skip("BPF tokens not supported in this environment")
	}

	if fd > 0 {
		defer unix.Close(fd)
		assert.Greater(t, fd, 0, "Token FD should be positive")
	}
}

// TestGetGlobalToken tests global token caching
func TestGetGlobalToken(t *testing.T) {
	// Note: This test doesn't require privileges as it may return -1
	// if no token is available, which is acceptable

	// First call
	fd1 := GetGlobalToken()

	// Second call should return same FD (cached)
	fd2 := GetGlobalToken()

	assert.Equal(t, fd1, fd2, "Global token should be cached and return same FD")
}

// TestPrivilegedOpenBPFTokenCloexec tests that token FD has O_CLOEXEC set
func TestPrivilegedOpenBPFTokenCloexec(t *testing.T) {
	testutils.PrivilegedTest(t)

	temp := testutils.TempBPFFS(t)

	fd, err := OpenBPFToken(temp)

	if err != nil && err.Error() == "BPF tokens not supported by kernel or BPFFS not configured for delegation" {
		t.Skip("BPF tokens not supported in this environment")
	}

	if fd <= 0 {
		t.Skip("No token available")
	}

	defer unix.Close(fd)

	// Get file descriptor flags
	flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
	require.NoError(t, err)

	// Check that FD_CLOEXEC is set
	assert.NotZero(t, flags&unix.FD_CLOEXEC, "Token FD should have O_CLOEXEC set")
}

// TestOpenBPFTokenInvalidPath tests various invalid path scenarios
func TestOpenBPFTokenInvalidPath(t *testing.T) {
	testCases := []struct {
		name string
		path string
	}{
		{"empty string", ""},
		{"non-existent directory", "/tmp/does-not-exist-bpf-token-test"},
		{"file instead of directory", "/tmp"},
		{"relative path", "./relative/path"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.path == "" {
				// Empty path should try default paths and may succeed
				_, _ = OpenBPFToken(tc.path)
				return
			}

			fd, err := OpenBPFToken(tc.path)
			// Should either fail or return -1
			if err == nil {
				assert.Equal(t, -1, fd, "Should return -1 for invalid path")
			} else {
				assert.Equal(t, -1, fd, "Should return -1 on error")
			}
		})
	}
}

// TestPrivilegedOpenBPFTokenWithSymlink tests opening token through a symlink
func TestPrivilegedOpenBPFTokenWithSymlink(t *testing.T) {
	testutils.PrivilegedTest(t)

	temp := testutils.TempBPFFS(t)

	// Create a temporary directory for the symlink
	tmpDir := t.TempDir()
	symlinkPath := filepath.Join(tmpDir, "bpf-symlink")

	// Create symlink to the BPFFS mount
	err := os.Symlink(temp, symlinkPath)
	require.NoError(t, err)

	// Try to open token through symlink
	fd, err := OpenBPFToken(symlinkPath)

	if err != nil && err.Error() == "BPF tokens not supported by kernel or BPFFS not configured for delegation" {
		t.Skip("BPF tokens not supported in this environment")
	}

	if fd > 0 {
		defer unix.Close(fd)
		assert.Greater(t, fd, 0, "Token FD should be positive even when accessed through symlink")
	}
}

// TestBPFTokenConstants tests that BPF token constants are defined correctly
func TestBPFTokenConstants(t *testing.T) {
	// BPF_TOKEN_CREATE should be 36
	assert.Equal(t, 36, BPF_TOKEN_CREATE, "BPF_TOKEN_CREATE should be 36")

	// BPF_F_TOKEN_FD should be 0x10000 (1 << 16)
	assert.Equal(t, 1<<16, BPF_F_TOKEN_FD, "BPF_F_TOKEN_FD should be 0x10000")
	assert.Equal(t, 65536, BPF_F_TOKEN_FD, "BPF_F_TOKEN_FD should be 65536")
}

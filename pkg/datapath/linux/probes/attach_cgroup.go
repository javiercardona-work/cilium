// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package probes

import (
	"errors"
	"fmt"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/features"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

// HaveAttachCgroup returns nil if the kernel is compiled with
// CONFIG_CGROUP_BPF.
//
// It's only an approximation and doesn't execute a successful cgroup attachment
// under the hood. If any unexpected errors are encountered, the original error
// is returned.
var HaveAttachCgroup = sync.OnceValue(func() error {
	// Load known-good program supported by the earliest kernels with cgroup
	// support.
	spec := &ebpf.ProgramSpec{
		Type:       ebpf.CGroupSKB,
		AttachType: ebpf.AttachCGroupInetIngress,
		Instructions: asm.Instructions{
			asm.LoadImm(asm.R0, 0, asm.DWord),
			asm.Return(),
		},
	}

	opts := ebpf.ProgramOptions{
		LogDisabled: true,
	}
	// Use global BPF token if available
	tokenFD := features.GetGlobalToken()
	if tokenFD > 0 {
		opts.TokenFD = tokenFD
	}
	p, err := ebpf.NewProgramWithOptions(spec, opts)
	if err != nil {
		// EPERM with a token means the kernel knows about cgroup progs but
		// the token doesn't allow it - treat as supported for feature detection.
		// Without a token, EPERM is a real permission error.
		if tokenFD > 0 && errors.Is(err, unix.EPERM) {
			return nil
		}
		return fmt.Errorf("create cgroup program: %w: %w", err, ebpf.ErrNotSupported)
	}
	defer p.Close()

	// Attaching to a non-cgroup node should result in EBADF when creating the
	// link, compared to EINVAL if the kernel does not support or was compiled
	// without CONFIG_CGROUP_BPF.
	_, err = link.AttachCgroup(link.CgroupOptions{Path: "/dev/null", Program: p, Attach: spec.AttachType})
	if errors.Is(err, unix.EBADF) {
		// The kernel checked the given file descriptor from within the cgroup prog
		// attach handler. Assume it supports attaching cgroup progs.
		return nil
	}
	// EPERM with a token means the kernel knows about this but the token
	// doesn't grant permission - treat as supported for feature detection.
	if tokenFD > 0 && errors.Is(err, unix.EPERM) {
		return nil
	}
	if err != nil {
		// Preserve the original error in the error string. Needs Go 1.20.
		return fmt.Errorf("link cgroup program to /dev/null: %w: %w", err, ebpf.ErrNotSupported)
	}

	return errors.New("attaching prog to /dev/null did not result in error")
})

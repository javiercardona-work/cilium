// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build linux

package bpf

import (
	"testing"

	ciliumebpf "github.com/cilium/ebpf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTrackedUsageFromActiveProgramsExpandsProgramArrays(t *testing.T) {
	programs := map[ciliumebpf.ProgramID]trackedProgram{
		1: {
			Name:    "cil_entry",
			Memlock: 100,
			MapIDs:  []ciliumebpf.MapID{10},
		},
		2: {
			Name:    "tail_call",
			Memlock: 200,
			MapIDs:  []ciliumebpf.MapID{11},
		},
	}
	maps := map[ciliumebpf.MapID]trackedMap{
		10: {
			Name:    "cilium_calls_00001",
			Memlock: 300,
			Type:    ciliumebpf.ProgramArray,
			Path:    "/sys/fs/bpf/tc/globals/cilium_calls_00001",
		},
		11: {
			Name:    "cilium_policy_v2_00001",
			Memlock: 400,
			Type:    ciliumebpf.Hash,
			Path:    "/sys/fs/bpf/tc/globals/cilium_policy_v2_00001",
		},
	}

	usage, err := trackedUsageFromActivePrograms(
		programs,
		maps,
		map[ciliumebpf.ProgramID]struct{}{1: {}},
		func(m trackedMap) ([]ciliumebpf.ProgramID, error) {
			if m.Name == "cilium_calls_00001" {
				return []ciliumebpf.ProgramID{2}, nil
			}
			return nil, nil
		},
	)
	require.NoError(t, err)

	assert.EqualValues(t, 2, usage.Programs)
	assert.EqualValues(t, 300, usage.ProgramBytes)
	assert.EqualValues(t, 2, usage.Maps)
	assert.EqualValues(t, 700, usage.MapBytes)
}

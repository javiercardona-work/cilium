// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build linux

package bpf

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"

	ciliumebpf "github.com/cilium/ebpf"
	ciliumlink "github.com/cilium/ebpf/link"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/cgroups"
	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	"github.com/cilium/cilium/pkg/metrics"
)

type trackedProgram struct {
	Name    string
	Memlock uint64
	MapIDs  []ciliumebpf.MapID
}

type trackedMap struct {
	Name    string
	Memlock uint64
	Type    ciliumebpf.MapType
	Path    string
}

type trackedBPFState struct {
	mu       sync.RWMutex
	programs map[ciliumebpf.ProgramID]trackedProgram
	maps     map[ciliumebpf.MapID]trackedMap
}

var ciliumOwnedBPFState = trackedBPFState{
	programs: make(map[ciliumebpf.ProgramID]trackedProgram),
	maps:     make(map[ciliumebpf.MapID]trackedMap),
}

func init() {
	metrics.RegisterBPFUsageProvider(ciliumOwnedBPFUsage)
}

func registerTrackedCollection(spec *ciliumebpf.CollectionSpec, coll *ciliumebpf.Collection, pinPath string) error {
	if spec == nil || coll == nil {
		return nil
	}

	nextPrograms := make(map[ciliumebpf.ProgramID]trackedProgram, len(coll.Programs))
	for name, prog := range coll.Programs {
		if prog == nil {
			continue
		}

		info, err := prog.Info()
		if err != nil {
			return fmt.Errorf("get program info for %s: %w", name, err)
		}

		id, ok := info.ID()
		if !ok || id == 0 {
			continue
		}

		memlock, _ := info.Memlock()
		mapIDs, _ := info.MapIDs()
		nextPrograms[id] = trackedProgram{
			Name:    info.Name,
			Memlock: memlock,
			MapIDs:  slices.Clone(mapIDs),
		}
	}

	nextMaps := make(map[ciliumebpf.MapID]trackedMap, len(coll.Maps))
	for name, m := range coll.Maps {
		if m == nil {
			continue
		}

		info, err := m.Info()
		if err != nil {
			return fmt.Errorf("get map info for %s: %w", name, err)
		}

		id, ok := info.ID()
		if !ok || id == 0 {
			continue
		}

		memlock, _ := info.Memlock()

		path := ""
		if pinPath != "" {
			if specMap := spec.Maps[name]; specMap != nil && specMap.Pinning != ciliumebpf.PinNone {
				path = filepath.Join(pinPath, specMap.Name)
			}
		}

		nextMaps[id] = trackedMap{
			Name:    info.Name,
			Memlock: memlock,
			Type:    m.Type(),
			Path:    path,
		}
	}

	ciliumOwnedBPFState.mu.Lock()
	for id, program := range nextPrograms {
		ciliumOwnedBPFState.programs[id] = program
	}
	for id, m := range nextMaps {
		ciliumOwnedBPFState.maps[id] = m
	}
	ciliumOwnedBPFState.mu.Unlock()

	return nil
}

func ciliumOwnedBPFUsage() (*metrics.BPFUsageStats, error) {
	programs, maps := snapshotTrackedObjects()

	activePrograms, err := discoverAttachedProgramIDs(programs)
	if err != nil {
		return nil, err
	}

	return trackedUsageFromActivePrograms(programs, maps, activePrograms, programArrayMembers)
}

func snapshotTrackedObjects() (map[ciliumebpf.ProgramID]trackedProgram, map[ciliumebpf.MapID]trackedMap) {
	ciliumOwnedBPFState.mu.RLock()
	defer ciliumOwnedBPFState.mu.RUnlock()

	programs := make(map[ciliumebpf.ProgramID]trackedProgram, len(ciliumOwnedBPFState.programs))
	for id, program := range ciliumOwnedBPFState.programs {
		programs[id] = trackedProgram{
			Name:    program.Name,
			Memlock: program.Memlock,
			MapIDs:  slices.Clone(program.MapIDs),
		}
	}

	maps := make(map[ciliumebpf.MapID]trackedMap, len(ciliumOwnedBPFState.maps))
	for id, m := range ciliumOwnedBPFState.maps {
		maps[id] = m
	}

	return programs, maps
}

func trackedUsageFromActivePrograms(
	programs map[ciliumebpf.ProgramID]trackedProgram,
	maps map[ciliumebpf.MapID]trackedMap,
	activePrograms map[ciliumebpf.ProgramID]struct{},
	readProgramArray func(trackedMap) ([]ciliumebpf.ProgramID, error),
) (*metrics.BPFUsageStats, error) {
	pending := make([]ciliumebpf.ProgramID, 0, len(activePrograms))
	seenPrograms := make(map[ciliumebpf.ProgramID]struct{}, len(activePrograms))
	activeMaps := map[ciliumebpf.MapID]struct{}{}
	seenProgArrays := map[ciliumebpf.MapID]struct{}{}

	for id := range activePrograms {
		pending = append(pending, id)
	}

	for len(pending) > 0 {
		id := pending[0]
		pending = pending[1:]

		if _, ok := seenPrograms[id]; ok {
			continue
		}
		seenPrograms[id] = struct{}{}

		prog, ok := programs[id]
		if !ok {
			continue
		}

		for _, mapID := range prog.MapIDs {
			activeMaps[mapID] = struct{}{}

			m, ok := maps[mapID]
			if !ok || m.Type != ciliumebpf.ProgramArray {
				continue
			}
			if _, ok := seenProgArrays[mapID]; ok {
				continue
			}
			seenProgArrays[mapID] = struct{}{}

			memberIDs, err := readProgramArray(m)
			if err != nil {
				return nil, fmt.Errorf("read program array %s: %w", m.Name, err)
			}

			for _, memberID := range memberIDs {
				if _, ok := seenPrograms[memberID]; ok {
					continue
				}
				pending = append(pending, memberID)
			}
		}
	}

	usage := &metrics.BPFUsageStats{}
	for id := range seenPrograms {
		prog, ok := programs[id]
		if !ok {
			continue
		}
		usage.Programs++
		usage.ProgramBytes += prog.Memlock
	}

	for id := range activeMaps {
		m, ok := maps[id]
		if !ok {
			continue
		}
		usage.Maps++
		usage.MapBytes += m.Memlock
	}

	return usage, nil
}

func discoverAttachedProgramIDs(programs map[ciliumebpf.ProgramID]trackedProgram) (map[ciliumebpf.ProgramID]struct{}, error) {
	activePrograms := map[ciliumebpf.ProgramID]struct{}{}

	if err := addPinnedLinkProgramIDs(activePrograms, programs); err != nil {
		return nil, err
	}
	if err := addTCFilterProgramIDs(activePrograms, programs); err != nil {
		return nil, err
	}
	if err := addXDPProgramIDs(activePrograms, programs); err != nil {
		return nil, err
	}
	if err := addCgroupProgramIDs(activePrograms, programs); err != nil {
		return nil, err
	}

	return activePrograms, nil
}

func addPinnedLinkProgramIDs(activePrograms map[ciliumebpf.ProgramID]struct{}, programs map[ciliumebpf.ProgramID]trackedProgram) error {
	root := CiliumPath()
	if _, err := os.Stat(root); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return fmt.Errorf("stat cilium bpffs path: %w", err)
	}

	return filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return nil
			}
			return err
		}
		if d.IsDir() {
			return nil
		}
		if !strings.Contains(path, string(filepath.Separator)+"links"+string(filepath.Separator)) {
			return nil
		}

		l, err := ciliumlink.LoadPinnedLink(path, &ciliumebpf.LoadPinOptions{})
		if err != nil {
			return nil
		}
		defer l.Close()

		info, err := l.Info()
		if err != nil || info == nil || info.Program == 0 {
			return nil
		}

		addIfTrackedCiliumProgram(activePrograms, programs, info.Program)
		return nil
	})
}

func addTCFilterProgramIDs(activePrograms map[ciliumebpf.ProgramID]struct{}, programs map[ciliumebpf.ProgramID]trackedProgram) error {
	links, err := safenetlink.LinkList()
	if err != nil {
		return fmt.Errorf("list links for tc filters: %w", err)
	}

	for _, l := range links {
		for _, parent := range []uint32{netlink.HANDLE_MIN_INGRESS, netlink.HANDLE_MIN_EGRESS} {
			filters, err := safenetlink.FilterList(l, parent)
			if err != nil {
				return fmt.Errorf("list tc filters on %s: %w", l.Attrs().Name, err)
			}

			for _, filter := range filters {
				bpfFilter, ok := filter.(*netlink.BpfFilter)
				if !ok || bpfFilter.Id <= 0 || !strings.HasPrefix(bpfFilter.Name, "cil_") {
					continue
				}

				addIfTrackedCiliumProgram(activePrograms, programs, ciliumebpf.ProgramID(bpfFilter.Id))
			}
		}
	}

	return nil
}

func addXDPProgramIDs(activePrograms map[ciliumebpf.ProgramID]struct{}, programs map[ciliumebpf.ProgramID]trackedProgram) error {
	links, err := safenetlink.LinkList()
	if err != nil {
		return fmt.Errorf("list links for xdp programs: %w", err)
	}

	for _, l := range links {
		xdp := l.Attrs().Xdp
		if xdp == nil || !xdp.Attached || xdp.ProgId == 0 {
			continue
		}
		addIfTrackedCiliumProgram(activePrograms, programs, ciliumebpf.ProgramID(xdp.ProgId))
	}

	return nil
}

func addCgroupProgramIDs(activePrograms map[ciliumebpf.ProgramID]struct{}, programs map[ciliumebpf.ProgramID]trackedProgram) error {
	cg, err := os.Open(cgroups.GetCgroupRoot())
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("open cgroup root: %w", err)
	}
	defer cg.Close()

	for _, attachType := range []ciliumebpf.AttachType{
		ciliumebpf.AttachCGroupInet4Connect,
		ciliumebpf.AttachCGroupUDP4Sendmsg,
		ciliumebpf.AttachCGroupUDP4Recvmsg,
		ciliumebpf.AttachCgroupInet4GetPeername,
		ciliumebpf.AttachCGroupInet4PostBind,
		ciliumebpf.AttachCGroupInet4Bind,
		ciliumebpf.AttachCGroupInet6Connect,
		ciliumebpf.AttachCGroupUDP6Sendmsg,
		ciliumebpf.AttachCGroupUDP6Recvmsg,
		ciliumebpf.AttachCgroupInet6GetPeername,
		ciliumebpf.AttachCGroupInet6PostBind,
		ciliumebpf.AttachCGroupInet6Bind,
		ciliumebpf.AttachCgroupInetSockRelease,
	} {
		result, err := ciliumlink.QueryPrograms(ciliumlink.QueryOptions{
			Target: int(cg.Fd()),
			Attach: attachType,
		})
		if errors.Is(err, unix.EINVAL) || errors.Is(err, unix.EPERM) || errors.Is(err, unix.EBADF) {
			continue
		}
		if err != nil {
			return fmt.Errorf("query cgroup attach type %s: %w", attachType, err)
		}

		for _, program := range result.Programs {
			addIfTrackedCiliumProgram(activePrograms, programs, program.ID)
		}
	}

	return nil
}

func addIfTrackedCiliumProgram(activePrograms map[ciliumebpf.ProgramID]struct{}, programs map[ciliumebpf.ProgramID]trackedProgram, id ciliumebpf.ProgramID) {
	program, ok := programs[id]
	if !ok {
		return
	}
	if !strings.HasPrefix(program.Name, "cil_") && !strings.HasPrefix(program.Name, "tail_") {
		return
	}
	activePrograms[id] = struct{}{}
}

func programArrayMembers(m trackedMap) ([]ciliumebpf.ProgramID, error) {
	if m.Path == "" {
		return nil, nil
	}

	pm, err := ciliumebpf.LoadPinnedMap(m.Path, nil)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer pm.Close()

	var (
		slot    uint32
		progID  uint32
		members []ciliumebpf.ProgramID
	)

	iter := pm.Iterate()
	for iter.Next(&slot, &progID) {
		if progID == 0 {
			continue
		}
		members = append(members, ciliumebpf.ProgramID(progID))
	}
	if err := iter.Err(); err != nil {
		return nil, err
	}

	return members, nil
}

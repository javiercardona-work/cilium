// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package agent

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/cilium/ebpf"
	"github.com/cilium/hive/cell"
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/pkg/bpf"
	datapathTypes "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/eventsmap"
)

// Cell provides the monitor agent, which monitors the cilium events perf event
// buffer and forwards events to consumers/listeners. It also handles
// multicasting of other agent events.
var Cell = cell.Module(
	"monitor-agent",
	"Consumes the cilium events map and distributes those and other agent events",

	cell.Provide(newMonitorAgent),
	cell.Config(defaultConfig),
)

type AgentConfig struct {
	// EnableMonitor enables the monitor unix domain socket server
	EnableMonitor bool

	// MonitorQueueSize is the size of the monitor event queue
	MonitorQueueSize int
}

var defaultConfig = AgentConfig{
	EnableMonitor: true,
}

func (def AgentConfig) Flags(flags *pflag.FlagSet) {
	flags.Bool("enable-monitor", def.EnableMonitor, "Enable the monitor unix domain socket server")
	flags.Int("monitor-queue-size", 0, "Size of the event queue when reading monitor events")
}

type agentParams struct {
	cell.In

	Lifecycle cell.Lifecycle
	Log       *slog.Logger
	Config    AgentConfig
	EventsMap eventsmap.Map    `optional:"true"`
	Loader    datapathTypes.Loader
}

func newMonitorAgent(params agentParams) Agent {
	ctx, cancel := context.WithCancel(context.Background())
	agent := newAgent(ctx, params.Log)

	params.Lifecycle.Append(cell.Hook{
		OnStart: func(cell.HookContext) error {
			if params.EventsMap == nil {
				// If there's no event map, function only for agent events.
				params.Log.Info("No eventsmap: monitor works only for agent events.")
				return nil
			}

			// Check if the underlying map is available (it may not exist yet
			// if BPF programs haven't been loaded)
			ebpfMap := params.EventsMap.EbpfMap()
			if ebpfMap == nil {
				params.Log.Info("Events map not yet available, will attach after host datapath initialization")
				go attachAfterInit(ctx, params, agent)
				return nil
			}

			return attachAndServe(ctx, params, agent, ebpfMap)
		},
		OnStop: func(cell.HookContext) error {
			cancel()
			return nil
		},
	})

	return agent
}

// attachAfterInit waits for the host datapath to be initialized (which pins
// the cilium_events ring buffer to bpffs), then loads the pinned map and
// attaches the monitor agent to it. This handles the case where the events
// map does not exist yet at agent startup because BPF programs haven't been
// loaded.
func attachAfterInit(ctx context.Context, params agentParams, agent *agent) {
	select {
	case <-params.Loader.HostDatapathInitialized():
	case <-ctx.Done():
		return
	}

	path := bpf.MapPath(params.Log, eventsmap.MapName)
	ebpfMap, err := ebpf.LoadPinnedMap(path, nil)
	if err != nil {
		params.Log.Error("Failed to load events map after host datapath initialization",
			logfields.Error, err, "path", path)
		return
	}

	if err := attachAndServe(ctx, params, agent, ebpfMap); err != nil {
		params.Log.Error("Failed to attach monitor agent after host datapath initialization",
			logfields.Error, err)
		ebpfMap.Close()
		return
	}

	params.Log.Info("Successfully attached monitor agent to events map after host datapath initialization")
}

// attachAndServe attaches the monitor agent to the given events map and
// optionally starts serving the monitor API.
func attachAndServe(ctx context.Context, params agentParams, agent *agent, ebpfMap *ebpf.Map) error {
	err := agent.AttachToEventsMap(ebpfMap, defaults.MonitorBufferPages)
	if err != nil {
		params.Log.Error("encountered error when attaching the monitor agent to eventsmap", logfields.Error, err)
		return fmt.Errorf("encountered error when attaching the monitor agent: %w", err)
	}

	if params.Config.EnableMonitor {
		queueSize := params.Config.MonitorQueueSize
		if queueSize == 0 {
			possibleCPUs, err := ebpf.PossibleCPU()
			if err != nil {
				params.Log.Error("failed to get number of possible CPUs", logfields.Error, err)
				return fmt.Errorf("failed to get number of possible CPUs: %w", err)
			}
			queueSize = min(possibleCPUs*defaults.MonitorQueueSizePerCPU, defaults.MonitorQueueSizePerCPUMaximum)
		}

		err = ServeMonitorAPI(ctx, params.Log, agent, queueSize)
		if err != nil {
			params.Log.Error("encountered error serving monitor agent API", logfields.Error, err)
			return fmt.Errorf("encountered error serving monitor agent API: %w", err)
		}
	}
	return nil
}

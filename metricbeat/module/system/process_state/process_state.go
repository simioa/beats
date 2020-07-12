// Licensed to Elasticsearch B.V. under one or more contributor
// license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright
// ownership. Elasticsearch B.V. licenses this file to you under
// the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

// +build darwin freebsd linux windows

package process_state

import (
	"regexp"

	"github.com/pkg/errors"

	"github.com/elastic/beats/v7/libbeat/common"
	"github.com/elastic/beats/v7/libbeat/metric/system/process"
	"github.com/elastic/beats/v7/metricbeat/mb"
	"github.com/elastic/beats/v7/metricbeat/mb/parse"
)

// init registers the MetricSet with the central registry.
// The New method will be called after the setup of the module and before starting to fetch data
func init() {
	mb.Registry.MustAddMetricSet("system", "process_state", New,
		mb.WithHostParser(parse.EmptyHostParser),
		mb.DefaultMetricSet(),
	)
}

type processState struct {
	cmdline string
	name    string
	running bool
}

// MetricSet type defines all fields of the MetricSet
// As a minimum it must inherit the mb.BaseMetricSet fields, but can be extended with
// additional entries. These variables can be used to persist data or configuration between
// multiple fetch calls.
type MetricSet struct {
	mb.BaseMetricSet
	stats *process.Stats
	procs []*procMatcher
}

// New create a new instance of the MetricSet
// Part of new is also setting up the configuration by processing additional
// configuration entries if needed.
func New(base mb.BaseMetricSet) (mb.MetricSet, error) {
	var config Config
	if err := base.Module().UnpackConfig(&config); err != nil {
		return nil, err
	}
	m := &MetricSet{
		BaseMetricSet: base,
		stats: &process.Stats{
			Procs: []string{".*"},
			IncludeTop: process.IncludeTopConfig{
				Enabled: false,
			},
		},
		procs: config.Procs,
	}
	err := m.stats.Init()
	if err != nil {
		return nil, err
	}
	return m, nil
}

// Fetch methods implements the data gathering and data conversion to the right format
// It returns the event which is then forward to the output. In case of an error, a
// descriptive error must be returned.
func (m *MetricSet) Fetch(r mb.ReporterV2) error {
	procs, err := m.stats.Get()
	if err != nil {
		return errors.Wrap(err, "process stats")
	}

	for _, checkedProc := range m.procs {
		procState, err := getProcessState(procs, checkedProc.Process)
		if err != nil {
			return errors.Wrap(err, "process state")
		}
		event := common.MapStr{
			"procString": checkedProc.Process,
			"alias":      checkedProc.Alias,
			"running":    procState.running,
		}
		if procState.running {
			event.Put("process", common.MapStr{
				"name":         procState.name,
				"command_line": procState.cmdline,
			})
		}
		r.Event(mb.Event{
			MetricSetFields: event,
		})
	}

	return nil
}

func getProcessState(runningProcesses []common.MapStr, process string) (processState, error) {
	procState := processState{
		running: false,
	}
	processPattern, err := regexp.Compile(process)
	if err != nil {
		return procState, err
	}
	for _, runningProcess := range runningProcesses {
		if processPattern.MatchString(runningProcess["cmdline"].(string)) {
			procState.cmdline = runningProcess["cmdline"].(string)
			procState.name = runningProcess["name"].(string)
			procState.running = true
			return procState, nil
		}
	}
	return procState, nil
}

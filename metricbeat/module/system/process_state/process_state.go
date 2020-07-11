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
	var processList []string
	for _, process := range config.Procs {
		processList = append(processList, process.Name)
	}
	m := &MetricSet{
		BaseMetricSet: base,
		stats: &process.Stats{
			Procs: processList,
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
		running, err := getProcessState(procs, checkedProc.Name, checkedProc.Args)
		if err != nil {
			return errors.Wrap(err, "process state")
		}
		event := common.MapStr{
			"process": common.MapStr{
				"name":  checkedProc.Name,
				"args":  checkedProc.Args,
				"alias": checkedProc.Alias,
			},
			"running": running,
		}
		r.Event(mb.Event{
			MetricSetFields: event,
		})
	}

	return nil
}

func getProcessState(runningProcesses []common.MapStr, processName string, processArgs string) (bool, error) {
	running := false
	namePattern, err := regexp.Compile(processName)
	if err != nil {
		return false, err
	}
	argsPattern, err := regexp.Compile(processArgs)
	if err != nil {
		return false, err
	}
	for _, runningProcess := range runningProcesses {
		if namePattern.MatchString(runningProcess["name"].(string)) {
			if argsPattern.MatchString(runningProcess["cmdline"].(string)) {
				running = true
			}
		}
	}
	return running, nil
}

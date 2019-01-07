/*
 * Copyright (C) 2018 Red Hat, Inc.
 *
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 *
 */

package traversal

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/skydive-project/skydive/common"
	"github.com/skydive-project/skydive/graffiti/graph/traversal"
)

// SFlowMetricsTraversalExtension describes a new extension to enhance the topology
type SFlowMetricsTraversalExtension struct {
	SFlowMetricsToken traversal.Token
}

// SFlowMetricsGremlinTraversalStep describes the Metrics gremlin traversal step
type SFlowMetricsGremlinTraversalStep struct {
	traversal.GremlinTraversalContext
}

// NewSFlowMetricsTraversalExtension returns a new graph traversal extension
func NewSFlowMetricsTraversalExtension() *SFlowMetricsTraversalExtension {
	return &SFlowMetricsTraversalExtension{
		SFlowMetricsToken: traversalSFlowMetricsToken,
	}
}

// ScanIdent returns an associated graph token
func (e *SFlowMetricsTraversalExtension) ScanIdent(s string) (traversal.Token, bool) {
	switch s {
	case "SFLOWMETRICS":
		return e.SFlowMetricsToken, true
	}
	return traversal.IDENT, false
}

// ParseStep parse SFlowmetrics step
func (e *SFlowMetricsTraversalExtension) ParseStep(t traversal.Token, p traversal.GremlinTraversalContext) (traversal.GremlinTraversalStep, error) {
	switch t {
	case e.SFlowMetricsToken:
		return &SFlowMetricsGremlinTraversalStep{GremlinTraversalContext: p}, nil
	}
	return nil, nil
}

// Exec executes the SFlowmetrics step
func (s *SFlowMetricsGremlinTraversalStep) Exec(last traversal.GraphTraversalStep) (traversal.GraphTraversalStep, error) {
	switch tv := last.(type) {
	case *traversal.GraphTraversalV:
		return SFlowMetrics(s.StepContext, tv), nil
	}
	return nil, traversal.ErrExecutionError
}

// Reduce sflowmetrics step
func (s *SFlowMetricsGremlinTraversalStep) Reduce(next traversal.GremlinTraversalStep) (traversal.GremlinTraversalStep, error) {
	return next, nil
}

// Context sflowmetrics step
func (s *SFlowMetricsGremlinTraversalStep) Context() *traversal.GremlinTraversalContext {
	return &s.GremlinTraversalContext
}

// SFlowMetricsTraversalStep traversal step metric interface counters
type SFlowMetricsTraversalStep struct {
	GraphTraversal *traversal.GraphTraversal
	sflowmetrics   map[string][]common.Metric
	error          error
}

// Sum aggregates integer values mapped by 'key' cross flows
func (m *SFlowMetricsTraversalStep) Sum(ctx traversal.StepContext, keys ...interface{}) *traversal.GraphTraversalValue {
	if m.error != nil {
		return traversal.NewGraphTraversalValueFromError(m.error)
	}

	if len(keys) > 0 {
		if len(keys) != 1 {
			return traversal.NewGraphTraversalValueFromError(fmt.Errorf("Sum requires 1 parameter"))
		}

		key, ok := keys[0].(string)
		if !ok {
			return traversal.NewGraphTraversalValueFromError(errors.New("Argument of Sum must be a string"))
		}

		var total int64
		for _, sflowmetrics := range m.sflowmetrics {
			for _, sflowmetric := range sflowmetrics {
				value, err := sflowmetric.GetFieldInt64(key)
				if err != nil {
					return traversal.NewGraphTraversalValueFromError(err)
				}
				total += value
			}
		}
		return traversal.NewGraphTraversalValue(m.GraphTraversal, total)
	}

	var total common.Metric
	for _, sflowmetrics := range m.sflowmetrics {
		for _, sflowmetric := range sflowmetrics {
			if total == nil {
				total = sflowmetric
			} else {
				total = total.Add(sflowmetric)
			}

			if total.GetStart() > sflowmetric.GetStart() {
				total.SetStart(sflowmetric.GetStart())
			}

			if total.GetLast() < sflowmetric.GetLast() {
				total.SetLast(sflowmetric.GetLast())
			}
		}
	}

	return traversal.NewGraphTraversalValue(m.GraphTraversal, total)
}

// Aggregates merges multiple SFlowmetrics array into one by summing overlapping
// metrics. It returns a unique array will all the aggregated metrics.
func (m *SFlowMetricsTraversalStep) Aggregates(ctx traversal.StepContext, s ...interface{}) *SFlowMetricsTraversalStep {
	if m.error != nil {
		return NewSFlowMetricsTraversalStepFromError(m.error)
	}

	sliceLength := defaultAggregatesSliceLength
	if len(s) != 0 {
		sl, ok := s[0].(int64)
		if !ok || sl <= 0 {
			return NewSFlowMetricsTraversalStepFromError(fmt.Errorf("Aggregatessflow parameter has to be a positive number"))
		}
		sliceLength = sl * 1000 // Millisecond
	}

	context := m.GraphTraversal.Graph.GetContext()

	var start, last int64
	if context.TimeSlice != nil {
		start, last = context.TimeSlice.Start, context.TimeSlice.Last
	} else {
		// no time context then take min/max of the metrics
		for _, array := range m.sflowmetrics {
			for _, sflowmetric := range array {
				if start == 0 || start > sflowmetric.GetStart() {
					start = sflowmetric.GetStart()
				}

				if last < sflowmetric.GetLast() {
					last = sflowmetric.GetLast()
				}
			}
		}
	}

	steps := (last - start) / sliceLength
	if (last-start)%sliceLength != 0 {
		steps++
	}

	aggregated := make([]common.Metric, steps, steps)
	for _, sflowmetrics := range m.sflowmetrics {
		aggregateMetrics(sflowmetrics, start, last, sliceLength, aggregated)
	}

	// filter out empty metrics
	final := make([]common.Metric, 0)
	for _, e := range aggregated {
		if e != nil {
			final = append(final, e)
		}
	}

	return NewSFlowMetricsTraversalStep(m.GraphTraversal, map[string][]common.Metric{"Aggregated": final})
}

// Values returns the graph sflowmetric values
func (m *SFlowMetricsTraversalStep) Values() []interface{} {
	if len(m.sflowmetrics) == 0 {
		return []interface{}{}
	}
	return []interface{}{m.sflowmetrics}
}

// MarshalJSON serialize in JSON
func (m *SFlowMetricsTraversalStep) MarshalJSON() ([]byte, error) {
	values := m.Values()
	m.GraphTraversal.RLock()
	defer m.GraphTraversal.RUnlock()
	return json.Marshal(values)
}

// Error returns error present at this step
func (m *SFlowMetricsTraversalStep) Error() error {
	return m.error
}

// Count step
func (m *SFlowMetricsTraversalStep) Count(ctx traversal.StepContext, s ...interface{}) *traversal.GraphTraversalValue {
	return traversal.NewGraphTraversalValue(m.GraphTraversal, len(m.sflowmetrics))
}

// PropertyKeys returns sflowmetric fields
func (m *SFlowMetricsTraversalStep) PropertyKeys(ctx traversal.StepContext, keys ...interface{}) *traversal.GraphTraversalValue {
	if m.error != nil {
		return traversal.NewGraphTraversalValueFromError(m.error)
	}

	var s []string

	if len(m.sflowmetrics) > 0 {
		for _, sflowmetrics := range m.sflowmetrics {
			// all SFlowMetric struct are the same, take the first one
			if len(sflowmetrics) > 0 {
				s = sflowmetrics[0].GetFieldKeys()
				break
			}
		}
	}

	return traversal.NewGraphTraversalValue(m.GraphTraversal, s)
}

// NewSFlowMetricsTraversalStep creates a new traversal sflowmetric step
func NewSFlowMetricsTraversalStep(gt *traversal.GraphTraversal, sflowmetrics map[string][]common.Metric) *SFlowMetricsTraversalStep {
	m := &SFlowMetricsTraversalStep{GraphTraversal: gt, sflowmetrics: sflowmetrics}
	return m
}

// NewSFlowMetricsTraversalStepFromError creates a new traversal metric step
func NewSFlowMetricsTraversalStepFromError(err error) *SFlowMetricsTraversalStep {
	m := &SFlowMetricsTraversalStep{error: err}
	return m
}

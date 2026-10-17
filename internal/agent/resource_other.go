//go:build !linux

package agent

import "context"

type resourceSampler struct{}

func newResourceSampler() *resourceSampler          { return &resourceSampler{} }
func (s *resourceSampler) run(ctx context.Context)  { <-ctx.Done() }
func (s *resourceSampler) metrics() map[string]any  { return map[string]any{} }
func (s *resourceSampler) addMasscanPID(pid int)    {}
func (s *resourceSampler) removeMasscanPID(pid int) {}

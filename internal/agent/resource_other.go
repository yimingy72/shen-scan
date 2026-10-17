//go:build !linux

package agent

import "context"

const toolRSSSupported = false

type resourceSampler struct{ tools toolTracker }

func newResourceSampler() *resourceSampler         { return &resourceSampler{} }
func (s *resourceSampler) run(ctx context.Context) { <-ctx.Done() }
func (s *resourceSampler) metrics() map[string]any { return s.tools.metrics() }

// Counts follow direct child Start/Wait lifetimes. No unavailable RSS is invented.
func readToolProcess(int) toolProcessSample { return toolProcessSample{alive: true} }

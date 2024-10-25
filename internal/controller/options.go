package controller // import "go.opentelemetry.io/ebpf-profiler/internal/controller"

import "go.opentelemetry.io/ebpf-profiler/reporter"

type Option interface {
	applyOption(*Controller) *Controller
}
type controllerOptionFunc func(*Controller) *Controller

func (f controllerOptionFunc) applyOption(c *Controller) *Controller {
	return f(c)
}

// WithReporter sets a custom reporter that will be run for that controller.
// This defaults to [reporter.OTLPReporter]
func WithReporter(rep reporter.Reporter) Option {
	return controllerOptionFunc(func(c *Controller) *Controller {
		c.reporter = rep
		return c
	})
}

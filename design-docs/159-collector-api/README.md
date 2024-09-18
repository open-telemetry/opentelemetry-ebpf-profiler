# Public API to run the agent as a collector receiver

## Meta

- **Author(s)**: @dmathieu
- **Start Date**: September 18 2024
- **Goal End Date**:
- **Primary Reviewers**: @open-telemetry/ebpf-profiler-maintainers

## Problem

As we move forward with the OpenTelemetry Collector being able to handle
profiles, we also want the ebpf agent to be able to run as a collector
receiver.
See [PR #87](https://github.com/open-telemetry/opentelemetry-ebpf-profiler/pull/87)

We also intend to provide a collector distribution that will provide the agent,
which most folks will want to use.

Some specific use cases may want to build their own distributions though. In
which case they will have to be able to rely on a stable public API allowing
them to build a receiver to use in their distribution.

This design document aims to describe the public API we will be exposing.

## Success Criteria

Folks need to be able to use a clear and consise public API when they wish to
build their own distribution of the collector to use as an ebpf agent.

### Scope

This document describes what the API will look like.

Like any other receiver (see the
[filelogreceiver](https://pkg.go.dev/github.com/open-telemetry/opentelemetry-collector-contrib/receiver/filelogreceiver)
as an example), there is a single method we need to expose: `NewFactory`, which
returns a [receiver
Factory](https://pkg.go.dev/go.opentelemetry.io/collector/receiver#Factory)
that can handle profiles.

Since the scope of this API is so small, the main question is in which package
the API should be located.

## Proposed Solutions

We will expose the `NewFactory` method as part of the **root** package within
the ebpf repository, meaning importing and using it will be as follows:

```golang
package main

import (
	agent "github.com/open-telemetry/opentelemetry-ebpf-profiler"
)

func main() {
	factory := agent.NewFactory()
	// Use the factory
}
```

The intent behind making the factory part of the root of the repository is to
make it clear to folks that the factory is the root of the agent running as a
collector receiver.

## Alternatives

We could also move have the receiver in a sub-package:

```golang
package main

import (
	"github.com/open-telemetry/opentelemetry-ebpf-profiler/collector"
)

func main() {
	factory := collector.NewFactory()
	// Use the factory
}
```

This would have the advantage of allowing us to provide a `go.mod` for this
package specifically, and avoid having the collector components as dependencies
of the main agent.

Since the vision is that the agent should always run as a collector receiver,
splitting things into multiple Go modules is probably unnecessary though.

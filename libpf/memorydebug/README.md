This package contains code to add memory profiling and the automated writing of heapdumps and heap
profiling samples to a given Go program, and uses build tags to only provide that functionality in
debug builds.

The profiling agent uses this functionality at the moment. To enable it, do ```go build -tags debug```
for the host agent. When running the agent with -v, it will log debug output showing memory
allocations, and also write memory profiles if 50 megabytes heap usage is exceeded to /tmp. It
will also write full heap dumps if heap usage exceeds 100 megabytes.

You can inspect the heap profiles using "go tool pprof (filename)", and then typing "web" or "text"
to either inspect graphical output or a text-based heap profile.

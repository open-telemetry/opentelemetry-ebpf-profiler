# Off-CPU profiling

The `offcpu` extension records stack traces for time that threads spend off CPU.
Enable it in the Collector configuration and add it to the service extensions:

```yaml
extensions:
  offcpu:
    threshold: 0.1
    map_entries: 4096
    mode: tracepoint

service:
  extensions: [offcpu]
```

## Configuration

- `threshold` is the probability of capturing a scheduler event. It must be in
  the range `(0.0, 1.0]`. Higher values produce more samples and more overhead.
- `map_entries` is the maximum number of pending off-CPU traces. `0` uses the
  default of `4096`. Larger maps reduce eviction under high thread counts but
  consume more kernel memory.
- `mode` selects the scheduler hooks. An empty value defaults to `tracepoint`.

The default `tracepoint` mode captures the stack when a task switches out and
completes the sample when the same task switches back in. It first tries the
BTF-enabled `sched_switch` tracepoint and falls back automatically to the raw
tracepoint when BTF attachment is unavailable. This mode avoids dependence on
kernel function names and is the recommended setting.

The `tracepoint-kprobe` compatibility mode retains the older implementation:
it records the switch-out time at the regular `sched_switch` tracepoint and
captures the stack from a `finish_task_switch` kprobe. Use it only when the
default tracepoint mode cannot be loaded. Because kernel function names and
availability vary, this mode is less portable than the default.

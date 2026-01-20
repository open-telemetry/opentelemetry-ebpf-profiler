When GC is running, we will abort unwinding the ruby stack and just push dummy
frames. This means that we must disable GC before taking coredumps if we don't
want to accidentally snapshot the process state while GC is running.

If we do want the coredump to be during GC, we must take extra steps to ensure
this.

# Coredump with GC

If we do want to ensure that GC is running, the easiest way is to use GDB:

```
gdb $(which ruby)

(gdb) start tools/coredump/testsources/ruby/loop.rb

(gdb) break gc_mark_finish

(gdb) continue
```

To break during sweeping, `gc_sweep_step` can be used.

We should be able to verify the GC state by running:

```
(gdb) print objectspace.flags
$2 = {mode = 2, immediate_sweep = 0, dont_gc = 0, dont_incremental = 0, during_gc = 1, during_compacting = 0, during_reference_updating = 0, gc_stressful = 0, has_newobj_hook = 0, during_minor_gc = 1,
  during_incremental_marking = 0, measure_gc = 1}
```

Where mode corresponds to [this enum](https://github.com/ruby/ruby/blob/16af72790837ffb10c87ec23f99a6c519abc21e3/gc/default/default.c#L460-L465):

```
enum gc_mode {
    gc_mode_none,
    gc_mode_marking,
    gc_mode_sweeping,
    gc_mode_compacting,
};
```

Then, take the coredump.

First write the coredump filter:

```
echo 0x3f > /proc/$(pidof ruby)/coredump_filter
```

Then within gdb:

```
gcore COREDUMP_NAME
```

We should now have a coredump that is being taken during GC

# Coredump without GC

Add `GC.disable` to the ruby script before running it to ensure GC won't be
running when the coredump is taken

#!/usr/bin/env python3
"""Generate a deep Python call stack with interleaved Python/C frames.

Each Python function call goes through CPython's C eval loop
(_PyFunction_Vectorcall → _PyEval_Vector → _PyEval_EvalFrame →
_PyEval_EvalFrameDefault → do_call_core), creating ~5 native frames
between every Python frame. With 20 class.__call__ levels, this
produces ~100 native frames interleaved with ~20 Python frames,
requiring ~40 Python↔native unwinder transitions.

On main (tail-call design), this exceeds the 29 tail call limit and
truncates the stack. With the combined Python+native loop, the full
stack is unwound.
"""
import os
import signal
import traceback

class Level:
    """Each subclass's __call__ invokes the next level via slot_tp_call."""
    pass

# Generate 20 levels of classes that chain-call each other.
# Each __call__ goes through CPython's slot_tp_call (C) which creates
# native frames between the Python frames.
NUM_LEVELS = 20

def _make_levels():
    levels = []
    for i in range(NUM_LEVELS):
        levels.append(type(f'Level{i}', (Level,), {}))

    # Wire up: each level's __call__ invokes the next level
    for i in range(NUM_LEVELS - 1):
        next_cls = levels[i + 1]
        # Use a closure to capture next_cls
        def make_call(nxt):
            def __call__(self):
                return nxt()()
            return __call__
        levels[i].__call__ = make_call(next_cls)

    # Last level: print the stack and hang so we can capture a coredump
    def last_call(self):
        print(f"Reached level {NUM_LEVELS - 1}, PID={os.getpid()}", flush=True)
        print("Stack trace:", flush=True)
        traceback.print_stack()
        print(f"\nWaiting for coredump (kill -ILL {os.getpid()})...", flush=True)
        signal.pause()

    levels[-1].__call__ = last_call
    return levels

def main():
    levels = _make_levels()
    levels[0]()()

if __name__ == '__main__':
    main()

-module(canonical_beam).
-export([start/0, caller/1, target/1]).
start() -> loop(1).
loop(N) -> caller(N), loop(N + 1).
caller(N) -> target(N) + 1.
target(N) -> erlang:monotonic_time() + N.

% Enable frame pointers with +JPperf fp when capturing these fixtures.

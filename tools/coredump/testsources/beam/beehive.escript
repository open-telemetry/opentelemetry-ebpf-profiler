#!/usr/bin/env escript

main(_) ->
    PrimeChecker = spawn(fun F() ->
        receive {Number, From} -> From ! {is_prime, Number, is_prime(Number)} end,
        F() end),
    Summer = spawn(fun() -> summer_loop(0, 0) end),
    lists:foreach(fun(N) -> PrimeChecker ! {N, self()} end, lists:seq(1, 1000000)),
    main_loop(Summer).

main_loop(Summer) ->
    receive Message -> handle_message(Summer, Message) end,
    main_loop(Summer).

handle_message(Summer, {is_prime, Number, true}) ->
    Summer ! {Number, self()};
handle_message(_, {sum, N, NewSum}) ->
    io:format("~w: ~w~n", [N, NewSum]);
handle_message(_, _) ->
    ok.

is_prime(Number) ->
    Candidates = lists:seq(2, trunc(math:sqrt(Number))),
    lists:all(fun(N) -> Number rem N =/= 0 end, Candidates).

summer_loop(N, PreviousSum) ->
    receive {Number, From} ->
        NewSum = PreviousSum + Number,
        From ! {sum, N + 1, NewSum},
        summer_loop(N + 1, NewSum) end.

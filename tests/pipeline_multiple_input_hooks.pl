
:- module(pipeline_multiple_input_hooks, [connected/4, signatures/3]).

% connected(Upstream Module, OGate, Downstream Module, IGate)
connected(a, 0, d, 0).
connected(b, 0, d, 0).
connected(c, 0, d, 0).
connected(a, 1, d, 1).
connected(b, 1, d, 1).

% signatures(Module name, Input sigs, Output sigs)
signatures(a, [], [Out0, Out1]) :-
    Out0 = ([ethernet, ipv4, payload], []),
    Out1 = ([ethernet, ipv6, payload], []).

signatures(b, [], [Out0, Out1]) :-
    Out0 = ([ethernet, ipv6, payload], []),
    Out1 = ([ethernet, payload], []).

signatures(c, [], [Out0]) :-
    Out0 = ([ethernet, ipv4, payload], []).

signatures(d, [In0, In1], []) :-
    In0 = ([ethernet, ip, payload], []),
    In1 =([payload], []).

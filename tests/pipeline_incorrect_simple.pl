
:- module(pipeline_incorrect_simplep, [connected/4, signatures/3]).

% connected(Upstream Module, OGate, Downstream Module, IGate)
connected(a, 0, d, 0).
connected(b, 0, d, 0).
connected(c, 0, d, 0).
connected(a, 1, d, 1).
connected(b, 1, d, 1).

% signatures(Module name, Input sigs, Output sigs)
signatures(a, [], [Out0, Out1]) :-
    Out0 = ([ethernet-[eth_test1-1], ipv4, payload], []),
    Out1 = ([ethernet, ipv6, payload], [agnostic_test3-1]).

signatures(b, [], [Out0, Out1]) :-
    Out0 = ([ethernet-[eth_test1-2], ipv6, payload], []),
    Out1 = ([ethernet, payload], [agnostic_test3-2]).

signatures(c, [], [Out0]) :-
    Out0 = ([ethernet-[eth_test1-3], ipv4, payload], []).

signatures(d, [In0, In1], []) :-
    In0 = ([ethernet-[eth_test1-4], ip, payload], []),
    In1 =([ip, payload], [agnostic_test3-1]).

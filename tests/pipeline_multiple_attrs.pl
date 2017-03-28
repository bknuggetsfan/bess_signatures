
:- module(pipeline_simple, [connected/4, signatures/3]).

% connected(Upstream Module, OGate, Downstream Module, IGate)
connected(a, 0, b, 0).
connected(c, 0, d, 0).

% signatures(Module name, Input sigs, Output sigs)
signatures(a, [], [Out0]) :-
    Out0 = ([ethernet-[eth_test1-1], ipv4-[checksum-correct, destAddressSet-correct], payload], [agnostic_test1-correct, agnostic_test2-2, agnostic_test3-incorrect]).

signatures(b, [In0], [Out0, Out1]) :-
    In0 = ([ethernet-[eth_test1-2], payload], [agnostic_test1-correct, agnostic_test2-3, agnostic_test3-incorrect]),
    Out0 = ([ethernet, ipv4, payload], []),
    Out1 = ([ethernet, ipv6, payload], []).

signatures(c, [In0], [Out0]) :-
    In0 = ([ethernet, ipv4, payload], []),
    Out0 = ([ethernet-[eth_test1-1], ipv4-[checksum-correct, destAddressSet-correct], payload], [agnostic_test3-correct]).

signatures(d, [In0], [Out0]) :-
    In0 = ([ethernet, ip, payload], []),
    Out0 = ([ethernet, ip, payload], []).

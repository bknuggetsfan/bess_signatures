
:- module(pipeline_combine_overloaded_igates, [connected/4, signatures/3, no_path/3]).

% connected(Upstream Module, OGate, Downstream Module, IGate)
connected(a, 0, e, 0).
connected(b, 0, e, 0).
connected(c, 0, e, 0).
connected(a, 1, e, 1).
connected(b, 1, e, 1).
connected(d, 0, e, 2).
connected(d, 1, e, 2).


% signatures(Module name, Input sigs, Output sigs)
signatures(a, [], [Out0, Out1]) :-
    Out0 = ([ethernet-[eth_test1-1], ipv4, payload], []),
    Out1 = ([ethernet, ipv4, payload], [agnostic_test3-1]).

signatures(b, [], [Out0, Out1]) :-
    Out0 = ([ethernet-[eth_test1-2], ip, payload], []),
    Out1 = ([ethernet, ipv4, payload], [agnostic_test3-1]).

signatures(c, [], [Out0]) :-
    Out0 = ([ethernet-[eth_test1-3], ip, payload], []).

signatures(d, [], [Out0, Out1]) :-
    Out0 = ([ethernet-[eth_test1-3], ipv6, payload], []),
    Out1 = ([ethernet-[eth_test1-3], ipv6, payload], []).

signatures(e, [In0, In1, In2], [Out0, Out1, Out2]) :-
    In0 = ([ethernet-[eth_test1-4], ip, payload], []),
    In1 =([payload], [agnostic_test3-1]),
    In2 = ([payload], []),
    Out0 = ([payload], []),
    Out1 = ([payload], []),
    Out2 = ([payload], []).

%no_path(module, igate, ogate)
no_path(e, 2, 1).
no_path(e, 0, 1).
no_path(e, 1, 2).
no_path(e, 0, 2).
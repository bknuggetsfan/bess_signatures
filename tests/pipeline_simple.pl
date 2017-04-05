
:- module(pipeline_simple, [connected/4, signatures/3]).

% connected(Upstream Module, OGate, Downstream Module, IGate)
connected(a, 0, b, 0).
connected(b, 0, c, 0).
connected(b, 1, d, 0).
connected(c, 0, e, 0).
connected(e, 0, f, 0).
connected(d, 0, g, 0).
connected(g, 0, h, 0).

% signatures(Module name, Input sigs, Output sigs)
signatures(a, [], [Out0]) :-
	Out0 = ([ethernet-[eth_test1-1], payload], [agnostic_test1-correct, agnostic_test2-2, agnostic_test3-incorrect]).

signatures(b, [In0], [Out0, Out1]) :-
	In0 = ([ethernet-[eth_test1-2], payload], [agnostic_test1-correct, agnostic_test2-3, agnostic_test3-incorrect]),
	Out0 = ([ethernet, ipv4, payload], []),
	Out1 = ([ethernet, ipv6, payload], []).

signatures(c, [In0], [Out0]) :-
	In0 = ([ethernet, ipv4, payload], []),
	Out0 = ([ipv4-[checksum-correct, destAddressSet-correct], payload], []).

signatures(d, [In0], [Out0]) :-
	In0 = ([ethernet, ip, payload], []),
	Out0 = ([ethernet, ip, payload], []).

signatures(e, [In0], [Out0]) :-
	In0 = ([ipv4-[checksum-correct, destAddressSet-correct], payload], []),
	Out0 = ([ethernet-[eth_test1-3], ipv4, payload], [agnostic_test2-4, agnostic_test3-incorrect]).

signatures(f, [In0], []) :-
	In0 = ([ethernet-[eth_test1-4], payload], [agnostic_test2-5, agnostic_test3-incorrect]).

signatures(g, [In0], [Out0]) :-
	In0 = ([ethernet, payload], []),
	Out0 = ([ethernet, payload], [agnostic_test1-correct]).

signatures(h, [In0], []) :-
	In0 = ([ethernet, payload], []).
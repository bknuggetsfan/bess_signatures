
:- module(pipeline_combine_input_connections, [connected/4, signatures/3]).

connected(a, 0, c, 0).
connected(b, 0, c, 0).

signatures(a, [], [Out0]) :-
    Out0 = ([ethernet, ipv4, tcp, payload], []).

signatures(b, [], [Out0]) :-
    Out0 = ([ethernet, ip, payload], []).

signatures(c, [In0], []) :-
    In0 = ([ethernet, ip, payload], []).

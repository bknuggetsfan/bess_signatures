
:- module(pipeline_combine_multiple_attrs, [connected/4, signatures/3]).

% connected(Upstream Module, OGate, Downstream Module, IGate)
connected(a, 0, i, 0).
connected(b, 0, i, 0).

% signatures(Module name, Input sigs, Output sigs)
signatures(a, [], [Out0]) :-
    Out0 = ([ethernet-[eth_test1-1], ipv4-[checksum-correct, destAddressSet-correct, payload], 
            [agnostic_test1-correct, agnostic_test2-4, agnostic_test3-3]).

signatures(b, [], [Out0, Out1]) :-
    Out0 = ([ethernet-[eth_test1-2], ipv4-[checksum-correct, destAddressSet-correct, payload], 
            [agnostic_test1-correct, agnostic_test2-5, agnostic_test3-3]).

signatures(i, [In0, In1, In2], []) :-
    In0 = ([ethernet-[eth_test1-4], ipv4-[checksum-correct, destAddressSet-correct], payload],  
           [agnostic_test1-correct, agnostic_test2-6, agnostic_test3-3]),
    In1 = ([ethernet-[eth_test1-5], ipv4-[checksum-incorrect, destAddressSet-incorrect], payload],  
           [agnostic_test1-correct, agnostic_test2-7, agnostic_test3-8]),
    In2 = ([ethernet-[eth_test1-5], ipv4-[checksum-correct, destAddressSet-correct], payload],  
           [agnostic_test1-correct, agnostic_test2-7, agnostic_test3-8]).

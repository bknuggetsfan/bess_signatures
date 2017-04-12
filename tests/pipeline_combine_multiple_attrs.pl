
:- module(pipeline_combine_multiple_attrs, [connected/4, signatures/3]).

% connected(Upstream Module, OGate, Downstream Module, IGate)
connected(a, 0, j, 0).
connected(b, 0, j, 1).
connected(c, 0, j, 1).
connected(d, 0, j, 2).
connected(e, 0, j, 2).
connected(f, 0, j, 2).
connected(g, 0, j, 3).
connected(h, 0, j, 3).
connected(i, 0, j, 3).

% signatures(Module name, Input sigs, Output sigs)
signatures(a, [], [Out0]) :-
    Out0 = ([ethernet-[eth_test1-1], ipv4-[checksum-correct, destAddressSet-correct], payload], 
            [agnostic_test1-correct, agnostic_test2-4, agnostic_test3-3]).

signatures(b, [], [Out0]) :-
    Out0 = ([ethernet-[eth_test1-1], ipv4-[checksum-correct, destAddressSet-correct], payload], 
            [agnostic_test1-correct, agnostic_test2-4, agnostic_test3-3]).

signatures(c, [], [Out0]) :-
    Out0 = ([ethernet-[eth_test1-2], ipv4-[checksum-correct, destAddressSet-correct], payload], 
            [agnostic_test1-correct, agnostic_test2-5, agnostic_test3-3]).

signatures(d, [], [Out0]) :-
     Out0 = ([ethernet-[eth_test1-1], ipv4-[checksum-correct, destAddressSet-correct], payload], 
            [agnostic_test1-correct, agnostic_test2-1, agnostic_test3-8]).  

signatures(e, [], [Out0]) :-
     Out0 = ([ethernet-[eth_test1-2], ipv4-[checksum-correct, destAddressSet-correct], payload], 
            [agnostic_test1-correct, agnostic_test2-2, agnostic_test3-8]).

signatures(f, [], [Out0]) :-
     Out0 = ([ethernet-[eth_test1-4], ipv4-[checksum-incorrect, destAddressSet-incorrect], payload], 
            [agnostic_test1-correct, agnostic_test2-3, agnostic_test3-8]). 

signatures(g, [], [Out0]) :-
     Out0 = ([ethernet-[eth_test1-1], ipv4-[checksum-correct, destAddressSet-correct], payload], 
            [agnostic_test1-correct, agnostic_test3-8]).  

signatures(h, [], [Out0]) :-
     Out0 = ([ethernet-[eth_test1-2], ipv4-[destAddressSet-correct], payload], 
            [agnostic_test1-correct, agnostic_test2-2, agnostic_test3-8]).

signatures(i, [], [Out0]) :-
     Out0 = ([ethernet-[eth_test1-3], ipv4-[checksum-correct], payload], 
            [agnostic_test1-correct, agnostic_test2-3, agnostic_test3-8]).     

signatures(j, [In0, In1, In2, In3], [Out0, Out1]) :-
    In0 = ([ethernet-[eth_test1-4], ipv4-[checksum-correct, destAddressSet-correct], payload],  
           [agnostic_test1-correct, agnostic_test2-6, agnostic_test3-3]),
    In1 = ([ethernet-[eth_test1-4], ipv4-[checksum-correct, destAddressSet-correct], payload],  
           [agnostic_test1-correct, agnostic_test2-6, agnostic_test3-3]),
    In2 = ([ethernet-[eth_test1-5], ipv4-[checksum-incorrect, destAddressSet-incorrect], payload],  
           [agnostic_test1-correct, agnostic_test2-7, agnostic_test3-8]),
    In3 = ([ethernet-[eth_test1-5], ipv4, payload],  
           [agnostic_test1-correct, agnostic_test3-8]),
    Out0 = ([payload],  
           [agnostic_test1-correct, agnostic_test2-6, agnostic_test3-3]),
    Out1 = ([ethernet-[eth_test1-4], ipv4-[checksum-correct, destAddressSet-correct], payload],  
           [agnostic_test1-correct, agnostic_test2-6, agnostic_test3-3]).

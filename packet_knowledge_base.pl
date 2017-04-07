
:- module(packet_knowledge_base, [layer/2, subtype/2, attr/2, compatible/4, combine/5]).
:-discontiguous([attr/2, compatible/4, combine/5]).

% ==================== PROTOCOL TREES ===============================

layer(l2).
layer(l3).
layer(l4).

child(ethernet, l2).
child(ip, l3).
child(ipv4, ip).
child(ipv6, ip).
child(udp, l4).
child(tcp, l4).

subtype(Prot, Prot).
subtype(Prot, Ancestor) :-
    child(Prot, Ancestor).
subtype(Prot, Ancestor) :-
    child(Prot, Parent),
    subtype(Parent, Ancestor).

layer(Prot, Layer) :-
    subtype(Prot, Layer),
    layer(Layer).


% ==================== PROTOCOL ATTRIBUTES ==========================


% attr(protocol, attribute name)
% compatible(protocol, attribute name, upstream/output attr value, donwnstream/input attr value) 
% combine(protocol, attribute name, value1, value2, reduced/combined value)

% -------------------- Test Cases -----------------------------------

attr(ethernet, eth_test1).
compatible(ethernet, eth_test1, ValUp, ValDown) :-
    ValDown > ValUp.
combine(ethernet, eth_test1, Val1, Val2, NewVal) :-
    Val2 > Val1 -> NewVal = Val2 ; NewVal = Val1.

attr(agnostic, agnostic_test1).
compatible(agnostic, agnostic_test1, correct, _).
combine(agnostic, agnostic_test1, Val1, _, Val1).

attr(agnostic, agnostic_test2).
compatible(agnostic, agnostic_test2, ValUp, ValDown) :-
    ValDown > ValUp.
combine(agnostic, agnostic_test2, Val1, Val2, NewVal) :-
    NewVal is Val1 + Val2.

attr(agnostic, agnostic_test3).
compatible(agnostic, agnostic_test3, Val, Val).
combine(agnostic, agnostic_test3, Val, Val, Val).

% -------------------- (Possible) Use Cases -------------------------

attr(ipv4, checksum).
compatible(ipv4, checksum, correct, _).
compatible(ipv4, checksum, _, incorrect).
combine(ipv4, checksum, Checksum1, Checksum2, NewChecksum) :-
    ((Checksum1 = correct, Checksum2 = correct)
     -> NewChecksum = correct
     ; NewChecksum = incorrect).

attr(ipv4, destAddressSet).
compatible(ipv4, destAddressSet, correct, _).
compatible(ipv4, destAddressSet, _, incorrect).
combine(ipv4, destAddressSet, AddrSet1, AddrSet2, AddrSetNew) :-
    ((AddrSet1 = correct, AddrSet2 = correct)
     -> AddrSetNew = correct
     ; AddrSetNew = incorrect).
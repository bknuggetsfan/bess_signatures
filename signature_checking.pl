
% ===================================================================
%                      FRAMEWORK
% ===================================================================

:-use_module(pipeline_simple).
:-discontiguous([attr/2, compatible/4, reduce/5]).

% ==================== UTIlITIES ====================================

upstream(Down, Up) :-
    connected(Up, _, Down, _).
upstream(Down, Up) :-
    connected(Module, _, Down, _),
    upstream(Module, Up).

downstream(Up, Down) :-
    upstream(Down, Up).

suffix(List1, List2) :-
    append([_], List1, List2).

contains_var(Lst) :-
    Lst = [First | _],
    var(First).
contains_var(Lst) :-
    Lst = [_ | Rest],
    contains_var(Rest).

remove_tail(Lst, []) :-
    Lst = [_].
remove_tail(Lst, NewLst) :-
    Lst = [First | Rest],
    remove_tail(Rest, NewLstRest),
    NewLst = [First | NewLstRest].


% ===================== PIPELINE TRAVERSAL ==========================


% ------------------------ Type Rules -------------------------------

% Takes protocols and strips offs protocol attrs to form a type
% Type is a list of protocols
strip_protocol_attrs([], []).
strip_protocol_attrs(Prots, Type) :-
    Prots = [Prot | ProtsRest],
    ( ((atom(Prot); var(Prot)), StrippedProt = Prot); Prot = StrippedProt-_ ),
    strip_protocol_attrs(ProtsRest, TypeRest),
    Type = [StrippedProt | TypeRest].

get_types_by_gate(_, _, [], []).
get_types_by_gate(Module, Gate, Signatures, Types) :-
    Signatures = [Sig | SigsRest],
    Sig = (Prots, _),
    strip_protocol_attrs(Prots, GateType),
    NextGate is Gate + 1,
    get_types_by_gate(Module, NextGate, SigsRest, TypesRest),
    Types = [ (Module, Gate, GateType) | TypesRest].

% Wrapper for getting input or output types of a module
% Types is a list of (Module Name, Gate, Type) tuples
get_types(Module, Mode, Types) :-
    ( (Mode = output, signatures(Module, _, Sigs)) ;
      (Mode = input, signatures(Module, Sigs, _)) ),
    get_types_by_gate(Module, 0, Sigs, Types).


% ------------------- Attribute Rules -------------------------------

% Takes protocols and extracts the protocol attributes
% Attrs is a list of (Protocol, Attr Name, Attr Value) tuples
extract_protocol_attrs([], []).
extract_protocol_attrs([X], []) :-
    var(X).
extract_protocol_attrs(Prots, Attrs) :-
    Prots = [ProtFirst | ProtsRest],
    atom(ProtFirst),
    extract_protocol_attrs(ProtsRest, Attrs).
extract_protocol_attrs(Prots, Attrs) :-
    Prots = [ProtFirst | ProtsRest],
    ProtFirst = _-[],
    extract_protocol_attrs(ProtsRest, Attrs).
extract_protocol_attrs(Prots, Attrs) :-
    Prots = [ProtFirst | ProtsRest],
    ProtFirst = Prot-[ProtAttr | ProtAttrsRest],
    ProtAttr = ProtName-ProtVal,
    extract_protocol_attrs([Prot-ProtAttrsRest | ProtsRest], RestAttrs),
    Attrs = [ (Prot, ProtName, ProtVal) | RestAttrs].

% Maps an agnostic attribute to ("agnotic", attr name, attr val)
agnostic_map(Name-Val, (agnostic, Name, Val)).
    
get_attrs_by_gate(_, _, [], []). 
get_attrs_by_gate(Module, Gate, Signatures, Attrs) :-
    Signatures = [Sig | SigsRest],
    Sig = (Prots, AgnosticAttrsRaw),
    extract_protocol_attrs(Prots, ProtAttrs),
    maplist(agnostic_map, AgnosticAttrsRaw, AgnosticAttrs),
    append(ProtAttrs, AgnosticAttrs, GateAttrs),
    NextGate is Gate + 1,
    get_attrs_by_gate(Module, NextGate, SigsRest, AttrsRest),
    Attrs = [(Module, Gate, GateAttrs) | AttrsRest].

% Wrapper for getting input or output attrs of a Module
% Attrs is a list composed of (Module Name, Gate Number, Attrs) tuples
get_attrs(Module, Mode, Attrs) :-
    ( (Mode = output, signatures(Module, _, Sigs)) ;
      (Mode = input, signatures(Module, Sigs, _)) ),
    get_attrs_by_gate(Module, 0, Sigs, Attrs).


% ------------------- Signature Checking ----------------------------



% all modules have been visited
verify_signatures(Explored, _, _) :-
    foreach( (connected(Module,_,_,_); connected(_,_,Module,_)),
            memberchk(Module, Explored) ).
% verify signatures for all source modules
verify_signatures(Explored, UpstreamTypes, UpstreamAttrs) :-
    connected(Module, _, _, _),
    not( (connected(_, _, Module, _); memberchk(Module, Explored)) ),
    get_types(Module, output, ModuleTypes),
    get_attrs(Module, output, ModuleAttrs),
    append(UpstreamTypes, ModuleTypes, UpdatedUpstreamTypes),
    append(UpstreamAttrs, ModuleAttrs, UpdatedUpstreamAttrs).
    %verify_signatures([Module | Explored], UpdatedUpstreamTypes, UpdatedUpstreamAttrs), !.



% ------------------- Framework Entry Point -------------------------

no_error() :-
    verify_signatures([],[],[]).


% ===================================================================
%                 ATTRIBUTE KNOWLEDGE BASE
% ===================================================================



% ==================== PROTOCOL TREES ===============================

layer(l2).
layer(l3).
layer(l4).

child(ethernet, l2).
child(vlan, l2).
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
% reduce(protocol, attribute name, value1, value2, reduced/combined value)

% -------------------- Test Cases -----------------------------------

attr(ethernet, eth_test1).
compatible(ethernet, eth_test1, ValUp, ValDown) :-
    ValDown > ValUp.
reduce(ethernet, eth_test1, Val1, Val2, NewVal) :-
    Val2 > Val1 -> NewVal = Val2 ; NewVal = Val1.

attr(agnostic, agnostic_test1).
compatible(agnostic, agnostic_test1, correct, _).

attr(agnostic, agnostic_test2).
compatible(agnostic, agnostic_test2, ValUp, ValDown) :-
    ValDown > ValUp.

attr(agnostic, agnostic_test3).
compatible(agnostic, agnostic_test3, Val, Val).

% -------------------- (Possible) Use Cases -------------------------

attribute(ipv4, checksum).
compatible(ipv4, checksum, correct, _).
reduce(ipv4, checksum, Checksum1, Checksum2, NewChecksum) :-
    ((Checksum1 = correct; Checksum2 = correct)
     -> NewChecksum = incorrect
     ; NewChecksum = correct).

attr(ipv4, destAddressSet).
compatible(ipv4, destAddressSet, correct, _).
reduce(ipv4, destAddressSet, Val1, Val2, NewVal) :-
    ((Val1 = correct; Val2 = correct)
     -> NewVal = incorrect
     ; NewVal = correct).

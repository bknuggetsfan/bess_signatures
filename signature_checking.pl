
% ===================================================================
%                      FRAMEWORK
% ===================================================================

:-use_module('tests/pipeline_incorrect_simple').
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


% ------------------------ Module Information ------------------------

num_igates(Module, NumIgates) :-
    signatures(Module, InputSigs, _),
    length(InputSigs, NumIgates).

num_ogates(Module, NumOgates) :-
    signatures(Module, _, OutputSigs),
    length(OutputSigs, NumOgates).

% ------------------------ Type Rules -------------------------------

% takes in protocols and strips off protocol attrs to form a type
% type is an ordered list of protocols
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

% wrapper for getting input or output types of a module
% types is a list of (module, gate, type) tuples
get_types(Module, Mode, Types) :-
    ( (Mode = output, signatures(Module, _, Sigs)) ;
      (Mode = input, signatures(Module, Sigs, _)) ),
    get_types_by_gate(Module, 0, Sigs, Types).

% same as get_types, except gets rid of the gate and module name info
get_flattened_types(Module, Mode, Types) :-
    get_types(Module, Mode, TypesUnflattened),
    maplist(flatten_tuple, TypesUnflattened, Types).

% types_compatible(upstream protcol, input protocol)
types_compatible(_, [X]) :-
    var(X).
types_compatible(_, [payload]).
types_compatible(UpProt, DownProt) :-
    (UpProt = [UpProt1-_ | UpProtRest]; UpProt = [UpProt1 | UpProtRest]),
    (DownProt = [DownProt1-_ | DownProtRest]; DownProt = [DownProt1 | DownProtRest]),
    layer(UpProt1, Layer),
    layer(DownProt1, Layer),
    subtype(UpProt1, DownProt1),
    types_compatible(UpProtRest, DownProtRest). 

% given all input types and all upstream types, checks pairwise compatiblity
all_types_compatible(_, []).
all_types_compatible(InputTypes, UpstreamTypes) :-
    UpstreamTypes = [(UpstreamType, Igate) | UpstreamTypesRest],
    nth0(Igate, InputTypes, InputType),
    (types_compatible(UpstreamType, InputType) -> true; false),
    all_types_compatible(InputTypes, UpstreamTypesRest).

% retrieve all types that feed into the given igate
all_input_types_per_igate(_, _, [], []).
all_input_types_per_igate(Module, Igate, UpstreamTypes, AllTypes) :-
    UpstreamTypes = [UpstreamType | UpstreamTypesRest],
    UpstreamType = (UpModule, UpOgate, _),
    connected(UpModule, UpOgate, Module, Igate),
    all_input_types_per_igate(Module, Igate, UpstreamTypesRest, AllTypesRest),
    AllTypes = (UpstreamType, AllTypesRest).

%% reduced_igate_types([], []).
%% reduced_igate_types(IgateTypes, ReducedTypes) :-
%%     nl.

% For each input gate, reduce all hooks into a single type
%% reduced_types(Module, UpstreamTypes, Igate, ReducedTypes) :-
%%     num_igates(Module, NumIgates),
%%     Igate < NumIgates,
%%     all_input_types_per_igate(Module, Igate, UpstreamTypes, AllTypes),
%%     reduce_igate_types(AllTypes, ReducedType),
%%     NextIgate is Igate + 1,
%%     reduced_types(Module, UpstreamTypes, NextIgate, ReducedTypesRest),
%%     ReducedTypes = [ReducedType | ReducedTypesRest].    
%% reduced_types(_, _, _, []).

% list of ALL upstream types represented as (type, igate)
all_upstream_types(Module, UpstreamTypes, AllTypes) :-
    findall((Type, Igate), 
            ( connected(Parent, Ogate, Module, Igate),
              memberchk((Parent, Ogate, Type), UpstreamTypes) ),
            AllTypes).

% combines all hook types for the same gate into a single gate type
% GateTypes is a list of all gate type, gate number tuples
hook_types_to_gate_types([], []).
hook_types_to_gate_types(HookTypes, GateTypes) :-
    HookTypes = [(HookType, HookGate) | HookTypesRest],
    hook_types_to_gate_types(HookTypesRest, GateTypesRest),
    (member((GateType, HookGate), GateTypesRest) ->
        (delete(GateTypesRest, (GateType, HookGate), GateTypesRestUpdated),
        combine_types(HookType, GateType, NewType),
        append(GateTypesRestUpdated, [(NewType, HookGate)], GateTypes)) ;
        (append(GateTypesRest, [(HookType, HookGate)], GateTypes))).

% combine (i.e. generalize) two types
combine_types([payload], _, [payload]).
combine_types(_, [payload], [payload]).
combine_types(Type1, Type2, NewType) :-
    Type1 = [Header1 | Type1Rest],
    Type2 = [Header2 | Type2Rest],
    combine_types(Type1Rest, Type2Rest, NewTypeRest),
    (subtype(Header1, Header2) -> NewHeader = Header2; NewHeader = Header1),
    NewType = [NewHeader | NewTypeRest]. 


% combine all types that feed into the given igate
reduced_types(Module, UpstreamTypes, [ReducedType]) :-
    connected(Parent, _, Module, _),
    memberchk((Parent, _, ReducedType), UpstreamTypes).

% TODO:
% cascading, etc goes here 
new_types(Module, _, ModuleTypes) :-
    get_types(Module, output, ModuleTypes).

% ------------------- Attribute Rules -------------------------------

% takes protocols and extracts the protocol attributes
% attributes are stored as a list of (protocol, attr Name, attr Value) tuples
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

% maps an agnostic attribute to ("agnotic", attr name, attr val)
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

% wrapper for getting input or output attrs of a module
% attrs is a list composed of (Module Name, Gate Number, Attrs) tuples
get_attrs(Module, Mode, Attrs) :-
    ( (Mode = output, signatures(Module, _, Sigs)) ;
      (Mode = input, signatures(Module, Sigs, _)) ),
    get_attrs_by_gate(Module, 0, Sigs, Attrs).

% same as get_attrs, except gets rid of the gate and module name info
get_flattened_attrs(Module, Mode, Attrs) :-
    get_attrs(Module, Mode, AttrsUnflattened),
    maplist(flatten_tuple, AttrsUnflattened, Attrs).

% list of ALL upstream types represented as (type, igate)
all_upstream_attrs(Module, UpstreamAttrs, AllAttrs) :-
    findall((Attrs, Igate), 
            ( connected(Parent, Ogate, Module, Igate),
              memberchk((Parent, Ogate, Attrs), UpstreamAttrs) ),
            AllAttrs).

% TODO:
% Currently support only one input gate per module
% No support for reduction either
reduced_attrs(Module, UpstreamAttrs, [ReducedAttrs]) :-
    connected(Parent, _, Module, _),
    memberchk((Parent, _, ReducedAttrs), UpstreamAttrs).

% TODO:
% cascading, etc goes here
new_attrs(Module, _, ModuleAttrs) :-
    get_attrs(Module, output, ModuleAttrs).

% checks if list of attrs is compatible with another list of attrs
check_attributes(_, []).
check_attributes(UpstreamAttrs, InputAttrs) :-
    InputAttrs = [(InputProt, InputName, InputVal) | InputAttrsRest],
    memberchk((InputProt, InputName, UpstreamVal), UpstreamAttrs),
    compatible(InputProt, InputName, UpstreamVal, InputVal),
    check_attributes(UpstreamAttrs, InputAttrsRest).

% given all input attrs and all upstream attrs, checks pairwise compatiblity
all_attrs_compatible(_, []).
all_attrs_compatible(InputAttrs, UpstreamAttrs) :-
    UpstreamAttrs = [(UpstreamAttr, Igate) | UpstreamAttrsRest],
    nth0(Igate, InputAttrs, InputAttr),
    check_attributes(UpstreamAttr, InputAttr),
    all_attrs_compatible(InputAttrs, UpstreamAttrsRest).


% ------------------- Signature Checking ----------------------------

    
% maps (module, gate, type/attrs) to type/attrs
flatten_tuple((_,_,Val), Val).

% visited all modules
verify_signatures(Explored, _, _) :-
    foreach( (connected(Module,_,_,_); connected(_,_,Module,_)),
            memberchk(Module, Explored) ).
% verify source modules
verify_signatures(Explored, UpstreamTypes, UpstreamAttrs) :-
    connected(Module, _, _, _),
    not( (connected(_, _, Module, _); memberchk(Module, Explored)) ),
    get_types(Module, output, ModuleTypes),
    get_attrs(Module, output, ModuleAttrs),
    append(UpstreamTypes, ModuleTypes, UpdatedUpstreamTypes),
    append(UpstreamAttrs, ModuleAttrs, UpdatedUpstreamAttrs),
    verify_signatures([Module | Explored], UpdatedUpstreamTypes, UpdatedUpstreamAttrs).
% verify non-source modules
verify_signatures(Explored, UpstreamTypes, UpstreamAttrs) :-
    connected(_, _, Module, _),
    foreach(connected(Parent, _, Module, _), memberchk(Parent, Explored) ),
    not(memberchk(Module, Explored)),
    get_flattened_types(Module, input, InputTypes),
    get_flattened_attrs(Module, input, InputAttrs),
    all_upstream_types(Module, UpstreamTypes, AllUpstreamTypes),
    all_upstream_attrs(Module, UpstreamAttrs, AllUpstreamAttrs),
    all_types_compatible(InputTypes, AllUpstreamTypes),
    all_attrs_compatible(InputAttrs, AllUpstreamAttrs),
    hook_types_to_gate_types(AllUpstreamTypes, UpstreamTypesPerIgate),
    %hook_attrs_to_gate_attrs(AllUpstreamAttrs, UpstreamAttrsPerIgate),
    new_types(Module, UpstreamTypes, OutputTypes),
    new_attrs(Module, UpstreamAttrs, OutputAttrs),
    append(UpstreamTypes, OutputTypes, UpdatedUpstreamTypes),
    append(UpstreamAttrs, OutputAttrs, UpdatedUpstreamAttrs),
    verify_signatures([Module | Explored], UpdatedUpstreamTypes, UpdatedUpstreamAttrs).


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
combine(agnostic, agnostic_test1, Val1, Val2, Val1).

attr(agnostic, agnostic_test2).
compatible(agnostic, agnostic_test2, ValUp, ValDown) :-
    ValDown > ValUp.
combine(agnostic, agnostic_test2, Val1, Val2, NewVal) :-
    NewVal is Val1 + Val2.

attr(agnostic, agnostic_test3).
compatible(agnostic, agnostic_test3, Val, Val).
combine(agnostic, agnostic_test3, Val, Val, Val).

% -------------------- (Possible) Use Cases -------------------------

attribute(ipv4, checksum).
compatible(ipv4, checksum, correct, _).
combine(ipv4, checksum, Checksum1, Checksum2, NewChecksum) :-
    ((Checksum1 = correct; Checksum2 = correct)
     -> NewChecksum = incorrect
     ; NewChecksum = correct).

attr(ipv4, destAddressSet).
compatible(ipv4, destAddressSet, correct, _).
combine(ipv4, destAddressSet, AddrSet1, AddrSet2, AddrSetNew) :-
    ((AddrSet1 = correct; AddrSet2 = correct)
     -> AddrSetNew = incorrect
     ; AddrSetNew = correct).

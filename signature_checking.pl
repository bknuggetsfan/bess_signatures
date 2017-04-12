
% ===================================================================
%                      FRAMEWORK
% ===================================================================

:-use_module('tests/pipeline_combine_overloaded_igates').
:-use_module('packet_knowledge_base').

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

% For each input gate, reduce all connections into a single type
%% reduced_types(Module, UpstreamTypes, Igate, ReducedTypes) :-
%%     num_igates(Module, NumIgates),
%%     Igate < NumIgates,
%%     all_input_types_per_igate(Module, Igate, UpstreamTypes, AllTypes),
%%     reduce_igate_types(AllTypes, ReducedType),
%%     NextIgate is Igate + 1,
%%     reduced_types(Module, UpstreamTypes, NextIgate, ReducedTypesRest),
%%     ReducedTypes = [ReducedType | ReducedTypesRest].    
%% reduced_types(_, _, _, []).

% list of ALL directly upstream types for a module represented as (type, igate)
all_upstream_types(Module, UpstreamTypes, AllTypes) :-
    findall((Type, Igate), 
            ( connected(Parent, Ogate, Module, Igate),
              memberchk((Parent, Ogate, Type), UpstreamTypes) ),
            AllTypes).

% combines all connection types for the same gate into a single gate type
% GateTypes is a list of all (gate type, gate number) tuples
connection_types_to_gate_types([], []).
connection_types_to_gate_types(ConnectionTypes, GateTypes) :-
    ConnectionTypes = [(ConnectionType, ConnectionGate) | ConnectionTypesRest],
    connection_types_to_gate_types(ConnectionTypesRest, GateTypesRest),
    (member((GateType, ConnectionGate), GateTypesRest) ->
        (delete(GateTypesRest, (GateType, ConnectionGate), GateTypesRestUpdated),
        combine_types(ConnectionType, GateType, NewType),
        append(GateTypesRestUpdated, [(NewType, ConnectionGate)], GateTypes)) ;
        (append(GateTypesRest, [(ConnectionType, ConnectionGate)], GateTypes))).

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

flatten_type_and_gate_tuple((Type, _), Type).

% combines types in a list reduction-style
combine_all_types([Type1], Type1).
combine_all_types([Type1, Type2], CombinedType) :-
    combine_types(Type1, Type2, CombinedType).
combine_all_types(Types, CombinedType) :-
    Types = [Type1, Type2 | RestTypes],
    RestTypes = [_ | _],
    combine_types(Type1, Type2, CombinedTypeTemp),
    combine_all_types([CombinedTypeTemp | RestTypes], CombinedType).

% combine igate types for each ogate
combine_igate_types_per_ogate(_, OgateNum, OgateNum, []).
combine_igate_types_per_ogate(IgateTypes, OgateNum, TotalOgates, IgateTypesPerOgate) :-
    maplist(flatten_type_and_gate_tuple, IgateTypes, IgateTypesFlattened),
    combine_all_types(IgateTypesFlattened, IgateTypeForOgate),
    NextOgateNum is OgateNum + 1,
    combine_igate_types_per_ogate(IgateTypes, NextOgateNum, TotalOgates, IgateTypesPerOgateRest),
    IgateTypesPerOgate = [IgateTypeForOgate | IgateTypesPerOgateRest].
    

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

% list of ALL directly upstream attrs for a module represented as (attrs, igate)
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

% given a list of attrs, combines attrs where applicable
reduce_attrs(_, [], _, ReducedAttrs, ReducedAttrs).
% case 1: at least one connection is missing the attr
reduce_attrs(NumConnections, OriginalAttrs, OriginalAttrsCopy, ReducedAttrs, AllAttrs) :-
    OriginalAttrs = [Attrs | OriginalAttrsRest],
    Attrs = (Prot, Name, _),
    findall((Prot, Name, _), member((Prot, Name, _), OriginalAttrsCopy), SharedAttrs),
    length(SharedAttrs, NumAttrs),
    not(NumAttrs = NumConnections),
    reduce_attrs(NumConnections, OriginalAttrsRest, OriginalAttrsCopy, ReducedAttrs, AllAttrs).
reduce_attrs(NumConnections, OriginalAttrs, OriginalAttrsCopy, ReducedAttrs, AllAttrs) :-
    OriginalAttrs = [Attrs | OriginalAttrsRest],
    Attrs = (Prot, Name, Val),
    (memberchk((Prot, Name, Val2), ReducedAttrs) ->
    (combine(Prot, Name, Val, Val2, NewVal),
    delete(ReducedAttrs, (Prot, Name, Val2), ReducedAttrsUpdated),
    (reduce_attrs(NumConnections, OriginalAttrsRest, OriginalAttrsCopy, [(Prot, Name, NewVal) | ReducedAttrsUpdated], AllAttrs)));
    (reduce_attrs(NumConnections, OriginalAttrsRest, OriginalAttrsCopy, [(Prot, Name, Val) | ReducedAttrs], AllAttrs))).

% combines connection attributes to form prot attrs for a single gate
gate_protocol_attrs(_, [], [], _).
gate_protocol_attrs(ConnectionAttrs, GateType, GateAttrs, NumConnections) :-
    NumConnections = 1,
    GateType = [Prot | GateTypeRest],
    findall((Prot, AttrName, AttrValue), (member(Attrs, ConnectionAttrs), member((Prot, AttrName, AttrValue), Attrs)),
        AllProtAttrs),
    gate_protocol_attrs(ConnectionAttrs, GateTypeRest, GateAttrsRest, NumConnections),
    append(AllProtAttrs, GateAttrsRest, GateAttrs).
gate_protocol_attrs(ConnectionAttrs, GateType, GateAttrs, NumConnections) :-
    GateType = [Prot | GateTypeRest],
    findall((Prot, AttrName, AttrValue), (member(Attrs, ConnectionAttrs), member((Prot, AttrName, AttrValue), Attrs)),
        AllProtAttrs),
    reduce_attrs(NumConnections, AllProtAttrs, AllProtAttrs, [], ReducedProtAttrs),
    gate_protocol_attrs(ConnectionAttrs, GateTypeRest, GateAttrsRest, NumConnections),
    append(ReducedProtAttrs, GateAttrsRest, GateAttrs).

% same as gate_protocol_attrs, except handles aganostic attrs
gate_agnostic_attrs(ConnectionAttrs, AgnosticAttrs, NumConnections) :-
    NumConnections = 1,
    findall((agnostic, AttrName, AttrValue), (member(Attrs, ConnectionAttrs), member((agnostic, AttrName, AttrValue), Attrs)),
        AgnosticAttrs).
gate_agnostic_attrs(ConnectionAttrs, AgnosticAttrs, NumConnections) :-
    findall((agnostic, AttrName, AttrValue), (member(Attrs, ConnectionAttrs), member((agnostic, AttrName, AttrValue), Attrs)),
        AllAgnosticAttrs),
    reduce_attrs(NumConnections, AllAgnosticAttrs, AllAgnosticAttrs, [], AgnosticAttrs).


% combines all connection attrs for the same gate into a single gate attrs
% GateAttrs is a list of all (gate attrs, gate number) tuples
% GateTypes are needed to extract only the necessary attrs for each gate
connection_attrs_to_gate_attrs(_, [], []).
connection_attrs_to_gate_attrs(AllConnectionAttrs, GateTypes, GateAttrs) :-
    GateTypes = [(GateType, GateIndex) | GateTypesRest], 
    findall(ConnectionAttrs, member((ConnectionAttrs, GateIndex), AllConnectionAttrs), ConnectionAttrsForGate),
    length(ConnectionAttrsForGate, NumConnections),
    gate_protocol_attrs(ConnectionAttrsForGate, GateType, ProtAttrsForGate, NumConnections),
    gate_agnostic_attrs(ConnectionAttrsForGate, AgnosticAttrsForGate, NumConnections),
    append(ProtAttrsForGate, AgnosticAttrsForGate, AllAttrsForGate),
    connection_attrs_to_gate_attrs(AllConnectionAttrs,  GateTypesRest, GateAttrsRest),
    GateAttrs = [(AllAttrsForGate, GateIndex) | GateAttrsRest].



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
    connection_types_to_gate_types(AllUpstreamTypes, UpstreamTypesPerIgate),
    connection_attrs_to_gate_attrs(AllUpstreamAttrs, UpstreamTypesPerIgate, UpstreamAttrsPerIgate),
    get_flattened_types(Module, output, OutputTypes),
    length(OutputTypes, NumOgates),
    combine_igate_types_per_ogate(UpstreamTypesPerIgate, 0, NumOgates, IgateTypesPerOgate),
    %igate_attrs_to_ogate_attrs(UpstreamAttrsPerIgate, OgateAttrs)
    new_types(Module, UpstreamTypes, NewOutputTypes),
    new_attrs(Module, UpstreamAttrs, NewOutputAttrs),
    append(UpstreamTypes, NewOutputTypes, UpdatedUpstreamTypes),
    append(UpstreamAttrs, NewOutputAttrs, UpdatedUpstreamAttrs),
    verify_signatures([Module | Explored], UpdatedUpstreamTypes, UpdatedUpstreamAttrs).


% ------------------- Framework Entry Point -------------------------

no_error() :-
    verify_signatures([],[],[]).

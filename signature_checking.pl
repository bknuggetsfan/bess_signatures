% TODO:
% - refine cascading:
% - multiple input gates and hooks
% - implement "or" syntax


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

% takes a list of protocol/protocol-attributes 
% and flattens it into a list of just protocols
flatten([], []).
flatten(Protocols, FlatProtocols) :-
	Protocols = [First | Rest],
	((atom(First), Prot = First); First = Prot-_),
	flatten(Rest, RestFlat),
	FlatProtocols = [Prot | RestFlat].

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


% ------------------- Protocol (Type) Checking ----------------------

% don't care about input, so preserve input
update_type(Module, InType, OutType, NewType, UpstreamTypes) :-
	InType = [X],
	OutType = [X],
	var(X),
	connected(Parent, _, Module, _),
	memberchk((Parent, _, ParentType), UpstreamTypes),
	NewType = ParentType.
% input is payload, so replace with output
update_type(_, [payload], OutType, OutType, _).
% first protocol of input matches first protocol of output
update_type(_, InType, OutType, NewType, _) :-
	(OutType = [OutProt-_ | RestOutType]; OutType = [OutProt | RestOutType]),
	(InType = [InProt-_ | RestInType]; InType = [InProt | RestInType]),
	InProt = OutProt,
	atom(InProt), 
	update_type(_, RestInType, RestOutType, RestNewType, _),
	NewType = [InProt | RestNewType].
% strip or add append header(s)
update_type(_, InType, OutType, OutType, _) :-
	flatten(OutType, FlatOutType),
	flatten(InType, FlatInType),
	(suffix(FlatOutType, FlatInType); suffix(FlatInType, FlatOutType)).

update_upstream_types(_, _, _, [], _, _).
update_upstream_types(Module, Ogate, InputType, OutputSigs, UpstreamTypes, NewUpstreamTypes) :-
	OutputSigs = [(OutputType, _) | OutputSigsRest],
	update_type(Module, InputType, OutputType, NewType, UpstreamTypes),
	NewOgate is Ogate + 1,
	update_upstream_types(Module, NewOgate, InputType, OutputSigsRest, UpstreamTypes, NewUpstreamTypesRest),
	NewUpstreamTypes = [(Module, Ogate, NewType) | NewUpstreamTypesRest].

% types_compatible(upstream/output protcol, downstream/input protocol)
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

module_type_satisfied(Module, UpstreamTypes, InputType) :-
	connected(Parent, _, Module, _),
	memberchk((Parent, _, ParentType), UpstreamTypes),
	types_compatible(ParentType, InputType).

initialize_upstream_types(_, _, [], []).
initialize_upstream_types(Module, Ogate, OutputSigs, UpstreamTypes) :-
	OutputSigs = [OutputSig | OutputSigsRest],
	OutputSig = (OutputType, _),
	flatten(OutputType, OutputTypeFlat),
	NewOgate is Ogate + 1,
	initialize_upstream_types(Module, NewOgate, OutputSigsRest, RestUpstreamTypes),
	UpstreamTypes = [ (Module, Ogate, OutputTypeFlat) | RestUpstreamTypes].

verify_types(Explored, _) :-
	foreach( (connected(Module,_,_,_); connected(_,_,Module,_)),
			  memberchk(Module, Explored) ).
verify_types(Explored, UpstreamTypes) :-
	connected(Module, _, _, _),
	not( (connected(_, _, Module, _); memberchk(Module, Explored)) ),
	not(memberchk(Module, Explored)),
	signatures(Module, _, OutputSigs),
	initialize_upstream_types(Module, 0, OutputSigs, RestUpstreamTypes),
	append(UpstreamTypes, RestUpstreamTypes, NewUpstreamTypes),
	verify_types([Module | Explored], NewUpstreamTypes), !.
verify_types(Explored, UpstreamTypes) :-
	connected(_, _, Module, _),
	foreach(connected(Parent, _, Module, _),
			memberchk(Parent, Explored) ),
	not(memberchk(Module, Explored)),  
	signatures(Module, [(InputType, _) | _], OutputSigs),
	module_type_satisfied(Module, UpstreamTypes, InputType),
	update_upstream_types(Module, 0, InputType, OutputSigs, UpstreamTypes, UpstreamTypesRest),
	append(UpstreamTypes, UpstreamTypesRest, NewUpstreamTypes),
	verify_types([Module | Explored], NewUpstreamTypes), !.


% ------------------- Generic Attribute Rules ------------------------------

% takes a list of protocols/protocol-attributes 
% and converts it into a list of (protocol-attribute) pairs
flatten_protocol_attrs([], []).
flatten_protocol_attrs([X], []) :-
	var(X).
flatten_protocol_attrs(Protocols, Attrs) :-
	Protocols = [Prot | ProtRest],
	atom(Prot),
	flatten_protocol_attrs(ProtRest, Attrs).
flatten_protocol_attrs(Protocols, Attrs) :-
	Protocols = [ProtFirst | ProtRest],
	ProtFirst = _-[],
	flatten_protocol_attrs(ProtRest, Attrs).
flatten_protocol_attrs(Protocols, Attrs) :-
	Protocols = [ProtFirst | ProtRest],
	ProtFirst = Prot-[ProtAttr | ProtAttrsRest],
	ProtAttr = Name-Val,
	flatten_protocol_attrs([Prot-ProtAttrsRest | ProtRest], RestAttrs),
	Attrs = [(Prot,Name,Val) | RestAttrs].

% ------------------- Protocol Attribute Checking --------------------------

initialize_prot_attributes(_, _, [], []).
initialize_prot_attributes(Module, Ogate, OutputSigs, NewAttrs) :-
    OutputSigs = [OutputSig | RestOutputSigs],
    OutputSig = (OutputType, _),
    flatten_protocol_attrs(OutputType, OutputAttrs),
    NewOgate is Ogate + 1,
    initialize_prot_attributes(Module, NewOgate, RestOutputSigs, RestAttrs),
    NewAttrs = [ (Module, Ogate, OutputAttrs) | RestAttrs].

prot_attr_compatible(Prot, Attr, UpstreamAttrs) :-
    Attr = AttrName - AttrValue,
    memberchk(AttrName-UpstreamAttrValue, UpstreamAttrs),
    compatible(Prot, AttrName, UpstreamAttrValue, AttrValue).

prot_attrs_compatible([], _).
prot_attrs_compatible([Attrs], _) :-
	var(Attrs).
prot_attrs_compatible(Attrs, UpstreamAttrs) :-
    Attrs = [(Prot,ProtAttrName, ProtAttrValue) | AttrsRest],
    member((Prot, ProtAttrName, UpstreamProtAttrValue), UpstreamAttrs),
    compatible(Prot, ProtAttrName, UpstreamProtAttrValue, ProtAttrValue),
    prot_attrs_compatible(AttrsRest, UpstreamAttrs).

module_prot_attrs_satisfied(_, [], _).
module_prot_attrs_satisfied(Module, Attrs, UpstreamAttrs) :-
	connected(Parent, _, Module, _),
	memberchk((Parent, _, ParentAttrs), UpstreamAttrs),
	prot_attrs_compatible(Attrs, ParentAttrs).

update_prot_attrs(_, _, _, [], _, _).
update_prot_attrs(Module, Ogate, InputAttrs, OutputSigs, UpstreamProtAttrs, NewUpstreamProtAttrs) :-
	OutputSigs = [(OutputType, _) | OutputSigsRest],
	flatten_protocol_attrs(OutputType, OutputAttrs),
	NewOgate is Ogate + 1,
	update_prot_attrs(Module, NewOgate, InputAttrs, OutputSigsRest, UpstreamProtAttrs, NewUpstreamProtAttrsRest),
	NewUpstreamProtAttrs = [(Module, Ogate, OutputAttrs) | NewUpstreamProtAttrsRest].

verify_prot_attributes(Explored, _) :-
	foreach( (connected(Module,_,_,_); connected(_,_,Module,_)),
			  memberchk(Module, Explored) ).
verify_prot_attributes(Explored, UpstreamAttrs) :-
	connected(Module, _, _, _),
	not( (connected(_, _, Module, _); memberchk(Module, Explored)) ),
	not(memberchk(Module, Explored)),
	signatures(Module, _, OutputSigs),
	initialize_prot_attributes(Module, 0, OutputSigs, RestUpstreamAttrs),
	append(UpstreamAttrs, RestUpstreamAttrs, NewUpstreamAttrs),
	verify_prot_attributes([Module | Explored], NewUpstreamAttrs), !.
verify_prot_attributes(Explored, UpstreamAttrs) :-
	connected(_, _, Module, _),
	foreach(connected(Parent, _, Module, _),
			memberchk(Parent, Explored) ),
	not(memberchk(Module, Explored)), 
	signatures(Module, [(InputType, _) | _], OutputSigs),
	flatten_protocol_attrs(InputType, InputAttrs),

	module_prot_attrs_satisfied(Module, InputAttrs, UpstreamAttrs),
	update_prot_attrs(Module, 0, InputAttrs, OutputSigs, UpstreamAttrs, RestUpstreamAttrs),
	append(UpstreamAttrs, RestUpstreamAttrs, NewUpstreamAttrs),
	verify_prot_attributes([Module | Explored], NewUpstreamAttrs), !.


% ------------------- Agnostic Attribute Checking -------------------

initialize_agnostic_attrs(_, _, [], []).
initialize_agnostic_attrs(Module, Ogate, OutputSigs, NewAttrs) :-
	OutputSigs = [OutputSig | OutputSigsRest],
	OutputSig = (_, OutputAttrs),
	NewOgate is Ogate + 1,
	initialize_agnostic_attrs(Module, NewOgate, OutputSigsRest, RestNewAttrs),
	NewAttrs = [ (Module, Ogate, OutputAttrs) | RestNewAttrs].

agnostic_attr_compatible(Attr, UpstreamAttrs) :-
	Attr = AttrName - AttrValue,
	memberchk(AttrName-UpstreamAttrValue, UpstreamAttrs),
	compatible(agnostic, AttrName, UpstreamAttrValue, AttrValue).

agnostic_attrs_compatible([Attrs], _) :-
	var(Attrs).
agnostic_attrs_compatible(Attrs, UpstreamAttrs) :-
	foreach( (member(Attr, Attrs)), agnostic_attr_compatible(Attr, UpstreamAttrs)).

module_agnostic_attrs_satisfied(_, _, []).
module_agnostic_attrs_satisfied(Module, Attrs, UpstreamAttrs) :-
	connected(Parent, _, Module, _),
	memberchk((Parent, _, ParentAttrs), UpstreamAttrs),
	agnostic_attrs_compatible(Attrs, ParentAttrs).

update_agnostic_attrs(_, _, _, [], _, _).
update_agnostic_attrs(Module, Ogate, InputAttrs, OutputSigs, UpstreamAttrs, NewUpstreamAttrs) :-
	OutputSigs = [(_, OutputAttrs) | OutputSigsRest],
	NewOgate is Ogate + 1,
	update_agnostic_attrs(Module, NewOgate, InputAttrs, OutputSigsRest, UpstreamAttrs, NewUpstreamAttrsRest),
	NewUpstreamAttrs = [(Module, Ogate, OutputAttrs) | NewUpstreamAttrsRest].

verify_agnostic_attributes(Explored, _) :-
	foreach( (connected(Module,_,_,_); connected(_,_,Module,_)),
			  memberchk(Module, Explored) ).
verify_agnostic_attributes(Explored, UpstreamAttrs) :-
	connected(Module, _, _, _),
	not( (connected(_, _, Module, _); memberchk(Module, Explored)) ),
	not(memberchk(Module, Explored)),
	signatures(Module, _, OutputSigs),
	initialize_agnostic_attrs(Module, 0, OutputSigs, RestUpstreamAttrs),
	append(UpstreamAttrs, RestUpstreamAttrs, NewUpstreamAttrs),
	verify_agnostic_attributes([Module | Explored], NewUpstreamAttrs), !.
verify_agnostic_attributes(Explored, UpstreamAttrs) :-
	connected(_, _, Module, _),
	foreach(connected(Parent, _, Module, _),
			memberchk(Parent, Explored) ),
	not(memberchk(Module, Explored)), 
	signatures(Module, [(_, InputAttrs) | _], OutputSigs),
	module_agnostic_attrs_satisfied(Module, InputAttrs, UpstreamAttrs),
	update_agnostic_attrs(Module, 0, InputAttrs, OutputSigs, UpstreamAttrs, RestUpstreamAttrs),
	append(UpstreamAttrs, RestUpstreamAttrs, NewUpstreamAttrs),
	verify_agnostic_attributes([Module | Explored], NewUpstreamAttrs), !.

% ------------------- Framework Entry Point -------------------------

no_error() :-
	verify_types([], []),
	verify_prot_attributes([], []),
	verify_agnostic_attributes([], []).



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

-------------------------------- MODULE AKAC --------------------------------
(***************************************************************************)
(* Bounded TLA+ model of the AKAC core authorization semantics (0.5 plus   *)
(* the 0.6 rules, R121-R196), checked with TLC. See docs/FORMAL-MODEL.md. *)
(*                                                                         *)
(* The OPERATIONAL part mirrors reference/policy.ts (decide, grantValid,   *)
(* visible, destinationGate), reference/engine.ts (openContext, derive,    *)
(* release, delegate) and reference/control.ts (revoke, quarantine,       *)
(* release from quarantine, erase, relabel with the R126 rule).        *)
(* The DECLARATIVE part states each property over every request of the    *)
(* finite universe, with its own closures (lineage, grant chain and role  *)
(* closure as fixpoints over the whole state, not the recursive visible() *)
(* traversal), raw tenant equality and a semantic notion of label         *)
(* widening. `Mutation` switches in one deliberately broken rule; "none"  *)
(* is the faithful model. Configurations: MC.cfg, MC_admin.cfg (faithful), *)
(* broken/*.cfg (must fail), witness/*.cfg (non-vacuity, must fail).       *)
(*                                                                         *)
(* A model is not the code: agreement between this model and the          *)
(* TypeScript reference is argued by review and by the conformance         *)
(* vectors, not proven. All results are bounded (finite universe below).   *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets

CONSTANTS
  Mutation,   \* "none" or the name of one broken rule (see Mutations)
  MaxEpoch,   \* bound on administrative changes (each advances the epoch)
  MaxDelegations, \* bound on delegated grants (0..2), each a child of the newest grant
  MaxContexts,    \* bound on contexts (1..2)
  MaxDerived      \* bound on derived records (1..2)

Mutations == {"none", "NoPurposeAttenuation", "DeriveOwnMinLabel",
              "LifecycleNotTransitive", "QuarantineNoEpoch", "NoTenantCheck",
              "DynSoDOnlyActivated", "ReleaseShallowRecipient", "KbAdminMayWiden"}
ASSUME /\ Mutation \in Mutations /\ MaxEpoch \in Nat /\ MaxDelegations \in 0..2
       /\ MaxContexts \in 1..2 /\ MaxDerived \in 1..2

-----------------------------------------------------------------------------
(* Fixed, bounded universe. Levels 0..2 stand for public < internal <     *)
(* confidential (the reference has four levels; three suffice to express  *)
(* above/below/equal for every comparison the model makes).               *)
-----------------------------------------------------------------------------
NONE == "none"
Levels == 0..2
Users == {"u1", "u2", "v1"}          \* u1: grant subject; u2: colleague; v1: other tenant
Agents == {"a1"}
Principals == Users \cup Agents
Projects == {"pa"}
RoleNames == {"lead", "staff", "audit"}
Inherits == [r \in RoleNames |-> IF r = "lead" THEN {"staff"} ELSE {}]
StaticSoD == {[roles |-> {"lead", "audit"}, card |-> 2]}
DynamicSoD == {[roles |-> {"staff", "audit"}, card |-> 2]}
Purposes == {"p1", "p2"}
Actions == {"read", "derive", "share"}        \* export behaves as share
Docs == {"k1", "k2", "k3"}                    \* administratively ingested documents
DerivedIds == {"d1", "d2"}                    \* slots for model-derived records
KIds == Docs \cup DerivedIds
GIds == {"g1", "g2", "g3"}                    \* g1 issued by the control plane; g2, g3 delegated
CIds == {"x1", "x2"}
Admins == {"sec", "kb"}
AdminRoles == [a \in Admins |-> IF a = "sec" THEN {"security-admin"} ELSE {"kb-admin"}]

TenantOf(p) == IF p = "v1" THEN "t2" ELSE "t1"
Clearance(p) == IF p = "u2" THEN 1 ELSE 2
ProjectsOf(p) == IF p = "u2" THEN {} ELSE {"pa"}
\* Destination profiles (ADR-008): u2 is an external destination (max internal, purpose p1);
\* other users are the implicit internal-user destination; the agent has none.
Profile(p) ==
  CASE p = "u2" -> [kind |-> "profile", class |-> "external", maxCls |-> 1, purposes |-> {"p1"}, active |-> TRUE]
    [] p \in Users -> [kind |-> "implicit", class |-> "internal-user", maxCls |-> 2, purposes |-> Purposes, active |-> TRUE]
    [] OTHER -> [kind |-> "none", class |-> NONE, maxCls |-> 0, purposes |-> {}, active |-> FALSE]
\* One knowledge-base container: floor internal, ACL names u1 and a1 only.
C1 == [tenant |-> "t1", cls |-> 1, readers |-> {"u1", "a1"}, roles |-> {}, projects |-> {}, active |-> TRUE]

Max(S) == CHOOSE m \in S : \A n \in S : n <= m
Min(S) == CHOOSE m \in S : \A n \in S : m <= n

VARIABLES
  world,  \* initial choices that never change: u1's direct roles, group membership
  now,    \* logical clock (0..1)
  epoch,  \* tenant t1 revocation epoch (t2 has no administrative activity)
  know,   \* knowledge records
  grant,  \* grants (delegation chain)
  ctx     \* contexts (run manifests)
vars == <<world, now, epoch, know, grant, ctx>>

DirectRoles(p) == IF p = "u1" THEN world.u1roles ELSE {"staff"}
GroupRoles(p) == IF p = "u1" /\ world.inGroup THEN {"audit"} ELSE {}

-----------------------------------------------------------------------------
(* Records                                                                 *)
-----------------------------------------------------------------------------
Absent == [exists |-> FALSE, tenant |-> "t1", cls |-> 0, readers |-> {}, roles |-> {},
           projects |-> {}, container |-> NONE, sources |-> {}, active |-> FALSE,
           lc |-> "none", ver |-> 0, by |-> NONE]
K1 == [Absent EXCEPT !.exists = TRUE, !.cls = 0, !.roles = {"staff"}, !.container = "c1",
                     !.active = TRUE, !.ver = 1]
K2 == [Absent EXCEPT !.exists = TRUE, !.cls = 0, !.readers = {"u1", "u2", "a1"},
                     !.active = TRUE, !.ver = 1]
K3 == [Absent EXCEPT !.exists = TRUE, !.tenant = "t2", !.readers = {"u1", "a1", "v1"},
                     !.roles = {"staff"}, !.active = TRUE, !.ver = 1]

NoGrant == [issued |-> FALSE, tenant |-> "t1", subject |-> "u1", agent |-> "a1",
            actions |-> {}, resources |-> {}, purposes |-> {}, destR |-> FALSE, dest |-> {},
            actR |-> FALSE, act |-> {}, max |-> 0, expires |-> 0, parent |-> NONE, active |-> FALSE]
\* Root A: broad run that may share; root B: narrow, restricted, activated, result-limited.
RootA == [NoGrant EXCEPT !.issued = TRUE, !.active = TRUE, !.actions = {"read", "derive", "share"},
                         !.resources = {"*"}, !.purposes = {"p1"}, !.expires = 2]
RootB == [NoGrant EXCEPT !.issued = TRUE, !.active = TRUE, !.actions = {"read", "derive"},
                         !.resources = {"k1", "k2"}, !.purposes = {"p1", "p2"},
                         !.destR = TRUE, !.dest = {"internal-user"},
                         !.actR = TRUE, !.act = {"staff"}, !.max = 1, !.expires = 1]
NoCtx == [open |-> FALSE, grant |-> "g1", sources |-> {}, n |-> 0, purpose |-> "p1", epoch |-> 0, expires |-> 0]

-----------------------------------------------------------------------------
(* OPERATIONAL semantics (mirrors reference/policy.ts)                     *)
-----------------------------------------------------------------------------
SameTenant(x, y) == Mutation = "NoTenantCheck" \/ x = y

CloseRoles(S) == LET f[n \in 0..Cardinality(RoleNames)] ==
                       IF n = 0 THEN S ELSE f[n-1] \cup UNION {Inherits[r] : r \in f[n-1]}
                 IN f[Cardinality(RoleNames)]
EffRoles(p) == CloseRoles(DirectRoles(p) \cup GroupRoles(p))
Violates(cs, R) == \E c \in cs : Cardinality(c.roles \cap R) >= c.card
Standing(p) == ~Violates(StaticSoD, EffRoles(p))

Covers(res, k) == "*" \in res \/ k \in res
SubRes(small, large) == \A r \in small : "*" \in large \/ r \in large

\* grantValid(): liveness, time, and attenuation against the parent, recursively.
GrantLive(G) ==
  /\ G.issued /\ G.active /\ now < G.expires /\ G.actions # {}
  /\ SameTenant(TenantOf(G.subject), G.tenant) /\ SameTenant(TenantOf(G.agent), G.tenant)
Attenuates(G, P) ==
  /\ P.issued /\ SameTenant(P.tenant, G.tenant) /\ P.subject = G.subject
  /\ G.actions \subseteq P.actions
  /\ SubRes(G.resources, P.resources)
  /\ Mutation = "NoPurposeAttenuation" \/ G.purposes \subseteq P.purposes
  /\ G.expires <= P.expires
  /\ ~P.actR \/ (G.actR /\ G.act \subseteq P.act)
  /\ ~P.destR \/ (G.destR /\ G.dest \subseteq P.dest)
  /\ P.max = 0 \/ (G.max # 0 /\ G.max <= P.max)
\* The delegation chain of g in grant map gs (grants are acyclic: a child id is
\* always fresh), then every link checked as grantValid() does recursively.
ChainIn(gs, g) == LET f[n \in 0..Cardinality(GIds)] ==
                        IF n = 0 THEN {g} ELSE f[n-1] \cup ({gs[h].parent : h \in f[n-1]} \ {NONE})
                  IN f[Cardinality(GIds)]
GrantValid(gs, g) ==
  \A h \in ChainIn(gs, g) :
    /\ GrantLive(gs[h])
    /\ IF gs[h].parent = NONE THEN TRUE ELSE Attenuates(gs[h], gs[gs[h].parent])

\* sessionRoles(): activated roles and their juniors, else every effective role.
Session(g) == IF grant[g].actR THEN CloseRoles(grant[g].act) ELSE EffRoles(grant[g].subject)
SessionValid(g) == ~grant[g].actR \/ grant[g].act \subseteq EffRoles(grant[g].subject)

Audience(p, R, L) ==
  /\ SameTenant(TenantOf(p), L.tenant) /\ Clearance(p) >= L.cls
  /\ L.projects \subseteq ProjectsOf(p)
  /\ (p \in L.readers \/ L.roles \cap R # {})

\* visible(): the record, its container and every transitive source admit p.
RECURSIVE Visible(_, _, _, _)
Visible(p, k, R, root) ==
  /\ know[k].exists /\ know[k].active
  /\ know[k].lc = "none" \/ (Mutation = "LifecycleNotTransitive" /\ ~root)
  /\ Audience(p, R, know[k])
  /\ know[k].container = NONE \/ (C1.active /\ Audience(p, R, C1))
  /\ \A r \in know[k].sources : know[r[1]].exists /\ know[r[1]].ver = r[2] /\ Visible(p, r[1], R, FALSE)

EffCls(k) == IF know[k].container = NONE THEN know[k].cls ELSE Max({know[k].cls, C1.cls})
EffProjects(k) == IF know[k].container = NONE THEN know[k].projects ELSE know[k].projects \cup C1.projects
\* transitiveClassification()
RECURSIVE TransCls(_)
TransCls(k) == Max({EffCls(k)} \cup {TransCls(r[1]) : r \in know[k].sources})

\* decide(): binding, grant chain, scope, SoD, then visibility for user and agent.
\* Written as Scope /\ Core: a conjunction, so the split (Core depends on the
\* grant and the record only) changes which reason code the reference would
\* report, never allow/deny. Invariants evaluate Core once per (grant, record).
Scope(g, k, a, p) ==
  /\ grant[g].issued /\ know[k].exists
  /\ a \in grant[g].actions /\ Covers(grant[g].resources, k) /\ p \in grant[g].purposes
Core(g, k) ==
  /\ SameTenant(TenantOf(grant[g].subject), grant[g].tenant) /\ SameTenant(TenantOf(grant[g].agent), grant[g].tenant)
  /\ SameTenant(know[k].tenant, grant[g].tenant)
  /\ GrantValid(grant, g)
  /\ SessionValid(g)
  /\ LET session == Session(g) IN
     /\ ~Violates(StaticSoD, EffRoles(grant[g].subject)) /\ ~Violates(StaticSoD, EffRoles(grant[g].agent))
     /\ (Mutation = "DynSoDOnlyActivated" /\ ~grant[g].actR) \/ ~Violates(DynamicSoD, session)
     /\ Visible(grant[g].subject, k, session, TRUE)
     /\ Visible(grant[g].agent, k, EffRoles(grant[g].agent), TRUE)
Decide(g, k, a, p) == Scope(g, k, a, p) /\ Core(g, k)
\* Every allowed decision request <<g, k, a, p>> of the current state.
Allowed == LET pairs == {gk \in GIds \X KIds : (\E a \in Actions, p \in Purposes : Scope(gk[1], gk[2], a, p)) /\ Core(gk[1], gk[2])}
           IN {q \in pairs \X Actions \X Purposes : Scope(q[1][1], q[1][2], q[2], q[3])}

\* Contexts: a context is fresh in its tenant's current epoch before expiry.
SrcIds(x) == {r[1] : r \in ctx[x].sources}
SameBinding(x) == {y \in CIds : ctx[y].open /\ ctx[y].grant = ctx[x].grant}
Fresh(y) == ctx[y].open /\ ctx[y].epoch = epoch /\ now < ctx[y].expires
\* contextSources(): every context of the binding fresh, same purpose, unchanged
\* source versions, and every source re-authorized for the action.
Usable(x, a) ==
  /\ ctx[x].open
  /\ \A y \in SameBinding(x) :
       /\ Fresh(y) /\ ctx[y].purpose = ctx[x].purpose
       /\ \A r \in ctx[y].sources :
            know[r[1]].exists /\ know[r[1]].ver = r[2] /\ Decide(ctx[x].grant, r[1], a, ctx[x].purpose)
UsedRefs(x) == UNION {ctx[y].sources : y \in SameBinding(x)}
UsedIds(x) == {r[1] : r \in UsedRefs(x)}

\* destinationGate() for a named recipient (release()).
DestGate(G, r, top, p) ==
  LET P == Profile(r) IN
  CASE P.kind = "profile" -> P.active /\ (~G.destR \/ P.class \in G.dest) /\ top <= P.maxCls /\ p \in P.purposes
    [] P.kind = "implicit" -> ~G.destR \/ "internal-user" \in G.dest
    [] OTHER -> ~G.destR

\* release(): share/export of a context to a named recipient.
ReleaseOK(x, r) ==
  LET G == grant[ctx[x].grant] IN
  /\ Usable(x, "share")
  /\ SameTenant(TenantOf(r), G.tenant)
  /\ \A s \in UsedIds(x) :
       IF Mutation = "ReleaseShallowRecipient"
       THEN Standing(r) /\ Audience(r, EffRoles(r), know[s])
       ELSE Standing(r) /\ Visible(r, s, EffRoles(r), TRUE)
  /\ DestGate(G, r, Max({TransCls(s) : s \in UsedIds(x)}), ctx[x].purpose)

-----------------------------------------------------------------------------
(* Actions                                                                 *)
-----------------------------------------------------------------------------
Init ==
  /\ world \in [u1roles : {{"staff"}, {"lead"}}, inGroup : BOOLEAN]
  /\ now = 0
  /\ epoch = 0
  /\ know = [k \in KIds |-> CASE k = "k1" -> K1 [] k = "k2" -> K2 [] k = "k3" -> K3 [] OTHER -> Absent]
  /\ \E root \in {RootA, RootB} : grant = [g \in GIds |-> IF g = "g1" THEN root ELSE NoGrant]
  /\ ctx = [x \in CIds |-> NoCtx]

\* Holds(P): evaluate a state predicate as one value. At action level TLC treats
\* every disjunction as a branch, so a guard such as Decide() would otherwise
\* produce many identical successor states (same states, much slower search).
Holds(P) == P = TRUE

Tick == now = 0 /\ now' = 1 /\ UNCHANGED <<world, epoch, know, grant, ctx>>

\* Child candidates: the parent with one field replaced by a value of a small
\* domain (wider, narrower or unrelated, depending on the parent).
Variants(P) ==
     {[P EXCEPT !.actions = v] : v \in {{"read"}, {"read", "derive", "share"}}}
  \cup {[P EXCEPT !.resources = v] : v \in {{"*"}, {"k1"}}}
  \cup {[P EXCEPT !.purposes = v] : v \in {{"p1"}, {"p1", "p2"}}}
  \cup {[P EXCEPT !.destR = FALSE, !.dest = {}], [P EXCEPT !.destR = TRUE, !.dest = {"external"}]}
  \cup {[P EXCEPT !.actR = FALSE, !.act = {}], [P EXCEPT !.actR = TRUE, !.act = {"audit"}]}
  \cup {[P EXCEPT !.max = v] : v \in {0, 1}}
  \cup {[P EXCEPT !.expires = v] : v \in {1, 2}}

\* engine.delegate() / canDelegate(): the child must be a valid grant in the next state.
Delegate ==
  LET pg == IF grant["g2"].issued THEN "g2" ELSE "g1"   \* a chain g1 <- g2 <- g3
      cg == IF grant["g2"].issued THEN "g3" ELSE "g2" IN
    /\ Cardinality({h \in GIds : grant[h].issued /\ grant[h].parent # NONE}) < MaxDelegations
    /\ ~grant[cg].issued
    /\ \E V \in Variants(grant[pg]) :
         LET C == [V EXCEPT !.parent = pg, !.issued = TRUE, !.active = TRUE]
             next == [grant EXCEPT ![cg] = C]
         IN /\ Holds(GrantValid(next, cg))
            /\ grant' = next
    /\ UNCHANGED <<world, now, epoch, know, ctx>>

Requests == {S \in SUBSET KIds : Cardinality(S) \in {1, 2}}

\* engine.openContext() / projection().
OpenContext ==
  \E g \in GIds, p \in Purposes, S \in Requests :
    LET x == IF ~ctx["x1"].open THEN "x1" ELSE "x2"
        same == {y \in CIds : ctx[y].open /\ ctx[y].grant = g}
        all == S \cup UNION {{r[1] : r \in ctx[y].sources} : y \in same}
    IN
    /\ ~ctx[x].open /\ (x = "x1" \/ MaxContexts = 2) /\ grant[g].issued
    /\ \A k \in S : know[k].exists
    /\ Holds(grant[g].max = 0 \/ Cardinality(S) <= grant[g].max)
    /\ Holds(\A y \in same : Fresh(y) /\ \A r \in ctx[y].sources : know[r[1]].ver = r[2])
    /\ Holds(\A k \in all : Decide(g, k, "read", p))
    /\ ctx' = [ctx EXCEPT ![x] = [open |-> TRUE, grant |-> g, purpose |-> p, epoch |-> epoch,
                                   sources |-> {<<k, know[k].ver>> : k \in all}, n |-> Cardinality(S),
                                   expires |-> Min({grant[g].expires} \cup {ctx[y].expires : y \in same})]]
    /\ UNCHANGED <<world, now, epoch, know, grant>>

\* engine.derive(): label = highest transitive classification, union of projects,
\* union of local ACLs (the transitive source conjunction still applies through
\* visible()), provenance = every source of the run.
DerivedRecord(x) ==
  LET ids == UsedIds(x) IN
  IF Mutation = "DeriveOwnMinLabel"
  THEN [Absent EXCEPT !.exists = TRUE, !.active = TRUE, !.ver = 1,
          !.cls = Min({know[s].cls : s \in ids}),
          !.projects = UNION {EffProjects(s) : s \in ids},
          !.readers = UNION {know[s].readers : s \in ids}, !.roles = UNION {know[s].roles : s \in ids},
          !.sources = UsedRefs(x)]
  ELSE [Absent EXCEPT !.exists = TRUE, !.active = TRUE, !.ver = 1,
          !.cls = Max({TransCls(s) : s \in ids}),
          !.projects = UNION {EffProjects(s) : s \in ids},
          !.readers = UNION {know[s].readers : s \in ids}, !.roles = UNION {know[s].roles : s \in ids},
          !.sources = UsedRefs(x)]

Derive ==
  \E x \in CIds :
    LET d == IF ~know["d1"].exists THEN "d1" ELSE "d2" IN
    /\ ~know[d].exists /\ (d = "d1" \/ MaxDerived = 2)
    /\ Holds(Usable(x, "derive"))
    /\ know' = [know EXCEPT ![d] = DerivedRecord(x)]
    /\ UNCHANGED <<world, now, epoch, grant, ctx>>

\* Control plane (reference/control.ts). Each change advances the tenant epoch.
\* Bound: lifecycle changes target the tenant's ingested documents (the roots of
\* every lineage); derived records are affected through their lineage.
AdminTargets == {k \in Docs : know[k].exists /\ know[k].tenant = "t1"}
Bump == epoch' = epoch + 1

RevokeGrant ==
  /\ epoch < MaxEpoch
  /\ \E g \in GIds : grant[g].issued /\ grant[g].active /\ grant' = [grant EXCEPT ![g].active = FALSE]
  /\ Bump /\ UNCHANGED <<world, now, know, ctx>>

RevokeKnowledge ==
  /\ epoch < MaxEpoch
  /\ \E k \in AdminTargets : know[k].active /\ know' = [know EXCEPT ![k].active = FALSE]
  /\ Bump /\ UNCHANGED <<world, now, grant, ctx>>

Quarantine ==
  /\ epoch < MaxEpoch
  /\ \E k \in AdminTargets : know[k].lc = "none" /\ know' = [know EXCEPT ![k].lc = "quarantined"]
  /\ IF Mutation = "QuarantineNoEpoch" THEN UNCHANGED epoch ELSE Bump
  /\ UNCHANGED <<world, now, grant, ctx>>

Unquarantine ==   \* release from quarantine (security-admin)
  /\ epoch < MaxEpoch
  /\ \E k \in AdminTargets : know[k].lc = "quarantined" /\ know' = [know EXCEPT ![k].lc = "none"]
  /\ Bump /\ UNCHANGED <<world, now, grant, ctx>>

\* Lineage by id at any version (reference/lifecycle.ts lineage()).
Parents(S) == UNION {{r[1] : r \in know[j].sources} : j \in S}
Ancestors(k) == LET f[n \in 0..Cardinality(KIds)] == IF n = 0 THEN Parents({k}) ELSE f[n-1] \cup Parents(f[n-1])
                IN f[Cardinality(KIds)]
Tomb(K) == [K EXCEPT !.lc = "erased", !.active = FALSE, !.readers = {}, !.roles = {}]

Erase ==   \* cascade erasure: the record and every descendant become tombstones
  /\ epoch < MaxEpoch
  /\ \E k \in AdminTargets :
       /\ know[k].lc # "erased"
       /\ know' = [j \in KIds |-> IF j = k \/ (know[j].exists /\ k \in Ancestors(j)) THEN Tomb(know[j]) ELSE know[j]]
  /\ Bump /\ UNCHANGED <<world, now, grant, ctx>>

\* Relabel candidates: one label field changed (classification one step up or
\* down, reader u2, reader role audit, project pa toggled).
Toggle(S, e) == IF e \in S THEN S \ {e} ELSE S \cup {e}
Candidates(K) ==
     {[K EXCEPT !.cls = c] : c \in {K.cls - 1, K.cls + 1} \cap Levels}
  \cup {[K EXCEPT !.readers = Toggle(K.readers, "u2")],
        [K EXCEPT !.roles = Toggle(K.roles, "audit")],
        [K EXCEPT !.projects = Toggle(K.projects, "pa")]}
\* control.ts widensLabel() restricted to the modelled fields.
SynWidens(old, new) ==
  \/ new.cls < old.cls
  \/ ~(new.readers \subseteq old.readers)
  \/ ~(new.roles \subseteq old.roles)
  \/ ~(old.projects \subseteq new.projects)

\* upsertKnowledge() on an existing document with unchanged content (R126).
Relabel ==
  /\ epoch < MaxEpoch
  /\ \E adm \in Admins, k \in {"k1", "k2"} :
       /\ know[k].exists /\ know[k].lc # "erased"
       /\ \E L \in Candidates(know[k]) :
            LET kb == "kb-admin" \in AdminRoles[adm]
                sec == "security-admin" \in AdminRoles[adm]
                w == SynWidens(know[k], L)
            IN /\ Holds(kb \/ w)                                    \* security-admin alone: widening only
               /\ Holds(w => (sec \/ Mutation = "KbAdminMayWiden")) \* CONFLICT for a kb-admin
               /\ know' = [know EXCEPT ![k] = [L EXCEPT !.ver = know[k].ver + 1, !.by = adm]]
  /\ Bump /\ UNCHANGED <<world, now, grant, ctx>>

Next == Tick \/ Delegate \/ OpenContext \/ Derive \/ RevokeGrant \/ RevokeKnowledge
        \/ Quarantine \/ Unquarantine \/ Erase \/ Relabel

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------
(* DECLARATIVE properties                                                  *)
-----------------------------------------------------------------------------
TypeOK ==
  /\ now \in 0..1 /\ epoch \in 0..MaxEpoch
  /\ \A k \in KIds : know[k].cls \in Levels /\ know[k].lc \in {"none", "quarantined", "erased"}
  /\ \A g \in GIds : grant[g].parent \in GIds \cup {NONE}

\* Role closure as a relational fixpoint (independent of CloseRoles).
InhPairs == {<<a, b>> \in RoleNames \X RoleNames : b \in Inherits[a]}
RoleReach(S) == LET f[n \in 0..Cardinality(RoleNames)] ==
                      IF n = 0 THEN S ELSE f[n-1] \cup {b \in RoleNames : \E a \in f[n-1] : <<a, b>> \in InhPairs}
                IN f[Cardinality(RoleNames)]
DeclRoles(p) == RoleReach(DirectRoles(p) \cup GroupRoles(p))
DeclSession(g) == IF grant[g].actR THEN RoleReach(grant[g].act) ELSE DeclRoles(grant[g].subject)
\* A constraint is met when some subset of its roles of size >= cardinality is held.
Meets(cs, R) == \E c \in cs : \E T \in SUBSET c.roles : Cardinality(T) >= c.card /\ T \subseteq R

\* Grant chain: g and every ancestor via `parent`.
ParentsG(S) == {grant[h].parent : h \in S} \ {NONE}
Chain(g) == LET f[n \in 0..Cardinality(GIds)] == IF n = 0 THEN {g} ELSE f[n-1] \cup ParentsG(f[n-1])
            IN f[Cardinality(GIds)]

Lineage(k) == {k} \cup Ancestors(k)
Live(a) == know[a].exists /\ know[a].active /\ know[a].lc = "none"
DeclEffCls(a) == Max({know[a].cls} \cup IF know[a].container = NONE THEN {} ELSE {C1.cls})
\* Admission by one record's own label and its container, with raw tenant equality.
Admits(p, R, a) ==
  LET A == know[a] IN
  /\ TenantOf(p) = A.tenant /\ Clearance(p) >= DeclEffCls(a) /\ A.projects \subseteq ProjectsOf(p)
  /\ (p \in A.readers \/ A.roles \cap R # {})
  /\ A.container = NONE \/ (TenantOf(p) = C1.tenant /\ C1.active /\ C1.projects \subseteq ProjectsOf(p)
                            /\ (p \in C1.readers \/ C1.roles \cap R # {}))
\* Every provenance reference of the lineage resolves at its bound version.
Resolves(d) == \A a \in Lineage(d) : \A r \in know[a].sources : know[r[1]].exists /\ know[r[1]].ver = r[2]
Recipients == Principals

\* (1) A delegated grant never permits an (action, resource, purpose,
\* destination, result count, session role) that some grant of its chain does not.
NoEscalationThroughDelegation ==
  /\ \A q \in Allowed : LET g == q[1][1] k == q[1][2] a == q[2] p == q[3] IN
         \A h \in Chain(g) :
           /\ grant[h].issued /\ grant[h].active /\ now < grant[h].expires
           /\ a \in grant[h].actions /\ ("*" \in grant[h].resources \/ k \in grant[h].resources)
           /\ p \in grant[h].purposes /\ grant[h].subject = grant[g].subject
           /\ grant[h].actR => (grant[g].actR /\ RoleReach(grant[g].act) \subseteq RoleReach(grant[h].act))
  /\ \A x \in CIds, r \in Recipients :
       ReleaseOK(x, r) => \A h \in Chain(ctx[x].grant) : grant[h].destR => Profile(r).class \in grant[h].dest
  /\ \A x \in CIds :   \* documents one disclosure returned
       ctx[x].open => \A h \in Chain(ctx[x].grant) : grant[h].max # 0 => ctx[x].n <= grant[h].max

\* (2) A derived record is never classified below any record of its (resolving)
\* lineage, keeps every project, and admits no principal that some record of its
\* lineage does not admit.
NoDeclassificationThroughDerivation ==
  \A d \in DerivedIds :
    know[d].exists =>
      /\ Resolves(d) => \A a \in Ancestors(d) : know[d].cls >= DeclEffCls(a) /\ know[a].projects \subseteq know[d].projects
      /\ \A p \in Principals :
           (Standing(p) /\ Visible(p, d, EffRoles(p), TRUE)) => \A a \in Ancestors(d) : Admits(p, DeclRoles(p), a)

\* (3) Nothing whose lineage holds a revoked, quarantined or erased record is
\* read, derived or released, and no context survives such a change as fresh.
RevokedOrQuarantinedSourceNoDisclosure ==
  /\ \A q \in Allowed : LET g == q[1][1] k == q[1][2] a == q[2] p == q[3] IN \A b \in Lineage(k) : Live(b)
  /\ \A x \in CIds : Fresh(x) => \A s \in SrcIds(x) : \A b \in Lineage(s) : Live(b)
  /\ \A x \in CIds, r \in Recipients : ReleaseOK(x, r) => \A s \in UsedIds(x) : \A b \in Lineage(s) : Live(b)

\* (4) No decision, context, derivation or release crosses tenants.
TenantIsolation ==
  /\ \A q \in Allowed : LET g == q[1][1] k == q[1][2] a == q[2] p == q[3] IN
         /\ TenantOf(grant[g].subject) = grant[g].tenant /\ TenantOf(grant[g].agent) = grant[g].tenant
         /\ \A b \in Lineage(k) : know[b].tenant = grant[g].tenant
         /\ \A h \in Chain(g) : grant[h].tenant = grant[g].tenant
  /\ \A x \in CIds : ctx[x].open => \A s \in SrcIds(x) : know[s].tenant = grant[ctx[x].grant].tenant
  /\ \A d \in DerivedIds : know[d].exists => \A a \in Ancestors(d) : know[a].tenant = know[d].tenant
  /\ \A x \in CIds, r \in Recipients : ReleaseOK(x, r) => TenantOf(r) = grant[ctx[x].grant].tenant

\* (5) No allowed decision for a principal whose held roles meet a static
\* constraint, or whose session roles meet a dynamic one; no such recipient.
SeparationOfDuty ==
  /\ \A q \in Allowed : LET g == q[1][1] k == q[1][2] a == q[2] p == q[3] IN
         /\ ~Meets(StaticSoD, DeclRoles(grant[g].subject))
         /\ ~Meets(StaticSoD, DeclRoles(grant[g].agent))
         /\ ~Meets(DynamicSoD, DeclSession(g))
         /\ DeclSession(g) \subseteq DeclRoles(grant[g].subject)
  /\ \A x \in CIds, r \in Recipients : ReleaseOK(x, r) => ~Meets(StaticSoD, DeclRoles(r))

\* (6) A release succeeds only if the recipient is admitted by every record of
\* every released lineage, and its destination admits class, classification and purpose.
ReleaseRecipientCheck ==
  \A x \in CIds, r \in Recipients :
    ReleaseOK(x, r) =>
      LET top == Max({DeclEffCls(b) : b \in UNION {Lineage(s) : s \in UsedIds(x)}}) IN
      /\ TenantOf(r) = grant[ctx[x].grant].tenant
      /\ \A s \in UsedIds(x) : \A b \in Lineage(s) : Live(b) /\ Admits(r, DeclRoles(r), b)
      /\ Profile(r).kind = "profile" => (Profile(r).active /\ top <= Profile(r).maxCls /\ ctx[x].purpose \in Profile(r).purposes)
      /\ \A h \in Chain(ctx[x].grant) : grant[h].destR => Profile(r).class \in grant[h].dest

\* (7) Semantic widening: some conceivable principal is admitted by the new own
\* label but not by the old one.
HypPrincipals == [clr : Levels, prj : SUBSET Projects, id : Principals \cup {"other"}, roles : SUBSET RoleNames]
OwnAdmits(h, L) == h.clr >= L.cls /\ L.projects \subseteq h.prj /\ (h.id \in L.readers \/ L.roles \cap h.roles # {})
SemWidens(old, new) == \E h \in HypPrincipals : OwnAdmits(h, new) /\ ~OwnAdmits(h, old)
Labelled(K) == [cls |-> K.cls, readers |-> K.readers, roles |-> K.roles, projects |-> K.projects]
LabelWideningRequiresSecurityAdmin ==
  [][\A k \in Docs :
       (know[k].exists /\ know'[k].exists /\ Labelled(know[k]) # Labelled(know'[k])
        /\ SemWidens(know[k], know'[k]))
       => (know'[k].by \in Admins /\ "security-admin" \in AdminRoles[know'[k].by])]_vars

-----------------------------------------------------------------------------
(* Non-vacuity witnesses: each MUST be violated (TLC finds a behaviour     *)
(* that reaches the situation), so the properties above are not vacuous.  *)
-----------------------------------------------------------------------------
NeverReleaseToColleague == ~\E x \in CIds : ReleaseOK(x, "u2")
NeverDelegatedAllow == ~\E g \in GIds, k \in KIds, a \in Actions, p \in Purposes :
                          grant[g].parent # NONE /\ grant[grant[g].parent].parent # NONE /\ Decide(g, k, a, p)
NeverDerivedFromDerived == ~\E d \in DerivedIds : know[d].exists /\ \E r \in know[d].sources : r[1] \in DerivedIds
NeverReadDerived == ~\E g \in GIds, d \in DerivedIds : Decide(g, d, "read", "p1")
NeverSecurityWidening == [][~\E k \in Docs : know[k].exists /\ SemWidens(know[k], know'[k])]_vars
=============================================================================

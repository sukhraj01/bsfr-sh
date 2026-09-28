---------------------------- MODULE pbft ----------------------------
(***************************************************************************)
(* M7-18. Formal specification of the *reduced* pBFT consensus protocol   *)
(* implemented in `consensus/pbft.py`, `consensus/protocol.py`,           *)
(* `consensus/view_change.py` (DEV-10, DEV-20).  Companion to M7-1's      *)
(* Scyther model of `crypto.session` (DEV-14): that verified the          *)
(* point-to-point session-establishment layer symbolically; this verifies *)
(* the multi-party consensus layer by exhaustive model checking.          *)
(*                                                                         *)
(* Scope: one sequence-number pipeline (DEV-20 #3, no pipelining), no     *)
(* checkpoints (DEV-20 #1 -- bounded instead via MaxSeq), no state        *)
(* transfer (DEV-20 #2 -- modelled directly, see DoCommit below), no      *)
(* null requests (DEV-20 #4, vacuous with one seq in flight), no          *)
(* retransmission (DEV-20 #6 -- the network is not modelled as lossy;     *)
(* liveness is checked under Dolev-Yao delivery, not message loss).       *)
(*                                                                         *)
(* Modelling choices, stated rather than silently assumed (mirrors the    *)
(* discipline `verification/README.md` set for the Scyther model):        *)
(*                                                                         *)
(* 1. Messages are never forged, only omitted, delayed or reordered       *)
(*    (Dolev-Yao over an authenticated channel -- `msgs` is a             *)
(*    monotonically growing SET of already-sent messages; any process     *)
(*    may "read" any message already in the set, in any order).  A        *)
(*    faulty replica may send ANY well-formed message under its own       *)
(*    identity (ByzantineAction) but can never produce a message          *)
(*    attributed to another replica's identity -- this is what "signed,   *)
(*    cannot forge" means for ECDSA-signed pBFT bodies (DEV-19).          *)
(*                                                                         *)
(* 2. ViewChange IS modelled as an explicit message (SendViewChange),     *)
(*    each one honestly reporting only what its OWN sender already knew   *)
(*    was prepared at the moment it was sent, and a new primary may       *)
(*    PrePrepare a later view only once it has collected a real `2f+1`    *)
(*    ViewChangeQuorumReached for it -- mirroring `view_change.py`'s      *)
(*    "broadcasts a signed ViewChange carrying every prepared certificate *)
(*    it holds" and the new primary needing `2f+1` of them before a       *)
(*    NewView is even possible.  An EARLIER draft of this spec tried the  *)
(*    cheaper route -- a plain guard on SendPrePrepare checking a GLOBAL, *)
(*    timing-free "was any block ever Prepared at an earlier view", with  *)
(*    no ViewChange message at all -- and TLC (MaxView=1, MaxSeq=1, F=1)  *)
(*    found a real Agreement violation under it within seconds: an        *)
(*    honest replica can race ahead to a new view and freely pick a       *)
(*    fresh block while a DIFFERENT honest replica is one message away    *)
(*    from completing the OLD view's certificate for something else --   *)
(*    the global snapshot the cheap guard consulted was simply not true   *)
(*    yet at the moment the new primary acted, though it inevitably       *)
(*    becomes true moments later in the very same trace.  That was a      *)
(*    SPEC bug, not a protocol one (kept as a comment on                  *)
(*    ViewChangeSenders below, because the mistake is instructive): the   *)
(*    real safety argument is a quorum-INTERSECTION argument between the  *)
(*    `2f+1` commit-senders for the old value and the `2f+1` view-change- *)
(*    senders for the new view (sharing at least `2f+1+2f+1-n` = 2        *)
(*    members at F=1/n=4, so at least one HONEST replica is in both), and *)
(*    it depends on each ViewChange message being a real, individually    *)
(*    honest report -- not a fact about the whole system becoming true at *)
(*    some possibly-later moment.  Modelling the message explicitly was   *)
(*    the fix, and it is also exactly the state the liveness property's   *)
(*    fairness constraint needs to range over, so it cost nothing beyond  *)
(*    correctness.                                                        *)
(*                                                                         *)
(* 3. QuorumSize is fixed from the DESIGN fault bound F (= 1 for the      *)
(*    paper's n=4, DEV-10's "3 of 4"), never recomputed from the ACTUAL   *)
(*    cardinality of Faulty.  This is the crux of the FLAW-5 check: the   *)
(*    protocol does not know how many replicas are really Byzantine, it  *)
(*    only knows the threshold it was configured with.  Faulty is a      *)
(*    separate constant, varied between runs (|Faulty|=1 for the safety  *)
(*    check, |Faulty|=2 for the FLAW-5 check) while QuorumSize stays 3.  *)
(***************************************************************************)

EXTENDS Naturals, FiniteSets, TLC

CONSTANTS
    r1, r2, r3, r4,  \* the four replica identities -- DEV-10 fixes n=4 for this paper's
                     \* configuration, so this is not made generic over an arbitrary N
    F,          \* the DESIGN fault bound (fixed: 1, for n=4 per DEV-10)
    Faulty,     \* the ACTUAL Byzantine replicas this run models, subset of Replicas
    MaxView,    \* bound on view number, for TLC (unbounded in the real protocol)
    MaxSeq,     \* bound on sequence number, for TLC (unbounded in the real protocol)
    Blocks,     \* small set of distinct proposable block values
    NoBlock     \* sentinel: "nothing committed here yet"

(* TLC's .cfg constant grammar has no tuple-literal syntax, so the ordered *)
(* replica list round-robin needs (`primary(view) -> ids[view % n]`,       *)
(* protocol.py) is built here from the four individually-declared          *)
(* constants rather than passed in as a CONSTANT sequence.                 *)
Replicas == {r1, r2, r3, r4}
RepSeq   == <<r1, r2, r3, r4>>
N        == 4

ASSUME
    /\ Faulty \subseteq Replicas
    /\ F \in Nat
    /\ MaxView \in Nat /\ MaxView >= 1
    /\ MaxSeq \in Nat /\ MaxSeq >= 1
    /\ NoBlock \notin Blocks

Honest     == Replicas \ Faulty
QuorumSize == 2 * F + 1              \* commit_threshold, protocol.py Membership
PrepVotes  == 2 * F                  \* prepare_quorum (non-primary prepares), protocol.py
Seqs       == 1..MaxSeq
Views      == 0..MaxView

(* protocol.py: `primary(view) -> ids[view % n]` *)
Primary(v) == RepSeq[(v % N) + 1]

VARIABLES
    view,   \* [Replicas -> Views]: each replica's current local view
    msgs,   \* set of every message ever sent (authenticated, never forged)
    log     \* [Replicas -> [Seqs -> Blocks \cup {NoBlock}]]: each replica's committed log

vars == <<view, msgs, log>>

Messages ==
    [type: {"PrePrepare"},  sender: Replicas, view: Views, seq: Seqs, block: Blocks]
        \cup [type: {"Prepare"},    sender: Replicas, view: Views, seq: Seqs, block: Blocks]
        \cup [type: {"Commit"},     sender: Replicas, view: Views, seq: Seqs, block: Blocks]
        \cup [type: {"ViewChange"}, sender: Replicas, view: Views, seq: Seqs, block: Blocks \cup {NoBlock}]

TypeOK ==
    /\ view \in [Replicas -> Views]
    /\ log  \in [Replicas -> [Seqs -> Blocks \cup {NoBlock}]]
    /\ msgs \subseteq Messages

-------------------------------------------------------------------------
(* Certificates, computed opportunistically from `msgs` -- there is no   *)
(* separate "phase" variable; a replica's phase for (v, s) is whatever   *)
(* these predicates say it is, given what has been sent so far.          *)

HasPrePrepare(v, s, b) ==
    \E m \in msgs : /\ m.type = "PrePrepare"
                     /\ m.sender = Primary(v)
                     /\ m.view = v /\ m.seq = s /\ m.block = b

PrepareSenders(v, s, b) ==
    { m.sender : m \in { mm \in msgs : /\ mm.type = "Prepare"
                                         /\ mm.view = v /\ mm.seq = s /\ mm.block = b
                                         /\ mm.sender # Primary(v) } }

(* "prepared" (protocol.py verify_prepared_certificate): accepted pre-prepare *)
(* plus `2f` matching prepares from distinct NON-PRIMARY replicas.            *)
Prepared(v, s, b) ==
    /\ HasPrePrepare(v, s, b)
    /\ Cardinality(PrepareSenders(v, s, b)) >= PrepVotes

CommitSenders(v, s, b) ==
    { m.sender : m \in { mm \in msgs : mm.type = "Commit" /\ mm.view = v
                                         /\ mm.seq = s /\ mm.block = b } }

(* "committed" (protocol.py verify_committed_certificate): prepared plus  *)
(* `commit_threshold` (2f+1) matching commits from distinct replicas.     *)
CommittedReady(v, s, b) ==
    Cardinality(CommitSenders(v, s, b)) >= QuorumSize

(* ViewChange quorum and the forced re-proposal it justifies.  EARLIER    *)
(* DRAFT NOTE, kept because the mistake is instructive: a first version   *)
(* of this spec computed "was ANY block ever Prepared at an earlier view" *)
(* as a plain, timing-free GLOBAL snapshot check, with no ViewChange      *)
(* message at all.  TLC (MaxView=1, MaxSeq=1, F=1) found a real Agreement *)
(* violation under that version: an honest replica can advance to view 1 *)
(* and legitimately be the one who ends up choosing a fresh block there, *)
(* racing another honest replica that is still one Prepare message away  *)
(* from completing view 0's certificate for a DIFFERENT block -- the     *)
(* global snapshot the guard consulted was simply not yet true at the    *)
(* moment the new primary acted, even though it inevitably becomes true  *)
(* moments later in the same trace.  That is a SPEC bug, not a protocol  *)
(* one: `view_change.py`'s actual safety argument is a quorum-            *)
(* INTERSECTION argument (the `2f+1` commit-senders for the old value and *)
(* the `2f+1` view-change-senders for the new view share at least         *)
(* `2f+1+2f+1-n` members, so at F=1/n=4 at least one HONEST replica is in *)
(* both), and it depends on each ViewChange message HONESTLY reporting   *)
(* what ITS OWN sender already knew AT THE TIME IT SENT IT -- not on a   *)
(* global fact becoming true at some possibly-later moment.  Modelled    *)
(* properly below with an explicit ViewChange message per replica.       *)

ViewChangeSenders(v, s) ==
    { m.sender : m \in { mm \in msgs : mm.type = "ViewChange" /\ mm.view = v /\ mm.seq = s } }

(* `view_change.py`'s `view_change_quorum` = `2f+1`: distinct view-changes *)
(* the new primary needs before it may issue anything for the new view.   *)
ViewChangeQuorumReached(v, s) == Cardinality(ViewChangeSenders(v, s)) >= QuorumSize

(* What a quorum of view-changes for (v, s) forces the new primary to     *)
(* re-propose.  A SECOND race surfaced here on the first attempt at this   *)
(* predicate (kept as a comment, like the one on ViewChangeSenders above,  *)
(* because it is equally instructive): counting the declared block of     *)
(* EVERY ViewChange message at face value lets a Byzantine sender simply  *)
(* ASSERT a false prepared-block claim with no evidence behind it, and    *)
(* TLC found exactly that -- a fabricated ViewChange declaring a second,  *)
(* never-actually-prepared block let a new primary "legitimately" pick    *)
(* either one.  Real Castro-Liskov does not trust the bare claim: "every  *)
(* receiver re-verifies each carried view-change and certificate" (DEV-   *)
(* 20) against the actual prepared-certificate evidence, which a          *)
(* Byzantine replica cannot forge (it would need `2f` genuine Prepare     *)
(* signatures from OTHER replicas it does not control).  So a declared    *)
(* block only forces anything here if `Prepared` independently confirms   *)
(* it against the real message log for the view being left -- exactly    *)
(* the re-verification DEV-20 describes, not a second trust-the-sender    *)
(* check.  An honest sender's declaration always re-verifies (it only     *)
(* ever declares what `Prepared` already told it, see SendViewChange);    *)
(* a dishonest one's only does when the claim happens to be true anyway,  *)
(* which no longer helps the adversary.                                   *)
ForcedBlocks(v, s) ==
    { m.block : m \in { mm \in msgs : /\ mm.type = "ViewChange" /\ mm.view = v /\ mm.seq = s
                                         /\ mm.block # NoBlock
                                         /\ Prepared(v - 1, s, mm.block) } }

-------------------------------------------------------------------------
Init ==
    /\ view = [r \in Replicas |-> 0]
    /\ msgs = {}
    /\ log  = [r \in Replicas |-> [s \in Seqs |-> NoBlock]]

(* An honest primary proposes at most one block per (view, seq) -- no     *)
(* self-equivocation.  View 0 is the genesis view (no view-change needed  *)
(* to enter it); any later view requires this replica to have actually    *)
(* seen a `2f+1` ViewChange quorum for it, and if that quorum's own       *)
(* declarations force a block, only that block may be (re-)proposed.      *)
SendPrePrepare(r, s, b) ==
    /\ r \in Honest
    /\ r = Primary(view[r])
    /\ ~ \E m \in msgs : m.type = "PrePrepare" /\ m.sender = r
                          /\ m.view = view[r] /\ m.seq = s
    /\ view[r] = 0 \/ ViewChangeQuorumReached(view[r], s)
    /\ LET forced == IF view[r] = 0 THEN {} ELSE ForcedBlocks(view[r], s)
       IN forced = {} \/ b \in forced
    /\ msgs' = msgs \cup {[type |-> "PrePrepare", sender |-> r, view |-> view[r], seq |-> s, block |-> b]}
    /\ UNCHANGED <<view, log>>

(* An honest replica endorses at most one block per (view, seq) -- no     *)
(* equivocation -- and only after seeing a matching pre-prepare.          *)
SendPrepare(r, s, b) ==
    /\ r \in Honest
    /\ HasPrePrepare(view[r], s, b)
    /\ ~ \E m \in msgs : m.type = "Prepare" /\ m.sender = r
                          /\ m.view = view[r] /\ m.seq = s
    /\ msgs' = msgs \cup {[type |-> "Prepare", sender |-> r, view |-> view[r], seq |-> s, block |-> b]}
    /\ UNCHANGED <<view, log>>

(* An honest replica commits (broadcasts Commit) at most once per         *)
(* (view, seq), and only once it is itself prepared.                      *)
SendCommit(r, s, b) ==
    /\ r \in Honest
    /\ Prepared(view[r], s, b)
    /\ ~ \E m \in msgs : m.type = "Commit" /\ m.sender = r
                          /\ m.view = view[r] /\ m.seq = s
    /\ msgs' = msgs \cup {[type |-> "Commit", sender |-> r, view |-> view[r], seq |-> s, block |-> b]}
    /\ UNCHANGED <<view, log>>

(* An honest replica finalises (writes its log) once it is itself         *)
(* prepared AND has collected a full commit quorum -- AND (DEV-20 #2, no  *)
(* state transfer) only if it already committed the immediately prior     *)
(* sequence number.  A replica that never sees `s-1` committed can never  *)
(* validate `prev_hash` for `s` and so can never commit it -- this is     *)
(* the exact mechanism `test_equivocation_with_honest_votes_strands_one_  *)
(* honest_replica` demonstrates on one constructed run; DoCommit's guard  *)
(* lets TLC search for every reachable way to reach the same outcome.     *)
PrevCommitted(r, s) == IF s = 1 THEN TRUE ELSE log[r][s - 1] # NoBlock

DoCommit(r, s, b) ==
    /\ r \in Honest
    /\ log[r][s] = NoBlock
    /\ Prepared(view[r], s, b)
    /\ CommittedReady(view[r], s, b)
    /\ PrevCommitted(r, s)
    /\ log' = [log EXCEPT ![r][s] = b]
    /\ UNCHANGED <<view, msgs>>

(* Timeout-triggered view change (DEV-20): an honest replica advances its *)
(* own local view, and its ViewChange message HONESTLY reports whatever   *)
(* it itself already knows is prepared for `s` at its OLD view -- exactly *)
(* `view_change.py`'s "broadcasts a signed ViewChange carrying every       *)
(* prepared certificate it holds".  It cannot declare a block it has not  *)
(* actually seen a real prepared certificate for (it is honest), and it   *)
(* cannot declare a block it never saw at all if none was ever prepared   *)
(* for it -- NoBlock in that case, which is equally honest and is what    *)
(* closes the earlier draft's race (see the note on ViewChangeSenders     *)
(* above): a replica that has not yet witnessed a prepared certificate    *)
(* truthfully says so, rather than a global check retroactively deciding  *)
(* what it "should" have known.                                           *)
SendViewChange(r, s) ==
    /\ r \in Honest
    /\ view[r] < MaxView
    /\ LET newview == view[r] + 1
           declared == IF \E bb \in Blocks : Prepared(view[r], s, bb)
                         THEN CHOOSE bb \in Blocks : Prepared(view[r], s, bb)
                         ELSE NoBlock
       IN /\ ~ \E m \in msgs : m.type = "ViewChange" /\ m.sender = r
                                /\ m.view = newview /\ m.seq = s
          /\ msgs' = msgs \cup {[type |-> "ViewChange", sender |-> r, view |-> newview, seq |-> s, block |-> declared]}
    /\ view' = [view EXCEPT ![r] = view[r] + 1]
    /\ UNCHANGED log

(* A Byzantine replica may send any message that is well-formed under ITS *)
(* OWN identity: a different block for the same seq than it sent before   *)
(* (equivocation), a Prepare for a seq it never really saw pre-prepared,  *)
(* a Commit with no matching local Prepared state, a ViewChange declaring *)
(* any block (or none) regardless of what it actually holds -- anything   *)
(* the message FORMAT allows, per the task brief.  It may act as          *)
(* PrePrepare sender only in a view where it actually is the primary      *)
(* (Dolev-Yao: it cannot forge another replica's identity, including the  *)
(* current primary's).                                                    *)
ByzantineAction(r, s, b, v, mtype) ==
    /\ r \in Faulty
    /\ v \in Views
    /\ mtype \in {"PrePrepare", "Prepare", "Commit", "ViewChange"}
    /\ (mtype = "PrePrepare") => (r = Primary(v))
    /\ msgs' = msgs \cup {[type |-> mtype, sender |-> r, view |-> v, seq |-> s, block |-> b]}
    /\ UNCHANGED <<view, log>>

Next ==
    \/ \E r \in Honest, s \in Seqs, b \in Blocks : SendPrePrepare(r, s, b)
    \/ \E r \in Honest, s \in Seqs, b \in Blocks : SendPrepare(r, s, b)
    \/ \E r \in Honest, s \in Seqs, b \in Blocks : SendCommit(r, s, b)
    \/ \E r \in Honest, s \in Seqs, b \in Blocks : DoCommit(r, s, b)
    \/ \E r \in Honest, s \in Seqs : SendViewChange(r, s)
    \/ \E r \in Faulty, s \in Seqs, b \in Blocks, v \in Views, t \in {"PrePrepare", "Prepare", "Commit", "ViewChange"} :
          ByzantineAction(r, s, b, v, t)

(* Weak fairness on every HONEST action, parameterised -- the standard    *)
(* per-process fairness idiom.  Deliberately NO fairness on               *)
(* ByzantineAction: an adversary that is obliged to act "fairly" is not   *)
(* adversarial, and liveness that depended on the adversary's cooperation *)
(* would not be liveness at all.                                          *)
Fairness ==
    /\ \A r \in Honest, s \in Seqs, b \in Blocks : WF_vars(SendPrePrepare(r, s, b))
    /\ \A r \in Honest, s \in Seqs, b \in Blocks : WF_vars(SendPrepare(r, s, b))
    /\ \A r \in Honest, s \in Seqs, b \in Blocks : WF_vars(SendCommit(r, s, b))
    /\ \A r \in Honest, s \in Seqs, b \in Blocks : WF_vars(DoCommit(r, s, b))
    /\ \A r \in Honest, s \in Seqs : WF_vars(SendViewChange(r, s))

Spec == Init /\ [][Next]_vars /\ Fairness

-------------------------------------------------------------------------
(* Safety properties -- invariants, checked in every reachable state.     *)

(* Agreement: no two honest replicas commit different blocks at one seq.  *)
Agreement ==
    \A ra, rb \in Honest, s \in Seqs :
        (log[ra][s] # NoBlock /\ log[rb][s] # NoBlock) => (log[ra][s] = log[rb][s])

(* Validity: a committed block was proposed by some replica (a real       *)
(* PrePrepare message exists for it), never fabricated out of thin air.   *)
Validity ==
    \A r \in Honest, s \in Seqs :
        log[r][s] # NoBlock =>
            \E m \in msgs : m.type = "PrePrepare" /\ m.seq = s /\ m.block = log[r][s]

(* Integrity: an honest replica commits at most once per seq.  This holds *)
(* by construction of `log` (a single-value slot, written only from       *)
(* NoBlock, DoCommit's own guard) -- TypeOK plus DoCommit's guard are the  *)
(* full argument; there is no separate temporal formula to check, because *)
(* the state representation cannot express "committed twice" in the first *)
(* place.  Checked anyway, structurally, via TypeOK on every step.        *)

Safety == TypeOK /\ Agreement /\ Validity

-------------------------------------------------------------------------
(* Liveness -- temporal, checked under Fairness.  With N=4 and the        *)
(* design bound F=1, QuorumSize (2F+1=3) equals |Honest| exactly whenever  *)
(* |Faulty|=1 -- so at the paper's own configuration, ANY progress at a   *)
(* sequence number requires ALL THREE honest replicas to commit it. There *)
(* is no weaker quorum-of-some-honest-replicas fallback to check instead. *)

Termination == \A s \in Seqs : <>(\A r \in Honest : log[r][s] # NoBlock)
================================================================================

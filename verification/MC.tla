---------------------------- MODULE MC ----------------------------
(* Model-checking wrapper for pbft.tla (M7-18).  Concrete constant        *)
(* assignments live in the .cfg files below, not here -- MC.tla exists so *)
(* TLC has a module to point at and a place for run-specific overrides    *)
(* (e.g. the FLAW-5 run's ExpectAgreementViolation note).  Four .cfg      *)
(* files pair with this one module, one per run the M7-18 brief asks for: *)
(*                                                                         *)
(*   pbft.cfg           -- safety only,          F=1, |Faulty|=1, small bounds *)
(*   pbft_liveness.cfg  -- safety + liveness,     F=1, |Faulty|=1, larger bounds *)
(*   pbft_control_f0.cfg-- safety + liveness,     F=1, |Faulty|=0 (no-fault control) *)
(*   pbft_flaw5.cfg     -- safety only, EXPECTED TO FAIL -- F=1, |Faulty|=2 (FLAW-5) *)
(*                                                                         *)
(* All four instantiate the same four replicas and two block values;      *)
(* Replicas/RepSeq/Blocks/NoBlock never change between runs, only         *)
(* Faulty, MaxView and MaxSeq do (see verification/pbft_results.md).      *)

EXTENDS pbft, TLC

(* Block VALUES are interchangeable labels -- nothing in the spec orders  *)
(* or distinguishes them except equality -- so permuting them is a sound  *)
(* symmetry reduction. Replica identities are NOT made symmetric: Primary *)
(* rotation depends on RepSeq's order, so permuting replicas would change *)
(* which runs are even reachable. *)
BlocksSymmetry == Permutations(Blocks)

================================================================================

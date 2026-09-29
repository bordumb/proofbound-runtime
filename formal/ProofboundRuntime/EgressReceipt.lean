namespace ProofboundRuntime.EgressReceipt

inductive Reason where
  | requestDenied
  | sniDenied
  | limitReached
  | proxyFailed
  | cleanupIncomplete
  deriving DecidableEq, Repr

structure Flags where
  authorityRejection : Bool
  sniDenied : Bool
  limitReached : Bool
  proxyFailed : Bool
  cleanupIncomplete : Bool
  deriving DecidableEq, Repr

def orderedReasons (flags : Flags) : List Reason :=
  (if flags.authorityRejection then [.requestDenied] else []) ++
  (if flags.sniDenied then [.sniDenied] else []) ++
  (if flags.limitReached then [.limitReached] else []) ++
  (if flags.proxyFailed then [.proxyFailed] else []) ++
  (if flags.cleanupIncomplete then [.cleanupIncomplete] else [])

theorem orderedReasons_empty_iff (flags : Flags) :
    orderedReasons flags = [] ↔
      flags.authorityRejection = false ∧
      flags.sniDenied = false ∧
      flags.limitReached = false ∧
      flags.proxyFailed = false ∧
      flags.cleanupIncomplete = false := by
  cases flags with
  | mk authority sni limit proxy cleanup =>
    cases authority <;> cases sni <;> cases limit <;> cases proxy <;> cases cleanup <;>
      decide

theorem orderedReasons_nodup (flags : Flags) :
    (orderedReasons flags).Nodup := by
  cases flags with
  | mk authority sni limit proxy cleanup =>
    cases authority <;> cases sni <;> cases limit <;> cases proxy <;> cases cleanup <;>
      decide

end ProofboundRuntime.EgressReceipt

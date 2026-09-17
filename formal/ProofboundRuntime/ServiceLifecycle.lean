namespace ProofboundRuntime.ServiceLifecycle

inductive Phase where
  | created
  | resolving
  | connecting
  | authenticating
  | ready
  | active
  | closing
  | closed
  | failed
  deriving DecidableEq, Repr

inductive FailureReason where
  | resolution
  | endpoint
  | tls
  | connector
  | channel
  | limit
  | launcher
  | cleanup
  deriving DecidableEq, Repr

inductive Event where
  | beginResolution
  | resolutionComplete
  | endpointConnected
  | tlsAuthenticated
  | childReleased
  | beginClose
  | closeComplete
  | fail (reason : FailureReason)
  deriving DecidableEq, Repr

structure State where
  phase : Phase
  failure : Option FailureReason
  deriving DecidableEq, Repr

def initial : State := {
  phase := .created
  failure := none
}

def Nonterminal : Phase → Prop
  | .created => True
  | .resolving => True
  | .connecting => True
  | .authenticating => True
  | .ready => True
  | .active => True
  | .closing => True
  | .closed => False
  | .failed => False

def ForwardTransition (phase : Phase) (event : Event) (next : State) : Prop :=
  match phase, event with
  | .created, .beginResolution => ⟨.resolving, none⟩ = next
  | .resolving, .resolutionComplete => ⟨.connecting, none⟩ = next
  | .connecting, .endpointConnected => ⟨.authenticating, none⟩ = next
  | .authenticating, .tlsAuthenticated => ⟨.ready, none⟩ = next
  | .ready, .childReleased => ⟨.active, none⟩ = next
  | .active, .beginClose => ⟨.closing, none⟩ = next
  | .closing, .closeComplete => ⟨.closed, none⟩ = next
  | _, _ => False

def AllowedTransition (state : State) (event : Event) (next : State) : Prop :=
  match event with
  | .fail reason =>
      Nonterminal state.phase ∧ ⟨.failed, some reason⟩ = next
  | _ => ForwardTransition state.phase event next

def transition (state : State) (event : Event) : Except Unit State :=
  match state.phase, event with
  | .created, .beginResolution => .ok ⟨.resolving, none⟩
  | .resolving, .resolutionComplete => .ok ⟨.connecting, none⟩
  | .connecting, .endpointConnected => .ok ⟨.authenticating, none⟩
  | .authenticating, .tlsAuthenticated => .ok ⟨.ready, none⟩
  | .ready, .childReleased => .ok ⟨.active, none⟩
  | .active, .beginClose => .ok ⟨.closing, none⟩
  | .closing, .closeComplete => .ok ⟨.closed, none⟩
  | .created, .fail reason => .ok ⟨.failed, some reason⟩
  | .resolving, .fail reason => .ok ⟨.failed, some reason⟩
  | .connecting, .fail reason => .ok ⟨.failed, some reason⟩
  | .authenticating, .fail reason => .ok ⟨.failed, some reason⟩
  | .ready, .fail reason => .ok ⟨.failed, some reason⟩
  | .active, .fail reason => .ok ⟨.failed, some reason⟩
  | .closing, .fail reason => .ok ⟨.failed, some reason⟩
  | _, _ => .error ()

theorem transition_exact (state : State) (event : Event) (next : State) :
    transition state event = .ok next ↔ AllowedTransition state event next := by
  rcases state with ⟨phase, failure⟩
  cases phase <;> cases event <;>
    simp [transition, AllowedTransition, ForwardTransition, Nonterminal]

end ProofboundRuntime.ServiceLifecycle

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

inductive State where
  | created
  | resolving
  | connecting
  | authenticating
  | ready
  | active
  | closing
  | closed
  | failed (reason : FailureReason)
  deriving DecidableEq, Repr

def State.phase : State → Phase
  | .created => .created
  | .resolving => .resolving
  | .connecting => .connecting
  | .authenticating => .authenticating
  | .ready => .ready
  | .active => .active
  | .closing => .closing
  | .closed => .closed
  | .failed _ => .failed

def State.failure : State → Option FailureReason
  | .failed reason => some reason
  | _ => none

def initial : State := .created

def Nonterminal : State → Prop
  | .created => True
  | .resolving => True
  | .connecting => True
  | .authenticating => True
  | .ready => True
  | .active => True
  | .closing => True
  | .closed => False
  | .failed _ => False

def ForwardTransition (state : State) (event : Event) (next : State) : Prop :=
  match state, event with
  | .created, .beginResolution => State.resolving = next
  | .resolving, .resolutionComplete => State.connecting = next
  | .connecting, .endpointConnected => State.authenticating = next
  | .authenticating, .tlsAuthenticated => State.ready = next
  | .ready, .childReleased => State.active = next
  | .active, .beginClose => State.closing = next
  | .closing, .closeComplete => State.closed = next
  | _, _ => False

def AllowedTransition (state : State) (event : Event) (next : State) : Prop :=
  match event with
  | .fail reason =>
      Nonterminal state ∧ State.failed reason = next
  | _ => ForwardTransition state event next

def transition (state : State) (event : Event) : Except Unit State :=
  match state, event with
  | .created, .beginResolution => .ok .resolving
  | .resolving, .resolutionComplete => .ok .connecting
  | .connecting, .endpointConnected => .ok .authenticating
  | .authenticating, .tlsAuthenticated => .ok .ready
  | .ready, .childReleased => .ok .active
  | .active, .beginClose => .ok .closing
  | .closing, .closeComplete => .ok .closed
  | .created, .fail reason => .ok (.failed reason)
  | .resolving, .fail reason => .ok (.failed reason)
  | .connecting, .fail reason => .ok (.failed reason)
  | .authenticating, .fail reason => .ok (.failed reason)
  | .ready, .fail reason => .ok (.failed reason)
  | .active, .fail reason => .ok (.failed reason)
  | .closing, .fail reason => .ok (.failed reason)
  | _, _ => .error ()

theorem transition_exact (state : State) (event : Event) (next : State) :
    transition state event = .ok next ↔ AllowedTransition state event next := by
  cases state <;> cases event <;>
    simp [transition, AllowedTransition, ForwardTransition, Nonterminal]

end ProofboundRuntime.ServiceLifecycle

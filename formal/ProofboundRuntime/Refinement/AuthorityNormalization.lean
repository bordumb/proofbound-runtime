import ProofboundRuntime.Refinement.Authority

open Aeneas Aeneas.Std Result ControlFlow Error

namespace ProofboundRuntime.Refinement.AuthorityNormalization

open ProofboundRuntime.Refinement.Authority
open proofbound_runtime_core

def EnvironmentSame
    (left right : authority.EnvironmentName) : Prop :=
  StringBytes left = StringBytes right

def EnvironmentNoneBetween
    (items : Slice authority.EnvironmentName)
    (candidate : Nat) (start stop : Nat) : Prop :=
  ∀ index, start ≤ index → index < stop →
    ¬EnvironmentSame items.val[index]! items.val[candidate]!

def EnvironmentPresentBetween
    (items : Slice authority.EnvironmentName)
    (candidate : Nat) (start stop : Nat) : Prop :=
  ∃ index, start ≤ index ∧ index < stop ∧
    EnvironmentSame items.val[index]! items.val[candidate]!

@[step]
theorem environment_prefix_contains_loop_spec
    (items : Slice authority.EnvironmentName)
    (endIndex candidate start : Usize)
    (hStart : start.val ≤ endIndex.val)
    (hEnd : endIndex.val ≤ items.length)
    (hCandidate : candidate.val < items.length)
    (hBounded : EnvironmentStringsBounded items.val) :
    normalize.environment_prefix_contains_loop items endIndex candidate start
      ⦃ found => found = true ↔
        EnvironmentPresentBetween items candidate.val start.val endIndex.val ⦄ := by
  unfold normalize.environment_prefix_contains_loop
  apply loop.spec_decr_nat
    (fun index => endIndex.val - index.val)
    (fun index =>
      start.val ≤ index.val ∧ index.val ≤ endIndex.val ∧
      EnvironmentNoneBetween items candidate.val start.val index.val)
    (fun found => found = true ↔
      EnvironmentPresentBetween items candidate.val start.val endIndex.val)
  · intro index hIndex
    rcases hIndex with ⟨hStartIndex, hIndexEnd, hNone⟩
    unfold normalize.environment_prefix_contains_loop.body
    split
    · rename_i hLess
      have hIndexLess : index.val < endIndex.val := by simpa using hLess
      have hIndexBound : index.val < items.length := by
        omega
      step
      step
      have hIndexValue := hBounded en (by
        rw [en_post]
        exact List.getElem_mem hIndexBound)
      have hCandidateValue := hBounded en1 (by
        rw [en1_post]
        exact List.getElem_mem hCandidate)
      step
      split
      · rename_i hFound
        simp only [WP.spec_ok]
        constructor
        · intro _
          refine ⟨index.val, hStartIndex, ?_, ?_⟩
          · simpa using hLess
          · have hSame := b_post.mp hFound
            simpa [EnvironmentSame, en_post, en1_post,
              hIndexBound, hCandidate] using hSame
        · intro _
          trivial
      · rename_i hNotFound
        step
        refine ⟨?_, ?_, ?_, ?_⟩
        · rw [index1_post]
          omega
        · rw [index1_post]
          omega
        · intro checked hCheckedStart hCheckedNext
          by_cases hChecked : checked < index.val
          · exact hNone checked hCheckedStart hChecked
          · have hCheckedEq : checked = index.val := by
              rw [index1_post] at hCheckedNext
              omega
            subst checked
            have hDifferent :
                ¬EnvironmentSame items.val[index.val]!
                  items.val[candidate.val]! := by
              intro hSame
              apply hNotFound
              apply b_post.mpr
              simpa [EnvironmentSame, en_post, en1_post,
                hIndexBound, hCandidate] using hSame
            exact hDifferent
        · rw [index1_post]
          omega
    · rename_i hDone
      simp only [WP.spec_ok]
      have hIndexEq : index.val = endIndex.val := by
        have : ¬index.val < endIndex.val := by simpa using hDone
        omega
      constructor
      · intro hFalse
        simp at hFalse
      · rintro ⟨found, hFoundStart, hFoundEnd, hSame⟩
        exact ((hNone found hFoundStart (by omega)) hSame).elim
  · exact ⟨Nat.le_refl _, hStart, by
      intro index hIndexStart hIndexStop
      omega⟩

@[step]
theorem environment_prefix_contains_spec
    (items : Slice authority.EnvironmentName)
    (endIndex candidate : Usize)
    (hEnd : endIndex.val ≤ items.length)
    (hCandidate : candidate.val < items.length)
    (hBounded : EnvironmentStringsBounded items.val) :
    normalize.environment_prefix_contains items endIndex candidate
      ⦃ found => found = true ↔
        EnvironmentPresentBetween items candidate.val 0 endIndex.val ⦄ := by
  unfold normalize.environment_prefix_contains
  apply environment_prefix_contains_loop_spec
  · simp
  · exact hEnd
  · exact hCandidate
  · exact hBounded

def PathStringsBounded
    (items : List authority.PathAuthority) : Prop :=
  ∀ item, item ∈ items → item.path.toByteArray.size ≤ U32.max

instance : Inhabited authority.PathAuthority where
  default := {
    path := ""
    access := .Read
    role := .ProjectInput
  }

def PathSame
    (left right : authority.PathAuthority) : Prop :=
  PathAuthoritySameValue left right

def PathNoneBetween
    (items : Slice authority.PathAuthority)
    (candidate : Nat) (start stop : Nat) : Prop :=
  ∀ index, start ≤ index → index < stop →
    ¬PathSame items.val[index]! items.val[candidate]!

def PathPresentBetween
    (items : Slice authority.PathAuthority)
    (candidate : Nat) (start stop : Nat) : Prop :=
  ∃ index, start ≤ index ∧ index < stop ∧
    PathSame items.val[index]! items.val[candidate]!

@[step]
theorem path_prefix_contains_loop_spec
    (items : Slice authority.PathAuthority)
    (endIndex candidate start : Usize)
    (hStart : start.val ≤ endIndex.val)
    (hEnd : endIndex.val ≤ items.length)
    (hCandidate : candidate.val < items.length)
    (hBounded : PathStringsBounded items.val) :
    normalize.path_prefix_contains_loop items endIndex candidate start
      ⦃ found => found = true ↔
        PathPresentBetween items candidate.val start.val endIndex.val ⦄ := by
  unfold normalize.path_prefix_contains_loop
  apply loop.spec_decr_nat
    (fun index => endIndex.val - index.val)
    (fun index =>
      start.val ≤ index.val ∧ index.val ≤ endIndex.val ∧
      PathNoneBetween items candidate.val start.val index.val)
    (fun found => found = true ↔
      PathPresentBetween items candidate.val start.val endIndex.val)
  · intro index hIndex
    rcases hIndex with ⟨hStartIndex, hIndexEnd, hNone⟩
    unfold normalize.path_prefix_contains_loop.body
    split
    · rename_i hLess
      have hIndexLess : index.val < endIndex.val := by simpa using hLess
      have hIndexBound : index.val < items.length := by omega
      step
      step
      have hIndexValue := hBounded pa (by
        rw [pa_post]
        exact List.getElem_mem hIndexBound)
      have hCandidateValue := hBounded pa1 (by
        rw [pa1_post]
        exact List.getElem_mem hCandidate)
      step
      split
      · rename_i hFound
        simp only [WP.spec_ok]
        constructor
        · intro _
          refine ⟨index.val, hStartIndex, ?_, ?_⟩
          · simpa using hLess
          · have hSame := b_post.mp hFound
            simpa [PathSame, pa_post, pa1_post,
              hIndexBound, hCandidate] using hSame
        · intro _
          trivial
      · rename_i hNotFound
        step
        refine ⟨?_, ?_, ?_, ?_⟩
        · rw [index1_post]
          omega
        · rw [index1_post]
          omega
        · intro checked hCheckedStart hCheckedNext
          by_cases hChecked : checked < index.val
          · exact hNone checked hCheckedStart hChecked
          · have hCheckedEq : checked = index.val := by
              rw [index1_post] at hCheckedNext
              omega
            subst checked
            intro hSame
            apply hNotFound
            apply b_post.mpr
            simpa [PathSame, pa_post, pa1_post,
              hIndexBound, hCandidate] using hSame
        · rw [index1_post]
          omega
    · rename_i hDone
      simp only [WP.spec_ok]
      have hIndexEq : index.val = endIndex.val := by
        have : ¬index.val < endIndex.val := by simpa using hDone
        omega
      constructor
      · intro hFalse
        simp at hFalse
      · rintro ⟨found, hFoundStart, hFoundEnd, hSame⟩
        exact ((hNone found hFoundStart (by omega)) hSame).elim
  · exact ⟨Nat.le_refl _, hStart, by
      intro index hIndexStart hIndexStop
      omega⟩

@[step]
theorem path_prefix_contains_spec
    (items : Slice authority.PathAuthority)
    (endIndex candidate : Usize)
    (hEnd : endIndex.val ≤ items.length)
    (hCandidate : candidate.val < items.length)
    (hBounded : PathStringsBounded items.val) :
    normalize.path_prefix_contains items endIndex candidate
      ⦃ found => found = true ↔
        PathPresentBetween items candidate.val 0 endIndex.val ⦄ := by
  unfold normalize.path_prefix_contains
  apply path_prefix_contains_loop_spec
  · simp
  · exact hEnd
  · exact hCandidate
  · exact hBounded

theorem take_swap_prefix_succ
    {T : Type} (values : List T) (write read : Nat)
    (hWriteRead : write ≤ read) (hRead : read < values.length) :
    (values.swap write read).take (write + 1) =
      values.take write ++ [values[read]] := by
  apply List.ext_getElem
  · simp only [List.length_take, List.length_swap, List.length_append,
      List.length_singleton]
    rw [Nat.min_eq_left (by omega), Nat.min_eq_left (by omega)]
  · intro index hLeft hRight
    have hWrite : write < values.length := by omega
    have hIndex : index < write + 1 := by
      rw [List.length_take, List.length_swap,
        Nat.min_eq_left (by omega)] at hLeft
      exact hLeft
    by_cases hIndexWrite : index = write
    · subst index
      rw [List.getElem_take, List.getElem_swap_left]
      simp [hRead, List.length_take,
        Nat.min_eq_left (Nat.le_of_lt hWrite)]
    · have hIndexBefore : index < write := by omega
      have hIndexRead : index ≠ read := by omega
      rw [List.getElem_take,
        List.getElem_swap_of_ne hIndexWrite hIndexRead]
      have hTakeIndex : index < (values.take write).length := by
        simp [List.length_take, Nat.min_eq_left (Nat.le_of_lt hWrite),
          hIndexBefore]
      rw [List.getElem_append_left hTakeIndex]
      rw [List.getElem_take]

def EnvironmentDistinctPrefix
    (items : List authority.EnvironmentName) (count : Nat) : Prop :=
  (items.take count).Pairwise (fun left right => ¬EnvironmentSame left right)

theorem environment_distinct_prefix_after_swap
    (items : List authority.EnvironmentName) (write read : Nat)
    (hWriteRead : write ≤ read) (hRead : read < items.length)
    (hDistinct : EnvironmentDistinctPrefix items write)
    (hAbsent : ∀ index, index < write →
      ¬EnvironmentSame items[index]! items[read]!) :
    EnvironmentDistinctPrefix (items.swap write read) (write + 1) := by
  unfold EnvironmentDistinctPrefix at hDistinct ⊢
  rw [take_swap_prefix_succ items write read hWriteRead hRead]
  apply List.pairwise_append.mpr
  refine ⟨hDistinct, List.pairwise_singleton _ _, ?_⟩
  intro item hItem candidate hCandidate
  simp only [List.mem_singleton] at hCandidate
  subst candidate
  rw [List.mem_take_iff_getElem] at hItem
  rcases hItem with ⟨index, hIndex, hItem⟩
  subst item
  have hIndexWrite : index < write := by omega
  have hResult := hAbsent index hIndexWrite
  rw [← List.Inhabited_getElem_eq_getElem! items index (by omega),
    ← List.Inhabited_getElem_eq_getElem! items read hRead] at hResult
  simpa [List.getElem_take] using hResult

def PathDistinctPrefix
    (items : List authority.PathAuthority) (count : Nat) : Prop :=
  (items.take count).Pairwise (fun left right => ¬PathSame left right)

theorem path_distinct_prefix_after_swap
    (items : List authority.PathAuthority) (write read : Nat)
    (hWriteRead : write ≤ read) (hRead : read < items.length)
    (hDistinct : PathDistinctPrefix items write)
    (hAbsent : ∀ index, index < write →
      ¬PathSame items[index]! items[read]!) :
    PathDistinctPrefix (items.swap write read) (write + 1) := by
  unfold PathDistinctPrefix at hDistinct ⊢
  rw [take_swap_prefix_succ items write read hWriteRead hRead]
  apply List.pairwise_append.mpr
  refine ⟨hDistinct, List.pairwise_singleton _ _, ?_⟩
  intro item hItem candidate hCandidate
  simp only [List.mem_singleton] at hCandidate
  subst candidate
  rw [List.mem_take_iff_getElem] at hItem
  rcases hItem with ⟨index, hIndex, hItem⟩
  subst item
  have hIndexWrite : index < write := by omega
  have hResult := hAbsent index hIndexWrite
  rw [← List.Inhabited_getElem_eq_getElem! items index (by omega),
    ← List.Inhabited_getElem_eq_getElem! items read hRead] at hResult
  simpa [List.getElem_take] using hResult

@[step]
theorem deduplicate_environment_loop_spec
    (items : alloc.vec.Vec authority.EnvironmentName)
    (iter : core.ops.range.Range Usize) (write : Usize)
    (hWriteStart : write.val ≤ iter.start.val)
    (hStartEnd : iter.start.val ≤ iter.end.val)
    (hEnd : iter.end.val = items.val.length)
    (hBounded : EnvironmentStringsBounded items.val)
    (hDistinct : EnvironmentDistinctPrefix items.val write.val) :
    normalize.deduplicate_environment_loop iter items write
      ⦃ out => out.1.val.Perm items.val ∧
        EnvironmentStringsBounded out.1.val ∧
        out.2.val ≤ out.1.val.length ∧
        EnvironmentDistinctPrefix out.1.val out.2.val ⦄ := by
  unfold normalize.deduplicate_environment_loop
  apply loop.spec_decr_nat
    (fun state : core.ops.range.Range Usize ×
        alloc.vec.Vec authority.EnvironmentName × Usize =>
      state.1.end.val - state.1.start.val)
    (fun state : core.ops.range.Range Usize ×
        alloc.vec.Vec authority.EnvironmentName × Usize =>
      state.2.1.val.Perm items.val ∧
      EnvironmentStringsBounded state.2.1.val ∧
      state.2.2.val ≤ state.1.start.val ∧
      state.1.start.val ≤ state.1.end.val ∧
      state.1.end.val = state.2.1.val.length ∧
      EnvironmentDistinctPrefix state.2.1.val state.2.2.val)
    (fun out : alloc.vec.Vec authority.EnvironmentName × Usize =>
      out.1.val.Perm items.val ∧
      EnvironmentStringsBounded out.1.val ∧
      out.2.val ≤ out.1.val.length ∧
      EnvironmentDistinctPrefix out.1.val out.2.val)
  · rintro ⟨currentIter, currentItems, currentWrite⟩
      ⟨hPerm, hCurrentBounded, hCurrentWrite, hCurrentRange,
        hCurrentEnd, hCurrentDistinct⟩
    simp only at hPerm hCurrentBounded hCurrentWrite hCurrentRange hCurrentEnd hCurrentDistinct ⊢
    unfold normalize.deduplicate_environment_loop.body
    step
    cases o with
    | none =>
        simp only [WP.spec_ok]
        exact ⟨hPerm, hCurrentBounded, by omega, hCurrentDistinct⟩
    | some read =>
        have hLess : currentIter.start.val < currentIter.end.val := by
          by_contra hNotLess
          simp [hNotLess] at o_post
        simp [hLess] at o_post
        rcases o_post with ⟨hReadEq, hNextStart⟩
        have hNextEnd : iter1.end.val = currentIter.end.val := by
          simpa using congrArg UScalar.val o_post1
        have hRead : read.val < currentItems.val.length := by
          rw [hReadEq, ← hCurrentEnd]
          exact hLess
        have hWriteEnd : currentWrite.val ≤ currentItems.val.length := by
          omega
        step with environment_prefix_contains_spec by
          simp_all [alloc.vec.Vec.deref, alloc.vec.Vec.val]
        split
        · rename_i hFound
          simp only [WP.spec_ok]
          refine ⟨hPerm, hCurrentBounded, ?_, ?_, ?_, ?_, ?_⟩
          · omega
          · omega
          · rw [hNextEnd, hCurrentEnd]
          · exact hCurrentDistinct
          · omega
        · rename_i hNotFound
          have hAbsent : ∀ index, index < currentWrite.val →
              ¬EnvironmentSame currentItems.val[index]!
                currentItems.val[read.val]! := by
            intro index hIndex hSame
            apply hNotFound
            apply r_post.mpr
            exact ⟨index, Nat.zero_le _, hIndex, by
              simpa [alloc.vec.Vec.deref, alloc.vec.Vec.val] using hSame⟩
          split
          · rename_i hSwap
            simp only [alloc.vec.Vec.deref_mut, lift]
            have hWriteBound : currentWrite.val < currentItems.slice.length := by
              simpa [alloc.vec.Vec.val] using
                (show currentWrite.val < currentItems.val.length by omega)
            have hReadBound : read.val < currentItems.slice.length := by
              simpa [alloc.vec.Vec.val] using hRead
            step with slice_swap_eq_list_swap as ⟨s2, s2_post⟩
            have hChanged :
                ({ slice := s2 } : alloc.vec.Vec authority.EnvironmentName).val =
                  currentItems.val.swap currentWrite.val read.val := by
              simpa [alloc.vec.Vec.val] using s2_post
            have hChangedPerm :
                ({ slice := s2 } : alloc.vec.Vec authority.EnvironmentName).val.Perm
                  currentItems.val := by
              rw [hChanged]
              exact List.swap_perm _ _ _
            have hWriteCapacity : currentWrite.val < Usize.max :=
              (show currentWrite.val < currentItems.val.length by omega).trans_le
                currentItems.property
            step as ⟨write1, write1_post⟩
            refine ⟨hChangedPerm.trans hPerm, ?_, ?_, ?_, ?_, ?_, ?_⟩
            · intro item hItem
              apply hCurrentBounded item
              exact hChangedPerm.mem_iff.mp hItem
            · rw [write1_post]
              omega
            · omega
            · rw [hNextEnd, hCurrentEnd]
              exact hChangedPerm.length_eq.symm
            · rw [write1_post, hChanged]
              apply environment_distinct_prefix_after_swap
              · rw [hReadEq]
                exact hCurrentWrite
              · exact hRead
              · exact hCurrentDistinct
              · exact hAbsent
            · omega
          · rename_i hNotSwap
            have hWriteRead : currentWrite.val = read.val := by
              simpa using hNotSwap
            step as ⟨write1, write1_post⟩
            refine ⟨hPerm, hCurrentBounded, ?_, ?_, ?_, ?_, ?_⟩
            · rw [write1_post]
              omega
            · omega
            · rw [hNextEnd, hCurrentEnd]
            · unfold EnvironmentDistinctPrefix at hCurrentDistinct ⊢
              rw [hWriteRead] at hCurrentDistinct
              rw [write1_post, hWriteRead]
              rw [← List.take_append_getElem hRead]
              apply List.pairwise_append.mpr
              refine ⟨hCurrentDistinct, List.pairwise_singleton _ _, ?_⟩
              intro item hItem candidate hCandidate
              simp only [List.mem_singleton] at hCandidate
              subst candidate
              rw [List.mem_take_iff_getElem] at hItem
              rcases hItem with ⟨index, hIndex, hItem⟩
              subst item
              have hIndexWrite : index < currentWrite.val := by omega
              have hResult := hAbsent index hIndexWrite
              rw [← List.Inhabited_getElem_eq_getElem! currentItems.val index
                  (by omega),
                ← List.Inhabited_getElem_eq_getElem! currentItems.val read.val hRead]
                at hResult
              simpa [List.getElem_take] using hResult
            · omega
  · exact ⟨List.Perm.refl _, hBounded, hWriteStart, hStartEnd,
      hEnd, hDistinct⟩

@[step]
theorem deduplicate_paths_loop_spec
    (items : alloc.vec.Vec authority.PathAuthority)
    (iter : core.ops.range.Range Usize) (write : Usize)
    (hWriteStart : write.val ≤ iter.start.val)
    (hStartEnd : iter.start.val ≤ iter.end.val)
    (hEnd : iter.end.val = items.val.length)
    (hBounded : PathStringsBounded items.val)
    (hDistinct : PathDistinctPrefix items.val write.val) :
    normalize.deduplicate_paths_loop iter items write
      ⦃ out => out.1.val.Perm items.val ∧
        PathStringsBounded out.1.val ∧
        out.2.val ≤ out.1.val.length ∧
        PathDistinctPrefix out.1.val out.2.val ⦄ := by
  unfold normalize.deduplicate_paths_loop
  apply loop.spec_decr_nat
    (fun state : core.ops.range.Range Usize ×
        alloc.vec.Vec authority.PathAuthority × Usize =>
      state.1.end.val - state.1.start.val)
    (fun state : core.ops.range.Range Usize ×
        alloc.vec.Vec authority.PathAuthority × Usize =>
      state.2.1.val.Perm items.val ∧
      PathStringsBounded state.2.1.val ∧
      state.2.2.val ≤ state.1.start.val ∧
      state.1.start.val ≤ state.1.end.val ∧
      state.1.end.val = state.2.1.val.length ∧
      PathDistinctPrefix state.2.1.val state.2.2.val)
    (fun out : alloc.vec.Vec authority.PathAuthority × Usize =>
      out.1.val.Perm items.val ∧
      PathStringsBounded out.1.val ∧
      out.2.val ≤ out.1.val.length ∧
      PathDistinctPrefix out.1.val out.2.val)
  · rintro ⟨currentIter, currentItems, currentWrite⟩
      ⟨hPerm, hCurrentBounded, hCurrentWrite, hCurrentRange,
        hCurrentEnd, hCurrentDistinct⟩
    simp only at hPerm hCurrentBounded hCurrentWrite hCurrentRange hCurrentEnd hCurrentDistinct ⊢
    unfold normalize.deduplicate_paths_loop.body
    step
    cases o with
    | none =>
        simp only [WP.spec_ok]
        exact ⟨hPerm, hCurrentBounded, by omega, hCurrentDistinct⟩
    | some read =>
        have hLess : currentIter.start.val < currentIter.end.val := by
          by_contra hNotLess
          simp [hNotLess] at o_post
        simp [hLess] at o_post
        rcases o_post with ⟨hReadEq, hNextStart⟩
        have hNextEnd : iter1.end.val = currentIter.end.val := by
          simpa using congrArg UScalar.val o_post1
        have hRead : read.val < currentItems.val.length := by
          rw [hReadEq, ← hCurrentEnd]
          exact hLess
        have hWriteEnd : currentWrite.val ≤ currentItems.val.length := by
          omega
        step with path_prefix_contains_spec by
          simp_all [alloc.vec.Vec.deref, alloc.vec.Vec.val]
        split
        · rename_i hFound
          simp only [WP.spec_ok]
          refine ⟨hPerm, hCurrentBounded, ?_, ?_, ?_, ?_, ?_⟩
          · omega
          · omega
          · rw [hNextEnd, hCurrentEnd]
          · exact hCurrentDistinct
          · omega
        · rename_i hNotFound
          have hAbsent : ∀ index, index < currentWrite.val →
              ¬PathSame currentItems.val[index]!
                currentItems.val[read.val]! := by
            intro index hIndex hSame
            apply hNotFound
            apply r_post.mpr
            exact ⟨index, Nat.zero_le _, hIndex, by
              simpa [alloc.vec.Vec.deref, alloc.vec.Vec.val] using hSame⟩
          split
          · rename_i hSwap
            simp only [alloc.vec.Vec.deref_mut, lift]
            have hWriteBound : currentWrite.val < currentItems.slice.length := by
              simpa [alloc.vec.Vec.val] using
                (show currentWrite.val < currentItems.val.length by omega)
            have hReadBound : read.val < currentItems.slice.length := by
              simpa [alloc.vec.Vec.val] using hRead
            step with slice_swap_eq_list_swap as ⟨s2, s2_post⟩
            have hChanged :
                ({ slice := s2 } : alloc.vec.Vec authority.PathAuthority).val =
                  currentItems.val.swap currentWrite.val read.val := by
              simpa [alloc.vec.Vec.val] using s2_post
            have hChangedPerm :
                ({ slice := s2 } : alloc.vec.Vec authority.PathAuthority).val.Perm
                  currentItems.val := by
              rw [hChanged]
              exact List.swap_perm _ _ _
            have hWriteCapacity : currentWrite.val < Usize.max :=
              (show currentWrite.val < currentItems.val.length by omega).trans_le
                currentItems.property
            step as ⟨write1, write1_post⟩
            refine ⟨hChangedPerm.trans hPerm, ?_, ?_, ?_, ?_, ?_, ?_⟩
            · intro item hItem
              apply hCurrentBounded item
              exact hChangedPerm.mem_iff.mp hItem
            · rw [write1_post]
              omega
            · omega
            · rw [hNextEnd, hCurrentEnd]
              exact hChangedPerm.length_eq.symm
            · rw [write1_post, hChanged]
              apply path_distinct_prefix_after_swap
              · rw [hReadEq]
                exact hCurrentWrite
              · exact hRead
              · exact hCurrentDistinct
              · exact hAbsent
            · omega
          · rename_i hNotSwap
            have hWriteRead : currentWrite.val = read.val := by
              simpa using hNotSwap
            step as ⟨write1, write1_post⟩
            refine ⟨hPerm, hCurrentBounded, ?_, ?_, ?_, ?_, ?_⟩
            · rw [write1_post]
              omega
            · omega
            · rw [hNextEnd, hCurrentEnd]
            · unfold PathDistinctPrefix at hCurrentDistinct ⊢
              rw [hWriteRead] at hCurrentDistinct
              rw [write1_post, hWriteRead]
              rw [← List.take_append_getElem hRead]
              apply List.pairwise_append.mpr
              refine ⟨hCurrentDistinct, List.pairwise_singleton _ _, ?_⟩
              intro item hItem candidate hCandidate
              simp only [List.mem_singleton] at hCandidate
              subst candidate
              rw [List.mem_take_iff_getElem] at hItem
              rcases hItem with ⟨index, hIndex, hItem⟩
              subst item
              have hIndexWrite : index < currentWrite.val := by omega
              have hResult := hAbsent index hIndexWrite
              rw [← List.Inhabited_getElem_eq_getElem! currentItems.val index
                  (by omega),
                ← List.Inhabited_getElem_eq_getElem! currentItems.val read.val hRead]
                at hResult
              simpa [List.getElem_take] using hResult
            · omega
  · exact ⟨List.Perm.refl _, hBounded, hWriteStart, hStartEnd,
      hEnd, hDistinct⟩

def ListSubset {T : Type} (left right : List T) : Prop :=
  ∀ item, item ∈ left → item ∈ right

@[step]
theorem deduplicate_environment_spec
    (items : alloc.vec.Vec authority.EnvironmentName)
    (hBounded : EnvironmentStringsBounded items.val) :
    normalize.deduplicate_environment items
      ⦃ out => out.val.Nodup ∧ ListSubset out.val items.val ∧
        EnvironmentStringsBounded out.val ⦄ := by
  unfold normalize.deduplicate_environment
  step with deduplicate_environment_loop_spec as
    ⟨items1, write, items1_post, items1_post1, items1_post2, items1_post3⟩ by
    simp_all [EnvironmentDistinctPrefix]
  step as ⟨out, out_post⟩
  rw [out_post]
  refine ⟨?_, ?_, ?_⟩
  · apply List.nodup_iff_pairwise_ne.mpr
    apply items1_post3.imp
    intro left right hDifferent hEqual
    apply hDifferent
    subst right
    rfl
  · intro item hItem
    apply items1_post.mem_iff.mp
    exact List.mem_of_mem_take hItem
  · intro item hItem
    apply hBounded item
    apply items1_post.mem_iff.mp
    exact List.mem_of_mem_take hItem

@[step]
theorem deduplicate_paths_spec
    (items : alloc.vec.Vec authority.PathAuthority)
    (hBounded : PathStringsBounded items.val) :
    normalize.deduplicate_paths items
      ⦃ out => out.val.Nodup ∧ ListSubset out.val items.val ∧
        PathStringsBounded out.val ⦄ := by
  unfold normalize.deduplicate_paths
  step with deduplicate_paths_loop_spec as
    ⟨items1, write, items1_post, items1_post1, items1_post2, items1_post3⟩ by
    simp_all [PathDistinctPrefix]
  step as ⟨out, out_post⟩
  rw [out_post]
  refine ⟨?_, ?_, ?_⟩
  · apply List.nodup_iff_pairwise_ne.mpr
    apply items1_post3.imp
    intro left right hDifferent hEqual
    apply hDifferent
    subst right
    simp [PathSame, PathAuthoritySameValue]
  · intro item hItem
    apply items1_post.mem_iff.mp
    exact List.mem_of_mem_take hItem
  · intro item hItem
    apply hBounded item
    apply items1_post.mem_iff.mp
    exact List.mem_of_mem_take hItem

theorem path_authority_comes_before_terminates
    (self other : authority.PathAuthority)
    (hSelf : self.path.toByteArray.size ≤ U32.max)
    (hOther : other.path.toByteArray.size ≤ U32.max) :
    authority.PathAuthority.comes_before self other ⦃ _ => True ⦄ := by
  apply Aeneas.Std.WP.spec_mono
    (path_authority_comes_before_spec self other hSelf hOther)
  simp

@[step]
theorem sort_path_inner_perm
    (items : alloc.vec.Vec authority.PathAuthority)
    (cursor : Usize)
    (hCursor : cursor.val < items.val.length)
    (hBounded : PathStringsBounded items.val) :
    normalize.sort_and_deduplicate_paths_loop0_loop0 items cursor
      ⦃ out => out.val.Perm items.val ⦄ := by
  unfold normalize.sort_and_deduplicate_paths_loop0_loop0
  apply loop.spec_decr_nat
    (fun state : alloc.vec.Vec authority.PathAuthority × Usize =>
      state.2.val)
    (fun state : alloc.vec.Vec authority.PathAuthority × Usize =>
      state.1.val.Perm items.val ∧
      state.2.val < state.1.val.length ∧
      PathStringsBounded state.1.val)
    (fun out : alloc.vec.Vec authority.PathAuthority =>
      out.val.Perm items.val)
  · rintro ⟨currentItems, currentCursor⟩
      ⟨hPerm, hCurrentCursor, hCurrentBounded⟩
    simp only at hPerm hCurrentCursor hCurrentBounded ⊢
    unfold normalize.sort_and_deduplicate_paths_loop0_loop0.body
    simp only
    split
    · rename_i hPositive
      have hPrevious : currentCursor.val - 1 < currentItems.val.length := by
        omega
      step
      step
      have hCurrentValue := hCurrentBounded pa (by
        rw [pa_post]
        exact List.getElem_mem hCurrentCursor)
      step
      have hIndex : i.val < currentItems.val.length := by
        simpa [i_post] using hPrevious
      have hPreviousValue := hCurrentBounded pa1 (by
        rw [pa1_post]
        exact List.getElem_mem hIndex)
      step
      split
      · simp only [alloc.vec.Vec.deref_mut, lift]
        have hCursorSlice : currentCursor.val < currentItems.slice.length := by
          simpa [alloc.vec.Vec.val] using hCurrentCursor
        have hIndexSlice : i.val < currentItems.slice.length := by
          simpa [alloc.vec.Vec.val] using hIndex
        step
        have hBackPerm :
            ({ slice := s } : alloc.vec.Vec authority.PathAuthority).val.Perm
              currentItems.val := by
          simpa [alloc.vec.Vec.val] using deref_mut_back
        refine ⟨hBackPerm.trans hPerm, ?_, ?_, ?_⟩
        · simpa [hBackPerm.length_eq] using hIndex
        · intro item hItem
          apply hCurrentBounded item
          exact hBackPerm.mem_iff.mp hItem
        · rw [i_post]
          omega
      · exact hPerm
    · exact hPerm
  · exact ⟨List.Perm.refl _, hCursor, hBounded⟩

theorem sort_path_loop_perm_any
    (items : alloc.vec.Vec authority.PathAuthority)
    (iter : core.ops.range.Range Usize)
    (hEnd : iter.end.val = items.val.length)
    (hBounded : PathStringsBounded items.val) :
    normalize.sort_and_deduplicate_paths_loop0 iter items
      ⦃ out => out.val.Perm items.val ⦄ := by
  unfold normalize.sort_and_deduplicate_paths_loop0
  apply loop.spec_decr_nat
    (fun state : core.ops.range.Range Usize ×
        alloc.vec.Vec authority.PathAuthority =>
      state.1.end.val - state.1.start.val)
    (fun state : core.ops.range.Range Usize ×
        alloc.vec.Vec authority.PathAuthority =>
      state.2.val.Perm items.val ∧
      PathStringsBounded state.2.val ∧
      state.1.end.val = state.2.val.length)
    (fun out : alloc.vec.Vec authority.PathAuthority =>
      out.val.Perm items.val)
  · rintro ⟨currentIter, currentItems⟩
      ⟨hPerm, hCurrentBounded, hCurrentEnd⟩
    simp only at hPerm hCurrentBounded hCurrentEnd ⊢
    unfold normalize.sort_and_deduplicate_paths_loop0.body
    step
    cases o with
    | none =>
        exact hPerm
    | some index =>
        have hLess : currentIter.start.val < currentIter.end.val := by
          by_contra hNotLess
          simp [hNotLess] at o_post
        simp [hLess] at o_post
        rcases o_post with ⟨hIndexEq, hNextStart⟩
        have hNextEnd : iter1.end.val = currentIter.end.val := by
          simpa using congrArg UScalar.val o_post1
        have hIndex : index.val < currentItems.val.length := by
          rw [hIndexEq, ← hCurrentEnd]
          exact hLess
        step
        refine ⟨r_post.trans hPerm, ?_, ?_, ?_⟩
        · intro item hItem
          apply hCurrentBounded item
          exact r_post.mem_iff.mp hItem
        · rw [hNextEnd, hCurrentEnd]
          exact r_post.length_eq.symm
        · omega
  · exact ⟨List.Perm.refl _, hBounded, hEnd⟩

@[step]
theorem sort_and_deduplicate_paths_spec
    (items : alloc.vec.Vec authority.PathAuthority)
    (hBounded : PathStringsBounded items.val) :
    normalize.sort_and_deduplicate_paths items
      ⦃ out => out.val.Nodup ∧ ListSubset out.val items.val ∧
        PathStringsBounded out.val ⦄ := by
  unfold normalize.sort_and_deduplicate_paths
  step with deduplicate_paths_spec
  step with sort_path_loop_perm_any
  refine ⟨?_, ?_, ?_⟩
  · exact items1_post.perm out_post.symm
  · intro item hItem
    apply items1_post1 item
    exact out_post.mem_iff.mp hItem
  · intro item hItem
    apply items1_post2 item
    exact out_post.mem_iff.mp hItem

theorem sort_environment_loop_perm_any
    (items : alloc.vec.Vec authority.EnvironmentName)
    (iter : core.ops.range.Range Usize)
    (hEnd : iter.end.val = items.val.length)
    (hBounded : EnvironmentStringsBounded items.val) :
    normalize.sort_and_deduplicate_environment_loop0 iter items
      ⦃ out => out.val.Perm items.val ⦄ := by
  unfold normalize.sort_and_deduplicate_environment_loop0
  apply loop.spec_decr_nat
    (fun state : core.ops.range.Range Usize ×
        alloc.vec.Vec authority.EnvironmentName =>
      state.1.end.val - state.1.start.val)
    (fun state : core.ops.range.Range Usize ×
        alloc.vec.Vec authority.EnvironmentName =>
      state.2.val.Perm items.val ∧
      EnvironmentStringsBounded state.2.val ∧
      state.1.end.val = state.2.val.length)
    (fun out : alloc.vec.Vec authority.EnvironmentName =>
      out.val.Perm items.val)
  · rintro ⟨currentIter, currentItems⟩
      ⟨hPerm, hCurrentBounded, hCurrentEnd⟩
    simp only at hPerm hCurrentBounded hCurrentEnd ⊢
    unfold normalize.sort_and_deduplicate_environment_loop0.body
    step
    cases o with
    | none =>
        exact hPerm
    | some index =>
        have hLess : currentIter.start.val < currentIter.end.val := by
          by_contra hNotLess
          simp [hNotLess] at o_post
        simp [hLess] at o_post
        rcases o_post with ⟨hIndexEq, hNextStart⟩
        have hNextEnd : iter1.end.val = currentIter.end.val := by
          simpa using congrArg UScalar.val o_post1
        have hIndex : index.val < currentItems.val.length := by
          rw [hIndexEq, ← hCurrentEnd]
          exact hLess
        step
        refine ⟨r_post.trans hPerm, ?_, ?_, ?_⟩
        · intro item hItem
          apply hCurrentBounded item
          exact r_post.mem_iff.mp hItem
        · rw [hNextEnd, hCurrentEnd]
          exact r_post.length_eq.symm
        · omega
  · exact ⟨List.Perm.refl _, hBounded, hEnd⟩

@[step]
theorem sort_and_deduplicate_environment_spec
    (items : alloc.vec.Vec authority.EnvironmentName)
    (hBounded : EnvironmentStringsBounded items.val) :
    normalize.sort_and_deduplicate_environment items
      ⦃ out => out.val.Nodup ∧ ListSubset out.val items.val ∧
        EnvironmentStringsBounded out.val ⦄ := by
  unfold normalize.sort_and_deduplicate_environment
  step with deduplicate_environment_spec
  step with sort_environment_loop_perm_any
  refine ⟨?_, ?_, ?_⟩
  · exact items1_post.perm out_post.symm
  · intro item hItem
    apply items1_post1 item
    exact out_post.mem_iff.mp hItem
  · intro item hItem
    apply items1_post2 item
    exact out_post.mem_iff.mp hItem

def AuthorityStringsBounded (plan : authority.AuthorityPlan) : Prop :=
  PathStringsBounded plan.paths.val ∧
    EnvironmentStringsBounded plan.environment.val

theorem normalize_authority_refines
    (plan : authority.AuthorityPlan)
    (hBounded : AuthorityStringsBounded plan) :
    normalize.normalize_authority plan
      ⦃ out =>
        out.paths.val.Nodup ∧
        ListSubset out.paths.val plan.paths.val ∧
        out.environment.val.Nodup ∧
        ListSubset out.environment.val plan.environment.val ∧
        out.limits = plan.limits ∧
        out.network = plan.network ⦄ := by
  unfold normalize.normalize_authority
  unfold authority.AuthorityPlan.into_parts
  simp only
  step with sort_and_deduplicate_paths_spec as
    ⟨paths1, hPathsNodup, hPathsSubset, hPathsBounded⟩
  step with sort_and_deduplicate_environment_spec as
    ⟨environment1, hEnvironmentNodup, hEnvironmentSubset,
      hEnvironmentBounded⟩
  constructor
  · exact hPathsNodup
  constructor
  · exact hPathsSubset
  constructor
  · exact hEnvironmentNodup
  exact hEnvironmentSubset

end ProofboundRuntime.Refinement.AuthorityNormalization

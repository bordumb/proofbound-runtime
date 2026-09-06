import ProofboundRuntimeCore.Funs

open Aeneas Aeneas.Std Result ControlFlow Error

namespace ProofboundRuntime.Refinement.Authority

open proofbound_runtime_core

theorem slice_swap_eq_list_swap
    {T : Type} [Inhabited T]
    (s : Slice T) (a b : Usize)
    (ha : a.val < s.length) (hb : b.val < s.length) :
    core.slice.Slice.swap s a b
      ⦃ s' => s'.val = s.val.swap a.val b.val ⦄ := by
  apply Aeneas.Std.WP.spec_mono (core.slice.Slice.swap_spec s a b ha hb)
  intro s' hs
  rcases hs with ⟨hlen, ha', hb', hother⟩
  apply List.ext_getElem
  · simpa using hlen
  · intro i hi' hiSwap
    by_cases hia : i = a.val
    · subst i
      rw [← List.Inhabited_getElem_eq_getElem! s'.val a.val hi',
        ← List.Inhabited_getElem_eq_getElem! s.val b.val hb] at ha'
      simpa [ha, hb] using ha'
    · by_cases hib : i = b.val
      · subst i
        rw [← List.Inhabited_getElem_eq_getElem! s'.val b.val hi',
          ← List.Inhabited_getElem_eq_getElem! s.val a.val ha] at hb'
        simpa [ha, hb] using hb'
      · have hAt := hother i hia hib
        have hi : i < s.val.length := by simpa [hlen] using hi'
        rw [← List.Inhabited_getElem_eq_getElem! s'.val i hi',
          ← List.Inhabited_getElem_eq_getElem! s.val i hi] at hAt
        simpa [hia, hib, hi', hiSwap] using hAt

@[step]
theorem slice_swap_perm
    {T : Type} [Inhabited T]
    (s : Slice T) (a b : Usize)
    (ha : a.val < s.length) (hb : b.val < s.length) :
    core.slice.Slice.swap s a b
      ⦃ s' => s'.val.Perm s.val ⦄ := by
  apply Aeneas.Std.WP.spec_mono (slice_swap_eq_list_swap s a b ha hb)
  intro s' h
  rw [h]
  exact List.swap_perm _ _ _

def BytesEqualFrom
    (left right : Slice Std.U8) (start : Nat) : Prop :=
  ∀ i, start ≤ i → i < left.length → left.val[i]! = right.val[i]!

@[step]
theorem bytes_same_loop_spec
    (left right : Slice Std.U8)
    (start : Std.Usize)
    (hStart : start.val ≤ left.length)
    (hLength : left.length = right.length) :
    authority.bytes_same_loop left right start
      ⦃ same => same = true ↔ BytesEqualFrom left right start.val ⦄ := by
  unfold authority.bytes_same_loop
  apply loop.spec_decr_nat
    (fun cursor => left.length - cursor.val)
    (fun cursor =>
      start.val ≤ cursor.val ∧
      cursor.val ≤ left.length ∧
      ∀ i, start.val ≤ i → i < cursor.val → left.val[i]! = right.val[i]!)
    (fun same => same = true ↔ BytesEqualFrom left right start.val)
  · intro cursor hCursor
    rcases hCursor with ⟨hStartCursor, hCursorLength, hPrefix⟩
    unfold authority.bytes_same_loop.body
    simp only
    split
    · rename_i hlt
      have hLeft : cursor.val < left.length := by
        simpa using hlt
      have hRight : cursor.val < right.length := by
        simpa [← hLength] using hLeft
      step
      step
      split
      · rename_i hne
        simp only [WP.spec_ok]
        constructor
        · intro hFalse
          simp at hFalse
        · intro hAll
          exfalso
          have hAt := hAll cursor.val hStartCursor hLeft
          simp_all
      · rename_i heq
        step
        refine ⟨?_, ?_, ?_, ?_⟩
        · rw [index1_post]
          omega
        · rw [index1_post]
          omega
        · intro i hiStart hiCursorNext
          by_cases hi : i < cursor.val
          · exact hPrefix i hiStart hi
          · have hiEq : i = cursor.val := by
              rw [index1_post] at hiCursorNext
              omega
            subst i
            have hVal : i1.val = i2.val := by
              simpa using heq
            have hI : i1 = i2 := UScalar.eq_of_val_eq hVal
            have hByte : left.val[cursor.val] = right.val[cursor.val] := by
              simpa [i1_post, i2_post] using hI
            simpa [hLeft, hRight] using hByte
        · rw [index1_post]
          omega
    · rename_i hnlt
      simp only [WP.spec_ok]
      have hCursorEq : cursor.val = left.length := by
        have : ¬ cursor.val < left.length := by simpa using hnlt
        omega
      constructor
      · intro _ i hiStart hiLength
        apply hPrefix i hiStart
        omega
      · intro _
        trivial
  · exact ⟨Nat.le_refl _, hStart, by omega⟩

theorem bytesEqualFrom_zero_iff
    (left right : Slice Std.U8)
    (hLength : left.length = right.length) :
    BytesEqualFrom left right 0 ↔ left.val = right.val := by
  constructor
  · intro h
    apply List.ext_getElem hLength
    intro i hLeft hRight
    have hAt := h i (Nat.zero_le _) hLeft
    simpa [hLeft, hRight] using hAt
  · intro h i _ hLeft
    rw [h]

@[step]
theorem bytes_same_spec (left right : Slice Std.U8) :
    authority.bytes_same left right
      ⦃ same => same = true ↔ left.val = right.val ⦄ := by
  unfold authority.bytes_same
  simp only
  split
  · rename_i hne
    simp only [WP.spec_ok]
    constructor
    · intro hFalse
      simp at hFalse
    · intro hEqual
      have hLength : left.length = right.length :=
        congrArg List.length hEqual
      simp_all
  · rename_i heq
    have hLength : left.length = right.length := by
      simpa using heq
    step
    exact same_post.trans (bytesEqualFrom_zero_iff left right hLength)

def ByteValuesEqualBetween
    (left right : Slice Std.U8) (start stop : Nat) : Prop :=
  ∀ i, start ≤ i → i < stop → left.val[i]!.val = right.val[i]!.val

def BytesComeBeforeFrom
    (left right : Slice Std.U8) (commonLength start : Nat) : Prop :=
  (∃ i,
      start ≤ i ∧ i < commonLength ∧
      ByteValuesEqualBetween left right start i ∧
      left.val[i]!.val < right.val[i]!.val) ∨
  (ByteValuesEqualBetween left right start commonLength ∧
    left.length < right.length)

@[step]
theorem bytes_come_before_loop_spec
    (left right : Slice Std.U8)
    (commonLength start : Std.Usize)
    (hStart : start.val ≤ commonLength.val)
    (hLeftLength : commonLength.val ≤ left.length)
    (hRightLength : commonLength.val ≤ right.length) :
    authority.bytes_come_before_loop left right commonLength start
      ⦃ before => before = true ↔
        BytesComeBeforeFrom left right commonLength.val start.val ⦄ := by
  unfold authority.bytes_come_before_loop
  apply loop.spec_decr_nat
    (fun cursor => commonLength.val - cursor.val)
    (fun cursor =>
      start.val ≤ cursor.val ∧
      cursor.val ≤ commonLength.val ∧
      ByteValuesEqualBetween left right start.val cursor.val)
    (fun before => before = true ↔
      BytesComeBeforeFrom left right commonLength.val start.val)
  · intro cursor hCursor
    rcases hCursor with ⟨hStartCursor, hCursorCommon, hPrefix⟩
    unfold authority.bytes_come_before_loop.body
    simp only
    split
    · rename_i hlt
      have hCommon : cursor.val < commonLength.val := by
        simpa using hlt
      have hLeft : cursor.val < left.length := hCommon.trans_le hLeftLength
      have hRight : cursor.val < right.length := hCommon.trans_le hRightLength
      step
      step
      split
      · rename_i hne
        simp only [WP.spec_ok]
        have hNeAt : left.val[cursor.val]!.val ≠ right.val[cursor.val]!.val := by
          have hNe : i.val ≠ i1.val := by
            simpa using hne
          simpa [i_post, i1_post, hLeft, hRight] using hNe
        constructor
        · intro hBefore
          left
          refine ⟨cursor.val, hStartCursor, hCommon, hPrefix, ?_⟩
          have hLess : i.val < i1.val := by
            simpa using hBefore
          simpa [i_post, i1_post, hLeft, hRight] using hLess
        · intro hRelation
          rcases hRelation with hFirst | hLengths
          · rcases hFirst with ⟨j, hjStart, hjCommon, hjPrefix, hjLess⟩
            have hj : j = cursor.val := by
              by_contra hjNe
              rcases Nat.lt_or_gt_of_ne hjNe with hjBefore | hjAfter
              · have hEq := hPrefix j hjStart hjBefore
                omega
              · have hEq := hjPrefix cursor.val hStartCursor hjAfter
                exact (hNeAt hEq).elim
            subst j
            have hLess : i.val < i1.val := by
              simpa [i_post, i1_post, hLeft, hRight] using hjLess
            simpa using hLess
          · rcases hLengths with ⟨hAllEqual, _⟩
            have hEq := hAllEqual cursor.val hStartCursor hCommon
            exact (hNeAt hEq).elim
      · rename_i heq
        step
        refine ⟨?_, ?_, ?_, ?_⟩
        · rw [index1_post]
          omega
        · rw [index1_post]
          omega
        · intro j hjStart hjNext
          by_cases hj : j < cursor.val
          · exact hPrefix j hjStart hj
          · have hjEq : j = cursor.val := by
              rw [index1_post] at hjNext
              omega
            subst j
            have hEq : i.val = i1.val := by
              simpa using heq
            simpa [i_post, i1_post, hLeft, hRight] using hEq
        · rw [index1_post]
          omega
    · rename_i hnlt
      simp only [WP.spec_ok]
      have hCursorEq : cursor.val = commonLength.val := by
        have : ¬ cursor.val < commonLength.val := by simpa using hnlt
        omega
      constructor
      · intro hLengths
        right
        constructor
        · intro i hiStart hiCommon
          apply hPrefix i hiStart
          omega
        · simpa using hLengths
      · intro hRelation
        rcases hRelation with hFirst | hLengths
        · rcases hFirst with ⟨i, hiStart, hiCommon, _, hiLess⟩
          have hEq := hPrefix i hiStart (by omega)
          omega
        · simpa using hLengths.2
  · exact ⟨Nat.le_refl _, hStart, by
      intro i hiStart hiStop
      omega⟩

def BytesComeBefore (left right : Slice Std.U8) : Prop :=
  BytesComeBeforeFrom left right (min left.length right.length) 0

@[step]
theorem bytes_come_before_spec (left right : Slice Std.U8) :
    authority.bytes_come_before left right
      ⦃ before => before = true ↔ BytesComeBefore left right ⦄ := by
  unfold authority.bytes_come_before
  simp only
  split
  · rename_i hlt
    have hLength : left.length < right.length := by
      simpa using hlt
    step
    unfold BytesComeBefore
    rw [Nat.min_eq_left (Nat.le_of_lt hLength)]
    exact common_length_post
  · rename_i hnlt
    have hLength : right.length ≤ left.length := by
      have : ¬ left.length < right.length := by simpa using hnlt
      omega
    step
    unfold BytesComeBefore
    rw [Nat.min_eq_right hLength]
    exact common_length_post

def StringBytes (value : String) : List Std.U8 :=
  value.toByteArray.toList.map (fun byte =>
    ⟨byte.toNat, by
      cases byte
      simp only [UInt8.toNat_ofBitVec, UScalarTy.U8_numBits_eq,
        Nat.reducePow]
      omega⟩)

@[step]
theorem string_as_bytes_spec (value : String)
    (hBound : value.toByteArray.size ≤ U32.max) :
    alloc.string.String.as_bytes value
      ⦃ bytes => bytes.val = StringBytes value ⦄ := by
  unfold alloc.string.String.as_bytes
  split
  · simp [Aeneas.Std.toStr, StringBytes]
  · rw [String.size_toByteArray] at hBound
    omega

@[step]
theorem string_len_spec (value : String)
    (hBound : value.toByteArray.size ≤ U32.max) :
    alloc.string.String.len value
      ⦃ length => length.val = value.toByteArray.size ⦄ := by
  unfold alloc.string.String.len
  step with string_as_bytes_spec
  change bytes.val.length = value.toByteArray.size
  rw [bytes_post]
  simp [StringBytes, ByteArray.length_toList]

@[step]
theorem fits_translation_string_carrier_spec (length : Usize) :
    authority.fits_translation_string_carrier length
      ⦃ fits => fits = true ↔ length.val ≤ U32.max ⦄ := by
  unfold authority.fits_translation_string_carrier
  step
  simp only [decide_eq_true_eq]
  change length.val ≤ i.val ↔ length.val ≤ U32.max
  simp [i_post, UScalar.cast_val_eq, core.num.U32.MAX, U32.rMax,
    U32.max, U32.numBits, UScalarTy.numBits]
  cases System.Platform.numBits_eq <;> simp_all

@[step]
theorem authority_path_same_value_spec
    (self other : authority.AuthorityPath)
    (hSelf : self.toByteArray.size ≤ U32.max)
    (hOther : other.toByteArray.size ≤ U32.max) :
    authority.AuthorityPath.same_value self other
      ⦃ same => same = true ↔ StringBytes self = StringBytes other ⦄ := by
  unfold authority.AuthorityPath.same_value
  step
  step
  step
  rw [s_post, s1_post] at same_post
  exact same_post

@[step]
theorem environment_name_same_value_spec
    (self other : authority.EnvironmentName)
    (hSelf : self.toByteArray.size ≤ U32.max)
    (hOther : other.toByteArray.size ≤ U32.max) :
    authority.EnvironmentName.same_value self other
      ⦃ same => same = true ↔ StringBytes self = StringBytes other ⦄ := by
  unfold authority.EnvironmentName.same_value
  step
  step
  step
  rw [s_post, s1_post] at same_post
  exact same_post

def ListByteValuesEqualBetween
    (left right : List Std.U8) (start stop : Nat) : Prop :=
  ∀ i, start ≤ i → i < stop → left[i]!.val = right[i]!.val

def StringComesBefore (self other : String) : Prop :=
  (∃ i,
      i < min (StringBytes self).length (StringBytes other).length ∧
      ListByteValuesEqualBetween (StringBytes self) (StringBytes other) 0 i ∧
      (StringBytes self)[i]!.val < (StringBytes other)[i]!.val) ∨
  (ListByteValuesEqualBetween (StringBytes self) (StringBytes other) 0
      (min (StringBytes self).length (StringBytes other).length) ∧
    (StringBytes self).length < (StringBytes other).length)

@[step]
theorem authority_path_comes_before_spec
    (self other : authority.AuthorityPath)
    (hSelf : self.toByteArray.size ≤ U32.max)
    (hOther : other.toByteArray.size ≤ U32.max) :
    authority.AuthorityPath.comes_before self other
      ⦃ before => before = true ↔ StringComesBefore self other ⦄ := by
  unfold authority.AuthorityPath.comes_before
  step
  step
  step
  have s_length : s.length = (StringBytes self).length :=
    congrArg List.length s_post
  have s1_length : s1.length = (StringBytes other).length :=
    congrArg List.length s1_post
  unfold BytesComeBefore BytesComeBeforeFrom ByteValuesEqualBetween at before_post
  unfold StringComesBefore
  rw [s_post, s1_post, s_length, s1_length] at before_post
  simpa [ListByteValuesEqualBetween] using before_post

@[step]
theorem environment_name_comes_before_spec
    (self other : authority.EnvironmentName)
    (hSelf : self.toByteArray.size ≤ U32.max)
    (hOther : other.toByteArray.size ≤ U32.max) :
    authority.EnvironmentName.comes_before self other
      ⦃ before => before = true ↔ StringComesBefore self other ⦄ := by
  unfold authority.EnvironmentName.comes_before
  step
  step
  step
  have s_length : s.length = (StringBytes self).length :=
    congrArg List.length s_post
  have s1_length : s1.length = (StringBytes other).length :=
    congrArg List.length s1_post
  unfold BytesComeBefore BytesComeBeforeFrom ByteValuesEqualBetween at before_post
  unfold StringComesBefore
  rw [s_post, s1_post, s_length, s1_length] at before_post
  simpa [ListByteValuesEqualBetween] using before_post

def PathAuthoritySameValue
    (self other : authority.PathAuthority) : Prop :=
  StringBytes self.path = StringBytes other.path ∧
    self.access = other.access ∧ self.role = other.role

@[step]
theorem path_authority_same_value_spec
    (self other : authority.PathAuthority)
    (hSelf : self.path.toByteArray.size ≤ U32.max)
    (hOther : other.path.toByteArray.size ≤ U32.max) :
    authority.PathAuthority.same_value self other
      ⦃ same => same = true ↔ PathAuthoritySameValue self other ⦄ := by
  rcases self with ⟨selfPath, selfAccess, selfRole⟩
  rcases other with ⟨otherPath, otherAccess, otherRole⟩
  unfold authority.PathAuthority.same_value
  step
  split
  · rename_i hTrue
    have hPathEq := b_post.mp hTrue
    cases selfAccess <;> cases otherAccess <;>
      cases selfRole <;> cases otherRole <;>
      simp [authority.file_access_rank, authority.path_role_rank,
        PathAuthoritySameValue, hPathEq]
  · rename_i hFalse
    have hPathNe : StringBytes selfPath ≠ StringBytes otherPath := by
      intro hEqual
      exact hFalse (b_post.mpr hEqual)
    simp [PathAuthoritySameValue, hPathNe]

def fileAccessRank : authority.FileAccess → Nat
  | .Read => 0
  | .Write => 1
  | .Execute => 2

def pathRoleRank : authority.PathRole → Nat
  | .ProjectInput => 0
  | .OutputRoot => 1
  | .RuntimeExecutable => 2
  | .RuntimeLoaderExecutable => 3
  | .RuntimeLibrary => 4

def PathAuthorityComesBefore
    (self other : authority.PathAuthority) : Prop :=
  if StringBytes self.path = StringBytes other.path then
    fileAccessRank self.access < fileAccessRank other.access ∨
      (self.access = other.access ∧
        pathRoleRank self.role < pathRoleRank other.role)
  else
    StringComesBefore self.path other.path

@[step]
theorem path_authority_comes_before_spec
    (self other : authority.PathAuthority)
    (hSelf : self.path.toByteArray.size ≤ U32.max)
    (hOther : other.path.toByteArray.size ≤ U32.max) :
    authority.PathAuthority.comes_before self other
      ⦃ before => before = true ↔ PathAuthorityComesBefore self other ⦄ := by
  rcases self with ⟨selfPath, selfAccess, selfRole⟩
  rcases other with ⟨otherPath, otherAccess, otherRole⟩
  unfold authority.PathAuthority.comes_before
  step
  split
  · rename_i hTrue
    have hPathEq := b_post.mp hTrue
    cases selfAccess <;> cases otherAccess <;>
      cases selfRole <;> cases otherRole <;>
      simp [authority.file_access_rank, authority.path_role_rank,
        PathAuthorityComesBefore, fileAccessRank, pathRoleRank, hPathEq]
  · rename_i hFalse
    have hPathNe : StringBytes selfPath ≠ StringBytes otherPath := by
      intro hEqual
      exact hFalse (b_post.mpr hEqual)
    step
    simpa [PathAuthorityComesBefore, hPathNe] using before_post

theorem bytes_same_loop_terminates
    (left right : Slice Std.U8)
    (index : Std.Usize)
    (hIndex : index.val ≤ left.length)
    (hLength : left.length = right.length) :
    authority.bytes_same_loop left right index ⦃ _ => True ⦄ := by
  unfold authority.bytes_same_loop
  apply loop.spec_decr_nat
    (fun index => left.length - index.val)
    (fun index => index.val ≤ left.length)
    (fun _ => True)
  · intro cursor hCursor
    unfold authority.bytes_same_loop.body
    simp only
    split
    · rename_i hlt
      have hLeft : cursor.val < left.length := by
        simpa using hlt
      have hRight : cursor.val < right.length := by
        simpa [← hLength] using hLeft
      step
      step
      split
      · simp
      · step
        constructor
        · simp_all
        · rw [index1_post]
          omega
    · simp
  · exact hIndex

theorem bytes_same_terminates (left right : Slice Std.U8) :
    authority.bytes_same left right ⦃ _ => True ⦄ := by
  unfold authority.bytes_same
  simp only
  split
  · simp
  · apply bytes_same_loop_terminates
    · simp
    · simp_all

theorem bytes_come_before_loop_terminates
    (left right : Slice Std.U8)
    (commonLength index : Std.Usize)
    (hIndex : index.val ≤ commonLength.val)
    (hLeftLength : commonLength.val ≤ left.length)
    (hRightLength : commonLength.val ≤ right.length) :
    authority.bytes_come_before_loop left right commonLength index
      ⦃ _ => True ⦄ := by
  unfold authority.bytes_come_before_loop
  apply loop.spec_decr_nat
    (fun index => commonLength.val - index.val)
    (fun index => index.val ≤ commonLength.val)
    (fun _ => True)
  · intro cursor hCursor
    unfold authority.bytes_come_before_loop.body
    simp only
    split
    · rename_i hlt
      have hCommon : cursor.val < commonLength.val := by
        simpa using hlt
      have hLeft : cursor.val < left.length := hCommon.trans_le hLeftLength
      have hRight : cursor.val < right.length := hCommon.trans_le hRightLength
      step
      step
      split
      · simp
      · step
        constructor
        · simp_all
        · rw [index1_post]
          omega
    · simp
  · exact hIndex

theorem bytes_come_before_terminates (left right : Slice Std.U8) :
    authority.bytes_come_before left right ⦃ _ => True ⦄ := by
  unfold authority.bytes_come_before
  simp only
  split
  · rename_i hlt
    apply bytes_come_before_loop_terminates
    · simp
    · simp
    · exact Nat.le_of_lt (by simpa using hlt)
  · rename_i hnlt
    apply bytes_come_before_loop_terminates
    · simp
    · exact Nat.le_of_not_gt (by simpa using hnlt)
    · simp

def EnvironmentStringsBounded
    (items : List authority.EnvironmentName) : Prop :=
  ∀ item, item ∈ items → item.toByteArray.size ≤ U32.max

theorem environment_comes_before_terminates
    (self other : authority.EnvironmentName)
    (hSelf : self.toByteArray.size ≤ U32.max)
    (hOther : other.toByteArray.size ≤ U32.max) :
    authority.EnvironmentName.comes_before self other ⦃ _ => True ⦄ := by
  apply Aeneas.Std.WP.spec_mono
    (environment_name_comes_before_spec self other hSelf hOther)
  simp

@[step]
theorem sort_environment_inner_perm
    (items : alloc.vec.Vec authority.EnvironmentName)
    (cursor : Usize)
    (hCursor : cursor.val < items.val.length)
    (hBounded : EnvironmentStringsBounded items.val) :
    normalize.sort_and_deduplicate_environment_loop0_loop0 items cursor
      ⦃ out => out.val.Perm items.val ⦄ := by
  unfold normalize.sort_and_deduplicate_environment_loop0_loop0
  apply loop.spec_decr_nat
    (fun state : alloc.vec.Vec authority.EnvironmentName × Usize =>
      state.2.val)
    (fun state : alloc.vec.Vec authority.EnvironmentName × Usize =>
      state.1.val.Perm items.val ∧
      state.2.val < state.1.val.length ∧
      EnvironmentStringsBounded state.1.val)
    (fun out : alloc.vec.Vec authority.EnvironmentName =>
      out.val.Perm items.val)
  · rintro ⟨currentItems, currentCursor⟩
      ⟨hPerm, hCurrentCursor, hCurrentBounded⟩
    simp only at hPerm hCurrentCursor hCurrentBounded ⊢
    unfold normalize.sort_and_deduplicate_environment_loop0_loop0.body
    simp only
    split
    · rename_i hPositive
      have hPrevious : currentCursor.val - 1 < currentItems.val.length := by
        omega
      step
      step
      have hCurrentValue := hCurrentBounded en (by
        rw [en_post]
        exact List.getElem_mem hCurrentCursor)
      step
      have hIndex : i.val < currentItems.val.length := by
        simpa [i_post] using hPrevious
      have hPreviousValue := hCurrentBounded en1 (by
        rw [en1_post]
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
            ({ slice := s } : alloc.vec.Vec authority.EnvironmentName).val.Perm
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

theorem sort_environment_loop_perm
    (items : alloc.vec.Vec authority.EnvironmentName)
    (iter : core.ops.range.Range Usize)
    (hStartEnd : iter.start.val ≤ iter.end.val)
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
      state.1.start.val ≤ state.1.end.val ∧
      state.1.end.val = state.2.val.length)
    (fun out : alloc.vec.Vec authority.EnvironmentName =>
      out.val.Perm items.val)
  · rintro ⟨currentIter, currentItems⟩
      ⟨hPerm, hCurrentBounded, hCurrentRange, hCurrentEnd⟩
    simp only at hPerm hCurrentBounded hCurrentRange hCurrentEnd ⊢
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
        refine ⟨r_post.trans hPerm, ?_, ?_, ?_, ?_⟩
        · intro item hItem
          apply hCurrentBounded item
          exact r_post.mem_iff.mp hItem
        · omega
        · rw [hNextEnd, hCurrentEnd]
          exact r_post.length_eq.symm
        · omega
  · exact ⟨List.Perm.refl _, hBounded, hStartEnd, hEnd⟩

end ProofboundRuntime.Refinement.Authority

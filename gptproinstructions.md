# GPT Pro Instructions for Improving Paper Readability

Use this document when you have access to the Pro model (9 Jan 2026) and want targeted, high-precision help improving readability of the ECAC paper. It is designed to minimize back-and-forth, constrain scope, and keep changes consistent with IEEE-style academic writing.

## 1) Context to Provide the Model

- Repo path: `/home/aditya/Downloads/ecac-core`
- Paper path: `/home/aditya/Downloads/ecac-core/Eventually_Consistent_Access_Control_with_Deterministic_Deny_Wins_Replay_for_Multi_Stakeholder_Offline_Systems/ecac.tex`
- Primary goal: improve readability without changing technical meaning or results.
- Constraints:
  - Do not change numbers, results, or claims.
  - Do not alter figures, tables, or citations unless readability requires a caption tweak.
  - Keep IEEEtran style; avoid stylistic drift.
  - Prefer minimal edits (sentence-level), no large rewrites unless explicitly requested.
  - Maintain deterministic/reproducibility wording.

## 2) One-Sentence Mission Statement

"Improve readability, clarity, and flow of the ECAC paper while preserving all technical content, results, and formatting conventions."

## 3) Scope Priorities (Top to Bottom)

1. Shorten or split long sentences.
2. Remove redundancy and reduce jargon density.
3. Improve paragraph flow and topic sentences.
4. Tighten definition-heavy passages with clearer structure.
5. Harmonize terminology (consistent names for concepts).

## 4) Explicit Do/Do-Not Rules

### Do
- Use concise, active voice where possible.
- Add short lead sentences to orient sections.
- Use parallel structure in lists.
- Replace vague pronouns with explicit nouns when clarity improves.
- Preserve citations and their placement.

### Do Not
- Do not change meaning, numbers, or conclusions.
- Do not add new references or remove existing citations.
- Do not modify algorithmic/formal definitions beyond formatting.
- Do not change section order or headings unless asked.
- Do not run formatting tools unless requested.

## 5) What to Ask the Model to Do

Use one of the following request templates:

### Template A: Whole-section readability pass
"Please do a readability-only edit of Section X in `ecac.tex`. Preserve technical meaning, citations, and results. Keep edits minimal and localized. Return a patch and a short summary of what you changed."

### Template B: Targeted paragraph improvement
"Please improve readability of paragraphs starting at line Y in `ecac.tex` (Section X). Keep meaning, citations, and terminology intact. Return a diff-only patch and a short justification."

### Template C: Consistency sweep
"Please scan `ecac.tex` for inconsistent terminology related to [concept] and unify naming for readability. Do not change meaning or claims. Provide a list of changes and a patch."

### Template D: Abstract + intro polish
"Please tighten the abstract and the first 2 paragraphs of the introduction for clarity and flow. Preserve all results, claims, and citations. Return a minimal patch."

## 6) Expected Output Format

Ask the model to respond with:

- A unified diff patch.
- A bullet list of changes (2-6 bullets).
- A short note on any risk of meaning drift.

Example:

"Return:
1) A unified diff.
2) 2-6 bullets summarizing changes.
3) Any potential meaning-risk sentence(s)."

## 7) Readability Checklist (for the model)

- Are all acronyms defined on first use?
- Is each paragraph centered on a single idea?
- Are sentences under ~30 words where possible?
- Is terminology consistent across sections?
- Does each section begin with a clear framing sentence?
- Are lists parallel and uniform?

## 8) Testing/Compilation Guidance

Only if requested:

"After edits, run:
- `pdflatex -interaction=nonstopmode ecac.tex`
- `bibtex ecac`
- `pdflatex -interaction=nonstopmode ecac.tex` (twice)
Report any new warnings introduced by edits."

## 9) Example High-Precision Prompt

"You are editing `ecac.tex` for readability only. Do not change results, data, citations, or meaning. Edit Sections 4.1 and 4.2 only. Keep edits minimal, prefer sentence splits and removal of redundancy. Output a unified diff and 2-5 bullets summarizing changes."


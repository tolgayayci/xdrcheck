<!-- Source of guide/VERIFICATION.md: build.py (verification.py) fills in the $$name placeholders from the repository. Edit this file, not VERIFICATION.md. -->

# Verification report: indexer-hardening guide

## 1. Purpose and status

This report sets out how the authors checked each statement in the indexer-hardening guide
([`indexer-hardening.mdx`](indexer-hardening.mdx) and its [checklist](checklist.mdx)). For every claim it gives the
kind of evidence behind it, where that evidence is in this repository or upstream, and what is still open. All
numbers below are generated from the repository's files by `guide/review/build.py`, and `make verify-guide` fails
if this report no longer matches them.

This is the authors' own check. Nobody independent has reviewed the guide. No stellar-core or platform engineer
has reviewed it yet, and nothing here should be read as saying one has. Of the guide's ${claims} claims,
${reviewed} are confirmed or corrected by a reviewer, ${disputed} are disputed and ${unreviewed} are unreviewed.

The guide is written for developers.stellar.org. It will not be published there until a stellar-core or platform
engineer has reviewed it: every fact claim `confirmed` or `corrected` and none `disputed` (the acceptance check
`guide-review` in [docs/acceptance.md](../docs/acceptance.md)). This report is meant to make that review short: it
tells the reviewer what each claim rests on and which claims need an expert's judgement most.

## 2. Method

### 2.1 What a claim is

Each normative sentence of the guide has a claim tag (`{/* claim: C-nnnn */}`) right after it. Each tag has one
record in [`claims.yaml`](claims.yaml): the sentence, whether it is a `fact` or a `recommendation`, its sources,
its `verification` and its `reviewer_status`. The field table also has records, one for each line's verdict, each
core check and each "you may / must not assume" sentence. `scripts/py/check_guide_claims.py` (in
`make repo-checks`) fails when the page and the records differ, or when a sentence with "must", "never", "should"
or "do not" has no tag. [REVIEW.md](REVIEW.md) describes the record format.

The records hold ${claims} claims (${facts} facts, ${recommendations} recommendations) and ${src_total} sources:
${src_code} code lines, ${src_corpus} corpus entries, ${src_probe} probes, ${src_cap} CAP and ${src_sep} SEP
sections, and ${src_issue} links to upstream issues that the report leaves out.

### 2.2 The evidence classes

`claims.yaml` stores two verification values: `executed` (${executed} claims) and `code_reference`
(${code_reference}). This report splits `executed` by what the record cites, which gives the classes used in every
table below. The rule is in `guide/review/verification.py`.

| Class | Rule | Claims | What it proves | What it does not prove |
| --- | --- | --- | --- | --- |
| Corpus entry | `executed`, and the claim cites a corpus entry | ${n_corpus} | stellar-core produced, or accepted into a real ledger, the bytes the claim describes. Anyone can check the bytes again from the entry. | That a check is absent everywhere. One accepted ledger shows that one value was accepted. |
| Probe | `executed`, no corpus entry, at least one probe source | ${n_probe} | A measurement was run: a decoder on hand-built inputs, a scan, a read of the network configuration, a local stellar-core run. | Anything outside the inputs and versions measured. |
| Executed, source not recorded | `executed`, but the record cites no corpus entry or probe | ${n_norecord} | Nothing the record itself shows. These are gaps in the records (section 5). | |
| Code reference | `verification: code_reference` | ${n_code} | The authors read the cited lines at the pinned commit and found that they say what the claim says. | That no other line changes the result, such as a check in a file or stage the claim does not cite. |

**Corpus entries: how the bytes were produced and checked.** The claims cite ${cited_ids} corpus IDs. An ID that names a group, such as a set of
SEP-23 vectors, stands for each of its members, so the IDs cover ${cited_entries} entries of `corpus/index.json`
(${cited_kinds}) with ${cited_variants} variants: ${variant_sources}. The checks on each
source kind are in [docs/manifest.md](../docs/manifest.md) sections 4.4 and 11.

- *All entries.* `xdrcheck-corpus verify` decodes each blob with explicit limits and re-encodes it, and the bytes
  must match exactly. It also checks the hashes: each blob's name is its SHA-256, and each decoded sidecar matches
  its stated hash and a fresh render. Every path and value an entry's `expect` names must resolve and be equal.
  The ledger header hash and the transaction hashes are recomputed under the stated passphrase. The participants,
  state changes and movements an entry expects must match the reference extractor's output.
- *local-core* variants come from the pinned stellar-core release, run on a local network with a scenario file. Of
  the cited variants: ${lc_repro}. Normalised-identical means two runs give the same ledger header hashes and the
  same bytes once stellar-core's own golden-comparison normalisation is applied. The raw meta bytes are not
  byte-reproducible (see manifest section 4.4). `xdrcheck-corpus gen --check` regenerates a run and compares it.
- *Golden agreement (AG-4).* Of the ${lc_cited} cited local-core entries, ${lc_mapped} match a transaction in
  stellar-core's own golden ledger set, and ${lc_opmapped} more have a golden operation of the same shape for each
  of their operations. Across the corpus the figures are ${mirror_mapped} and ${mirror_ops} of ${mirror_lc}
  local-core entries. This agreement is about shape: union arms, lengths and shape tokens. It never covers values or
  bytes ([corpus/mirrors.json](../corpus/mirrors.json)).
- *history* variants are captured verbatim from the public ledger data set. `xdrcheck-corpus refetch` checks the
  object hash, the decompressed hash and the offset again. Of the cited history variants, ${hist_regen_true} have
  `regenerated: true`: the object was written by a later stellar-core than the ledger's own era. Such an object is
  real stellar-core output for that ledger, but not the bytes a node wrote at the time. ${hist_regen_false} have
  `regenerated: false`.
- *Hash chain.* ${scan_claims} claims about when a result code occurs rest on the pubnet scan. That scan reads every ledger
  from ${scan_first} to ${scan_last} (${scan_ledgers} ledgers) and refuses ${scan_refusals}. It checks ${scan_links} previous-ledger
  hash links and finds ${scan_mismatch} mismatches ([evidence/mainnet-scan](../evidence/mainnet-scan/README.md)).
- *synthetic* and *core-golden* variants: a synthetic variant follows a recorded recipe, and its entry says why
  stellar-core cannot emit it. A core-golden variant must equal a frame of stellar-core's golden file at the pinned
  tag (AG-1).

**Probes, by family.** Every probe source fits one or more families below. If one fits none, the build fails.

| Family | What was run | Probe sources | Claims | Where the run is |
| --- | --- | --- | --- | --- |
${probe_rows}
Some probe sources record design reasoning or cite an existing docs page rather than a measurement. They back
only these recommendations: ${design_claims}. Their `verification` is `code_reference`, so the tables count them
as code references. The result files of the SDK decoding matrix are not committed: `evidence/sdk-matrix/run.sh`
regenerates them, and the corpus entries and conformance columns cite the vectors that matter.

**Code references.** Each code source names a file and lines at a fixed commit:

| Commit as the record states it | Code sources |
| --- | --- |
${code_at_rows}
The claims cite ${ref_unique} distinct line ranges in ${ref_files} files.
[`review/code-refs.tsv`](review/code-refs.tsv) records whether each range exists at its pinned commit:
${ref_ok} of ${ref_unique} do. `build.py --check` fails when a claim cites a range the file does not hold, or one
resolved at another commit. The file is regenerated from clones of the three repositories with
`build.py --resolve-refs`. The field table's own ${fields_code_refs} code references can be printed with their
source lines by `scripts/py/check_fields.py --print-refs`, and it fails on a reference that does not exist. A line
that exists is not proof that it says what the claim says. Only reading it shows that, which is the reviewer's
task.

| Repository | Pinned commit | Line ranges cited | Files |
| --- | --- | --- | --- |
${ref_by_repo}
Links in the guide and in this report use the release tag `v${core_version}` for stellar-core, which is commit
`${core_commit}`. For stellar-xdr and rs-soroban-env they use the commit itself.

### 2.3 The field table is checked against the corpus (`guide-table`)

The field-by-field table on the page is never written by hand.
`xdrcheck-corpus guide-table` generates it from [`corpus/fields.yaml`](../corpus/fields.yaml) joined with the
corpus manifest: each line's status, stage, code link and "demonstrated by" entries.
`make verify-guide OFFLINE=1` then fails when:

- the committed table differs from a fresh build;
- a sentence differs from its claim record (`guide-claims --check`);
- the checklist differs from the linter's rule registry (`xdrlint-docs --check`);
- this review package, this report included, is out of date (`guide/review/build.py --check`).

`make repo-checks` (`scripts/py/check_fields.py`) and `xdrcheck-corpus verify` also fail when a manifest entry
lists a line under a status other than the line's own.

It also runs the stellar-docs repository's own format and link checks on the pages, in a clone at the pinned docs
commit `${docs_commit}`. The table has ${table_rows} rows; a row whose parts differ is split into one line per part.
${table_lines} lines are published (${table_validated}
validated, ${table_partial} partially validated, ${table_passed} passed through) and ${table_withheld} are held
back until they are established. ${table_demonstrated} of the published lines cite a corpus entry that
demonstrates them. ${table_code_only} rest on a code reference alone ([review/unverified.md](review/unverified.md)).

### 2.4 Pinned versions

From [`pins.toml`](../pins.toml) and the `pins` block of `corpus/fields.yaml`:

| What | Pin |
| --- | --- |
| stellar-core | v${core_version}, commit `${core_commit}`, release binary SHA-256 `${core_binary}` (image `${core_image}`) |
| Protocol | ${protocol} |
| stellar-xdr definitions | ${xdr_tag}, commit `${xdr_commit}` |
| Soroban host the claims cite | rs-soroban-env `${env_commit}`, the p30 host submodule commit of stellar-core v${core_version}. This is not the rs-soroban-env release tag. The kit's own tools build against the crate soroban-env-host ${env_crate}, a different pin. |
| Decoder of the corpus (oracle) | rs-stellar-xdr (`stellar-xdr` crate) ${rs_xdr} |
| SDK releases the claims about SDK behaviour were measured on | JavaScript ${js_cols}; Go ${go_cols}; Rust ${rust_cols}; Python ${py_cols} (current: JavaScript ${js_sdk}, Go ${go_sdk}, Python ${py_sdk}) |
| Indexers | wallet-backend `${wb_commit}`; stellar-etl ${etl_tag} (`${etl_commit}`) |
| stellar-docs, for the docs checks | `${docs_commit}` |

## 3. Results in numbers

### 3.1 Claims per section and evidence class

${section_totals}
The `reviewer_note` fields of ${author_notes} claims (${author_note_ids}) hold notes the authors wrote. No
reviewer wrote them.

### 3.2 What the guide says core does not validate

These are the claims a reviewer should check first. A ledger can show that core accepted a value. No ledger can
show that core has no check for it, and a code reference can miss a check that sits in a file or stage the claim
does not cite. The list is derived, not hand-picked ([review/high-risk.md](review/high-risk.md) gives each
sentence). It holds ${hr_total} claims:

- ${hr_verdicts} "passed through" verdicts of the field table, ${hr_verdicts_code} of them on a code reference
  alone;
- ${hr_others} other statements that core does not check, verify, consume or accept something,
  ${hr_others_code} of them on a code reference alone.

Of the ${hr_total}: ${hr_corpus} cite a corpus entry, ${hr_probe} a probe without an entry, ${hr_norecord} record no
executed source, and ${hr_code} rest on code alone. In each table, claims on code alone come first.

#### Passed-through verdicts

${hr_verdict_table}
#### Other "core does not check" statements

${hr_other_table}
## 4. Section by section

The guide has four top-level sections: validated versus unvalidated fields, recommended caps,
participants from meta, muxed and signed-payload addresses including the SEP-23 forms; then a checklist that
carries the three linter checks to other languages.

### 4.1 Validated versus unvalidated fields

**What it claims.** Validation runs in stages, D0 to H. A transaction in a ledger has passed every stateless check
against the last closed ledger. A failed result can come from any stateful check. Then, field by field, the
section says whether core validates the field, validates part of it, or passes it through untouched, with the
stage, the code, the result code and what a reader may and must not assume. Further subsections cover passed-through
fields, three places where the common shorthand is wrong, what a failed transaction still leaves in the ledger,
which parts of meta are consensus, and how strict decoders are.

${sec_validated_fields}
${ev_validated_fields}
**How it was verified.**

- *Stages and the general rule* (C-001 to C-011, C-6101 to C-6104, C-6162 to C-6171) cite the stage functions at
  v${core_version}. Every cited range exists at the pinned commit (section 2.2). The field table's ${vf_claims}
  claims share these stage definitions.
- *Validated and partially validated verdicts* rest on the core check each line cites. Where a corpus entry lists
  the line, the entry shows the check at work: a ledger with the stated result code, or a value at the edge of what
  the check allows. ${table_code_only} published lines have no such entry yet. They are listed with their code
  links in [review/unverified.md](review/unverified.md), and question 1 of
  [review/questions.md](review/questions.md) asks the reviewer to check them first.
- *Passed-through verdicts* (section 3.2): where an entry exists, it shows an attacker-shaped value accepted into a
  ledger. Examples: a muxed ID above 2^63 (`cap-0027/muxed-source-id-above-2-pow-63`), a non-UTF-8 memo
  (`cap-0067/to-muxed-id-text-non-utf8-memo`), a forged token event (`cap-0067/forged-token-event-from-unrelated-contract`),
  unmatched authorization entries in a successful transaction (`cap-0046/auth-unmatched-entries-succeed`).
  Lines without an entry rest on code.
- *Failed transactions and the time-bound race* (C-6144 to C-6146, C-6161, C-6172): local-core runs, a captured
  pubnet ledger (`cap-0034/tx-too-late-with-fee-charged`) and the pubnet scan.
- *Meta consensus* (C-6147 to C-6150): code for the hashing and the node flags. For the regenerated public data
  set, the lake object metadata of the captured ledgers.
- *Decoder strictness* (C-6151 to C-6160): the SDK decoding matrix, and stellar-core's own `print-xdr`
  transcripts under [evidence/core-print-xdr](../evidence/core-print-xdr/README.md). These show how core's decoder
  behaves offline, not what core admits into a ledger, and the guide says so in C-6151.

**What remains open.** The held-back lines and the open points inside published rows (section 5).

### 4.2 Recommended caps

**What it claims.** A meta reader must never cap below what core admitted. A pre-submission reader may cap tighter
if it documents that choice. Each decoder counts depth in its own unit. The section then gives what core's
decoder, its envelope admission check and the Soroban host admit, the defaults the SDKs ship with, and what to do
at a bound.

${sec_caps}
${ev_caps}
**How it was verified.**

- *Units per nesting level, per decoder* (C-7005 to C-7011): measured by bisection. For the SDKs, in the depth
  group of the SDK decoding matrix. For stellar-core, with the release binary's `print-xdr`, whose transcript is
  `evidence/core-print-xdr/out/depth.txt`.
- *Limits core admits* (C-7013 to C-7018): each limit is read from code at the pinned commits. The decoder bound
  and the host value limit were also measured: the decoder bound with `print-xdr`, and the host value limit in a
  local-core scenario run in which a contract emits a nested vector in an event and the next level fails
  (`cap-0046/scval-nested-vec-99-in-event`).
- *Derived bounds* (C-7019 to C-7023) are marked as derived on the page. They are arithmetic on the measured units
  and the code limits. The page labels each one as measured, derived or read from code.
- *SDK defaults* (C-7024 to C-7031) are measured on the releases in section 2.4.
- *Sizes* (C-7038, C-7045, C-7051, C-7052) come from a captured pubnet ledger and a read of the network
  configuration at a stated ledger.
- *Recommendations* (C-7033 to C-7048) and the summary table (C-7049 to C-7054) follow from the facts above.
  C-7041 to C-7044, on batching and on what to do at a bound, rest on design reasoning, and their records say so.

**What remains open.** The envelope admission depth that core releases enforced before Protocol 28. The deepest
nesting a failed transaction's envelope can hold in each era. The cost per level of authorization sub-invocations
(question 3; section 5).

### 4.3 Participants from meta

**What it claims.** Who a transaction affected comes from meta: fee processing, transaction-level changes,
operation changes, Soroban changes and consensus events. It does not come from the envelope. The section gives a
step-by-step algorithm, a table of cases where envelope and meta disagree, and a worked example of a transaction
refused at apply.

${sec_participants_from_meta}
${ev_participants_from_meta}
**How it was verified.**

- Each row of the disagreement table (C-8025 to C-8033) and most algorithm steps name a corpus entry. A ledger
  entry states the participants, state changes and movements a correct reader produces, and `xdrcheck-corpus
  verify` (the `extractor` check) fails when the reference extractor's output differs from them.
- The worked example (C-8034, C-8035) is the captured pubnet ledger `cap-0034/tx-too-late-with-fee-charged`. Its
  values are read from the ledger's bytes.
- Protocol-boundary advice (C-8019 to C-8024) rests on the SDK decoding matrix on a Protocol 30 ledger, captured
  upgrade ledgers (`protocol-13/upgrade-ledger-header-13-envelopes-v0`, `cap-0088/first-ledger-with-signed-ms`),
  the code that sets the meta version on an upgrade ledger, and a replay of an indexer that halts on one error.
- The authorizer rule (C-8013, C-8014) rests on `cap-0046/auth-unmatched-entries-succeed`. There, a nonce entry is
  created only for the matched entry.

**What remains open.** Some claims here are marked executed, but their records cite no corpus entry or probe
(section 5, item 8). Question 9 asks whether the event rule (C-8009 to C-8011) is complete.

### 4.4 Muxed and signed-payload addresses, including the SEP-23 forms

**What it claims.** The section covers every SEP-23 strkey form with its version byte, payload and length, and
the XDR types that render to each. It covers storage widths, muxed accounts and the event routing ID, muxed
contracts (CAP-84), signed-payload signers (CAP-40), how to decode addresses safely, and how to carry 64-bit IDs.

${sec_muxed_and_signed_payload}
${ev_muxed_and_signed_payload}
**How it was verified.**

- *The form table and the worked examples* (C-9001 to C-9003, C-9032 to C-9038) come from the
  SEP-23 v1.4.0 test vectors, stored as corpus entries (`strkey/sep-0023-v1.4.0-vectors`) and decoded by every
  SDK column. The widths are measured on synthetic vectors (`strkey/synthetic-gap-vectors`).
- *Decoder behaviour on edge cases* (C-9005, C-9021, C-9026, C-9028, C-9029): groups 9 and 3 of the SDK decoding
  matrix, and `strkey/truncated-muxed-address-56-chars`.
- *Muxed accounts, the routing ID and muxed contracts* (C-9007 to C-9021): local-core runs with muxed sources and destinations,
  the maximum ID and ID zero, and captured pubnet and testnet ledgers for each `to_muxed_id` form, including the
  CAP-84 muxed contract on testnet (`cap-0084/sac-transfer-to-muxed-contract`).
- *Signed-payload signers* (C-9022 to C-9026): a captured testnet ledger adding the signer
  (`cap-0040/signed-payload-signer-added`), a captured ledger with two signed-payload extra signers
  (`cap-0021/extra-signers-two-signed-payload-keys`), and a local-core run with payloads of 1 and 64 bytes
  (`cap-0040/signed-payload-signers-1-byte-and-64-byte`). That core refuses an empty payload rests on code.
- *Storage advice* (C-9003, C-9004, C-9006) and *64-bit IDs* (C-9030, C-9031) follow from the SEP text and the
  matrix's ID-encoding vectors.

**What remains open.** Question 7 (whether an explicit void routing ID should mean "no ID") and question 8
(whether SEP-23 should state the 1 to 64-byte payload bound).

### 4.5 The checklist, carrying the three linter checks to other languages

**What it claims.** One item for each check an indexer in any language should pass, grouped by mistake. Each item
names the `xdrlint` rule that checks it in Go code, or explains why it is checked by hand and how.

${checklist_table}
**How it was verified.** The checklist has no records in `claims.yaml`: it restates the guide's claims as checks.
`go run ./cmd/xdrlint-docs --check` (in `make verify-guide`) generates it from the linter's rule registry. Every
one of the ${checklist_rules} rules has an item. ${checklist_linter} of the ${checklist_items} items are checked by
the linter and ${checklist_manual} by hand. `make lint-fixtures` runs the linter's tests, which check each rule
against fixture code with seeded violations. Every corpus entry the checklist names exists (`scripts/py/check_guide_entries.py`, run by
`build.py --check`). The guide sections each item links to are checked by the docs repository's link check.

**What remains open.** Manual items are checked only by the procedure each one describes. They have no automated
test.

## 5. Known limits and open questions

Each item states what is not established and what would establish it. [review/questions.md](review/questions.md)
holds the ${questions_n} questions put to the reviewer. The page lists the first four items under "Not yet
established". The field table holds back these lines: ${held_lines}.

1. **A time-bound failure in a ledger after CAP-34** (VF-14b; C-6173, C-6172; question 11). The corpus shows
   `txTOO_LATE` with the fee charged only in Protocol 13. The pubnet scan finds no `txTOO_LATE` after the upgrade
   to Protocol 15, and the corpus has no `txTOO_EARLY`. *To close it:* a local-core run at Protocol 30 that closes
   a ledger whose close time passes a queued transaction's `maxTime` (and one before its `minTime`), recording
   whether the transaction lands with a failed result or is dropped. Then a scan query for `txTOO_EARLY`.
2. **An archived-entry index that names a live entry** (VF-45b; question 4). *To close it:* a local-core run at
   Protocol 30 submitting a Soroban transaction whose `archivedSorobanEntries` marks a read-write entry that is
   live, recording core's answer (refused at submission, failed at apply, or applied).
3. **The deepest nesting core admits in a failed transaction's envelope, per era, and the depth of authorization
   sub-invocation trees** (VF-50c, VF-49; C-7012, C-7014, C-7023; question 3). *To close it:* bisect the nesting of
   an argument in an `InvokeHostFunction` transaction that fails, submitted to the pinned release, and record the
   last depth admitted. For eras before Protocol 28, repeat with the core release that was live then. Measure the
   decoder cost per level of a sub-invocation tree in every decoder column.
4. **Plain enum fields at admission, and non-canonical encodings in meta** (C-6156, C-6160; question 10). *To close
   it:* submit to a local core an envelope with an undeclared value in a plain enum field, and one with a boolean
   encoded as 2. Record whether core admits either into a ledger, and read the admission code with a core engineer.
5. **Open points inside published rows.** Where a clawback whose `from` is a muxed form of the issuer fails at
   apply (VF-20, VF-34; question 5). Whether unused CAP-71 delegate signatures are tolerated (VF-48; question 2).
   The deepest authorization tree in a successful and a failed transaction (VF-49). *To close them:* one local-core
   run for each, recording the result code and the meta.
6. **How the regenerated public data set was produced** (C-6150; question 6). The object metadata names
   stellar-core 23.0.1. The configuration flags it ran with are not recorded. *To close it:* a statement from the
   data set's maintainers, or a regeneration of one captured ledger with stated flags and a byte comparison.
7. **Conventions the code cannot settle** (questions 7 to 9): whether an explicit void `to_muxed_id` means "no
   routing ID", the signed-payload bound in SEP-23, and the event rule for token movements. *To close them:* the
   reviewer's answer, and where needed a SEP change proposed by the maintainers.
8. **Gaps in the records.** Executed, but no executed source recorded: ${norecord_ids}. Code reference, but the
   record cites no code line (${nocode_n}): ${nocode_ids}. *To close them:* add the corpus entry or probe each one
   rests on, or change its `verification` to what the record shows. Only the authors change records, and this
   report changes no verdict.
9. **Limits of the method itself.** A line that exists may not say what the claim says. A ledger shows that a value
   was accepted, not that no check exists. Golden agreement covers shape only. Local-core meta matches only after
   normalisation. Regenerated history is not the bytes of its time. `print-xdr` shows the decoder, not admission.
   *To close them:* only the engineer's review closes the first two for code-only claims, and section 3.2 lists
   those first.

## 6. For the reviewer

### Check one claim in five minutes

1. Find the claim. On the page, the tag follows the sentence. In [`claims.yaml`](claims.yaml), search for
   `claim_id: C-nnnn`. [`review/claims.csv`](review/claims.csv) has the same record with a link to every cited
   source line at its pinned commit.
2. Read the sources. A `code` source is a file and line range at the commit in its `at` field. The CSV links open
   it upstream.
3. If it cites a corpus entry, look at the bytes:

   ```sh
   xdrcheck entry cap-0027/muxed-source-id-above-2-pow-63            # tags, variants, expected values, provenance
   xdrcheck entry --decoded pubnet cap-0027/muxed-source-id-above-2-pow-63   # the decoded ledger (SEP-51 JSON)
   xdrcheck-corpus verify --entries 'cap-0027/*'                      # round trip, hashes and expected values again
   ```

   The entry's manifest, under `corpus/manifest/`, names the blob, its SHA-256, the source (a local-core run, a
   captured ledger or a recipe) and the values a correct reader derives.
4. If it cites a probe, open the run's folder (section 2.2, "Probes, by family"). Each README gives the command
   that runs it again.
5. Check the whole set at once:

   ```sh
   make verify-guide OFFLINE=1     # field table against the manifest, claims against the page, checklist, this report
   make repo-checks                # schemas, claim records, entry citations
   .venv/bin/python scripts/py/check_fields.py --print-refs --src core=PATH --src xdr=PATH --src env=PATH
                                   # every field-table code reference with its source lines at the pinned commits
   ```

### Record the review

Each answer changes one claim's `reviewer_status` in [`claims.yaml`](claims.yaml):

- `confirmed`;
- `corrected`: the page sentence and the record's `sentence` change together;
- `disputed`: the objection goes in `reviewer_note`.

[REVIEW.md](REVIEW.md) gives the full procedure. Then run `.venv/bin/python guide/review/build.py` to rebuild the
package and this report, and `make verify-guide OFFLINE=1`. The counts in the first section and the tables follow the records.
The docs pull request is opened only when no claim is disputed and every fact claim is confirmed or corrected.

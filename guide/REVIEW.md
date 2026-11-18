# Reviewing the indexer-hardening guide

The guide (`indexer-hardening.mdx`, `checklist.mdx`) is meant for developers.stellar.org. It is published only
after a stellar-core or platform engineer has reviewed what it says about stellar-core. Nothing in it is marked
reviewed today: every claim in `claims.yaml` has `reviewer_status: unreviewed`. This step cannot be finished
inside the repository; this file is what a maintainer hands to the reviewer.

[VERIFICATION.md](VERIFICATION.md) is the authors' own verification report: how each claim was checked, with which
evidence, and what is still open. It is not a review, and it is generated from the files below.

## What to check, in this order

1. **`review/high-risk.md`**: what the guide says stellar-core does *not* validate. List 1 is every
   "passed through" verdict of the field table; list 2 is every other statement that core does not check, verify,
   consume or accept something. Claims resting on a code reference alone come first. Both lists are generated
   from `claims.yaml` and `../corpus/fields.yaml`, so they stay current.
2. **`review/questions.md`**: the points the code at the pinned commits does not settle on its own.
3. **The field-by-field table** (`#field-table` in the page): each line's status, stage and code link. Lines
   published on a code reference alone, and lines held back, are in `review/unverified.md`.
4. **The rest of `review/claims.csv`**: every claim with a link to each source line at its pinned commit.

Statements about core refer to stellar-core v30.0.0 (Protocol 30), its Soroban host pin and stellar-xdr at the
commit in `../corpus/fields.yaml` (`pins`). A claim whose source is a corpus entry can be re-checked from the
entry's bytes: `corpus/manifest/<entry ID>.json` names the blob and the expected values.

## The claims file

`claims.yaml` (schema `../corpus/schema/claims.schema.json`) holds one record per normative statement:

| Field | Meaning |
| --- | --- |
| `claim_id` | `C-nnnn`; the page tags the sentence with `{/* claim: C-nnnn */}` right after it |
| `guide_anchor` | The section of the page the sentence is in (`#vf-nn` for field-table claims) |
| `sentence` | The page text, links reduced to their text; a table row is one statement, cells joined with ` \| ` |
| `kind` | `fact` or `recommendation` |
| `source` | Each source: `code` (file and lines at the stated commit), `cap`, `sep`, `corpus` (entry ID), `probe` (an executed measurement), `issue` |
| `verification` | `executed` (a ledger or probe shows it) or `code_reference` (read from the code only) |
| `corpus_entries`, `fields` | The corpus entries and field-table lines the claim bears on |
| `reviewer_status` | `unreviewed`, `confirmed`, `corrected` or `disputed`; changed only by the review |
| `reviewer_note` | What the reviewer said (optional until the review) |

## Recording the review

For each claim the reviewer answers on:

- **confirmed**: set `reviewer_status: confirmed`; add a `reviewer_note` if the reviewer added something.
- **corrected**: change the page sentence and the claim's `sentence` together, then set
  `reviewer_status: corrected` and a `reviewer_note` saying what changed and why.
- **disputed**: set `reviewer_status: disputed` and record the objection in `reviewer_note`; the claim stays
  disputed until it is corrected or withdrawn.

Then rebuild and check: `make verify-guide OFFLINE=1` (it rebuilds nothing; run `.venv/bin/python
guide/review/build.py` first to refresh the package's counts) and `make repo-checks`. The docs pull request is
opened only when no claim is `disputed` and every `fact` claim is `confirmed` or `corrected`.

## Sending the request

`review/request.md` is a draft of the request to send. A maintainer chooses the reviewer and the channel, checks the counts
against `review/README.md`, and sends it; nothing is sent from the repository. When the review is recorded, the
pages go to the docs repository with `docs-nav.patch` (see `README.md`).

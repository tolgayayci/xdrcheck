<!-- Source of request.md: build.py fills in the $$name placeholders. Edit this file, not request.md. -->

# Review request (draft)

Draft for a maintainer of this repository to send to a stellar-core or platform engineer at the Stellar Development
Foundation. Nothing has been sent. Fill in the names, pick the channel, and check the counts against `README.md`
before sending.

---

**Subject:** Review request: what an indexer-hardening guide says about stellar-core v30.0.0

Hi [name],

We have written a guide for developers.stellar.org on reading ledger data safely: which transaction fields
stellar-core validates and which it passes through, how deep and how large ledger data can be, how to work out
who a transaction affected from ledger meta, and how to handle every address form. It is two pages, written for
the docs repository at its current Mintlify layout, with a self-audit checklist.

Before we propose it to the docs maintainers we would like someone who knows stellar-core to check what the guide
says about core. We would rather publish nothing than publish a wrong statement about validation.

To make the review cheap, every normative sentence in the guide has a record with its source:

- $claims claims ($facts facts, $recommendations recommendations), each with the file and lines it rests on at
  stellar-core v30.0.0, its host pin or stellar-xdr, or a CAP or SEP section, or a test ledger;
- $executed of them are backed by an executed ledger or probe, and $code_reference by a code reference alone;
- a field-by-field table of $rows rows and parts, $code_only_rows of them published on a code reference alone;
- $withheld lines of that table held back from publication until they are established and demonstrated.

The package is in the repository under `guide/review/`: `README.md` explains it, `claims.csv` is the
claim-to-source map with a link to every cited line, `unverified.md` lists what still rests on code reading or is
not established, and `questions.md` holds the questions below in full.

What we would most like your view on:

$questions

Any answer helps, even to one question. The easiest way to reply is a list of claim IDs, each with "confirmed",
"disputed" or "corrected" and a note; we record each in the claim map, and we open the docs pull request only when
no claim is disputed and every fact claim is confirmed or corrected.

Thank you,

[name]

# Security policy

This page covers two different things: how to report a vulnerability **in this kit**, and how the kit handles
defects it finds **in other projects** before they have been reported to those projects.

## Reporting a vulnerability in this kit

Please do not open a public issue for a security problem in this repository. Report it privately through the
repository host's private vulnerability reporting ("Report a vulnerability" on the repository's Security tab).
If that option is not available to you, open a public issue that asks the maintainers for a private contact and
contains no details of the problem.

Please include what you ran (commit, command, platform), what happened and what you expected. You will get an
acknowledgement within 5 working days. A fix is released as soon as it is ready; the report and the fix are
published once a fixed version is available, crediting the reporter if they wish.

Supported versions: the default branch and the latest release. Older releases receive no fixes.

What is in scope, for example:

- a tool of the kit (`xdrcheck-corpus`, `xdrcheck`, `xdrlint`, an adapter or a driver) that can be made to execute code,
  write outside its working and report directories, or reach the network outside `make fetch`, through a crafted
  corpus entry, manifest, recipe, scenario, report or adapter response;
- a corpus file or release artefact that does not match its published hash, or a way to make the checks accept one;
- a way for a pull request to obtain write access or secrets in the project's CI;
- any secret, private key with funds, or personal data committed to the repository.

Not in scope: an expected value in the corpus that you believe is wrong (open an ordinary issue; corrections are
described in [docs/maintenance.md](docs/maintenance.md)), and defects in the projects the kit tests (below).

Some corpus entries are inputs built on purpose to stress readers: deep nesting, length prefixes near the limit,
very large ledgers. A reader that crashes on one of them, while decoding without limits, is showing the failure
the corpus exists to expose, not a vulnerability in this kit. The kit's own runs decode with explicit limits and
run every reader under memory and time limits ([docs/ci-isolation.md](docs/ci-isolation.md)).

## Defects the kit finds in other projects

Running the corpus against SDKs and pipelines finds defects in them. Some of those defects have security impact
for the project concerned: a transaction anyone can submit might halt a production indexer, exhaust its memory,
or make it record wrong balances or participants. The kit never publishes such a defect before the affected
project has been told.

### The rule: report before release

> Nothing that makes an unreported, security-relevant defect discoverable enters the public tree, a public CI log,
> a release or a status update until it has been reported privately to the affected project and the embargo has
> ended.

"Discoverable" means anything that would let a reader find or exercise the defect: the corpus entry built to
trigger it (manifest, blobs and the recipe that rebuilds them), a conformance column or driver that would run it
against the affected version, a known-divergence annotation naming the affected project and version, a linter
profile entry or suppression naming the affected code, a linter rule or target whose first public run would report
it, probe results, transcripts and report rows, matrix cells, the finding record and draft issue, its record ID,
and counts broken down by project.

Every trigger moves to the overlay. A corpus entry stays public only when a public purpose needs it (a public
finding, a guide claim) and nothing public runs it against the affected project and version; such a conflict is
decided per record by the maintainers, and until it is the tree is not pushed.

Files are published whole or withheld whole. A public file is never an overlay file with rows taken out (a results
table, a transcript, a probe source): the gap itself points at what is withheld. A file that would need trimming
stays in the overlay, and the public tree cites what reproduces it instead.

A finding is embargoed when any of these holds: the input can halt or crash a production reader on default
settings; it can exhaust memory, CPU or stack; it lets a submitter make a reader record wrong balances,
participants or authorisation without an error; the affected project's policy asks for private reports of that
kind; or its impact is not yet known and a worse outcome is plausible. **When in doubt, embargo**: lifting an
unnecessary embargo costs a day, a premature publication cannot be undone. Defects already public upstream, and
divergences anyone sees by running the published SEP vectors, are not embargoed.

### The private overlay

Withheld material lives in an **overlay**: a private directory, kept outside this repository, with the same
layout as the public tree and holding only what is withheld — finding records and drafts, the corpus entries and
recipes that exist only to show the defect, known-divergence annotations to add to public entries, conformance
columns with their drivers (a `drivers/sets.toml` of its own), probe results, linter profile additions and
suppressions, and scenarios or rules not yet released.

- Every tool that reads the manifest, findings or suppressions accepts `--overlay DIR` (or `XDRCHECK_OVERLAY`) and
  merges the overlay over the public files **in memory**; nothing is written back to the public tree.
- Reports made with an overlay are marked as such. `xdrcheck report acceptance` and `xdrcheck findings check` refuse them
  unless the overlay is given, and `xdrcheck conform run` with the overlay writes its report outside the working tree.
- Overlay finding records take IDs above `F-5000`, so creating one consumes no public ID and the public
  sequence (`F-0001`, …) reveals nothing about withheld work. The findings check fails on an embargoed record found
  in the public `findings/` directory.
- **Public CI never loads an overlay.** It stays green because nothing that would exercise an embargoed defect is
  in the public tree. A private run with the overlay checks everything, including the acceptance-mode findings
  check.
- **Before every push**, `make overlay-audit` (`xdrcheck overlay audit`, with `XDRCHECK_OVERLAY` set) checks the tree
  against the overlay: no trigger of an embargoed record (its entries with a public column, recipes, columns only
  the overlay runs, linter rows and profile additions, evidence files, record ID), a manifest entry for every
  recipe, no public file that is a row subset of, or identical to, the overlay file at the same path, and no
  public file anywhere with the content (git blob id) of an overlay file. It prints record IDs and paths only.
- **Every commit of a push, not only its tip.** A pushed commit can never be taken back, so `make push-gate
  RANGE=<last-pushed>..main` runs the same audit at every commit of the range (`xdrcheck overlay audit --revs`, read
  from git without a checkout), the public-tree scan at every commit (`check_public.py --revs`), the scan of every
  commit message (`check_public.py --messages`), and checks that only `main` is pushed. It needs the overlay and
  fails without it. Any problem blocks the push.
- **Private names are not in the public tree, not even in the scan.** `scripts/py/private-terms.sha256` holds
  salted hashes of the names the scan rejects; the plain list stays in the overlay. `xdrcheck report redact` reads the
  same list.
- **Replay triggers.** Every replay adapter ships in the public tree, so a public entry is enough to repeat any
  replay run. An embargoed record whose entry has scope `replay`, or whose evidence lists a `replay:` report row,
  therefore fails the audit while that entry is in the public tree: the entry moves to the overlay (manifest,
  blobs, sidecars, scenario or recipe, chain indexes only it uses, plan row), public records and pages that cited
  it cite other public entries, and from then on the audit looks only for its ID in public files.

### Pending finding review

A defect a public run reports that has not yet been reported upstream must still be accounted for, or public CI
would have to go red or publish it. The public tree therefore holds **pending lists** that name only the report
rows they account for, by key, and nothing else: no reason, no finding ID, no description
(`findings/pending/conformance.json` for conformance cells; `lint/expected/<target>/<commit>.pending.json` for
linter reports). Any other key fails the check, so a description cannot slip in. In development mode a matching
row is counted as "pending finding review"; in acceptance mode it fails, like an unfiled draft. When the finding
is approved and reported, its record and annotations move to the public tree and its rows leave the pending list.
Details: [findings/README.md](findings/README.md).

### Changing pins and adding rules

The only way a gating public job can meet a new defect is a change the project makes itself, so those changes are
tried privately first: a pin move to a new SDK or pipeline version is run with the overlay before it is proposed
publicly, and a new linter rule or profile is run privately over every pinned target before it is merged. If
either would surface a security-relevant defect, the change waits until the defect has been reported. Scheduled
jobs that track unpinned upstream releases never gate a merge and publish counts only, never details.

### Reporting and timelines

| Step | Default |
|---|---|
| Channel | The affected project's own security policy. Projects that point to the Stellar Development Foundation's bug bounty programme are reported there; where a repository has no policy file, the maintainers are asked how they want a private report, through a question that contains no details |
| Report | Within 5 working days of the decision to embargo, once the report text is approved by the maintainers of this kit |
| Embargo length | Until a fixed release is published, or 90 days after the report, whichever comes first. The affected project's programme terms take precedence, and a maintainer may ask for more time |
| Lifting | The affected maintainer is told the date in advance. The overlay's entries, annotations, suppressions and finding record then move to the public tree in an ordinary pull request and ship in the next corpus minor release; from then on the fixed version must pass and the affected range must still fail, so the fix becomes a regression test for every reader |

Every public acceptance report carries the fixed sentence "Findings under embargo, if any, are not represented in
this report; the private acceptance run covers them", so its presence reveals nothing.

### Nothing is filed automatically

No tool in this repository files, comments on or reports anything to another project, and CI holds no token that
could. `xdrcheck findings issue` writes a draft and prints the command a person would run, after the maintainers have
approved that exact draft and channel. Finding records name roles, never people.

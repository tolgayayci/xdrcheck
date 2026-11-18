# Drafts awaiting approval

Every draft in the public tree, with the command that would send it. **Nothing here has been filed, commented or
requested upstream, and no tool in this repository runs these commands.** Each one is sent by a person, after a
maintainer has approved that exact draft and channel, and the result (the URL of the issue or comment) is then recorded in
the finding record (`findings/README.md`, Lifecycle).

A draft lives next to its record, `findings/<id>/issue-<repository>.md`, and the record's `issue_draft` holds its
path, kind and command. This page is the index. Drafts are written by `xdrcheck findings issue <id>` (one record) and
`xdrcheck conform siblings --finding <id>` (the same defect in the other SDK families); both print the command and
never run it.

Only items whose upstream record is already public appear in this tree. Defects our runs found that are not yet
reported upstream are drafted privately and are not represented here (`findings/README.md`, Pending finding review
and Embargo).

## Drafts

| Record | Project | Kind | Upstream item | Body | State of the record |
|---|---|---|---|---|---|
| [F-0028](../F-0028/finding.json) | lightsail-network/java-stellar-sdk | release request | [PR #832](https://github.com/lightsail-network/java-stellar-sdk/pull/832), merged 2026-11-05, after release 6.0.0 (2026-10-28) | [issue-java-stellar-sdk.md](../F-0028/issue-java-stellar-sdk.md) | `duplicate-of` (the fix is upstream; the request asks for a release) |
| [F-0032](../F-0032/finding.json) | Beans-BV/dotnet-stellar-sdk | evidence comment | [issue #257](https://github.com/Beans-BV/dotnet-stellar-sdk/issues/257), open; [PR #272](https://github.com/Beans-BV/dotnet-stellar-sdk/pull/272), open, says it fixes it | [issue-dotnet-stellar-sdk.md](../F-0032/issue-dotnet-stellar-sdk.md) | `duplicate-of` issue #257: read from the 17.0.0 source, not executed (the kit has no driver for this SDK); the comment stays a draft |

Both come from one run of `xdrcheck conform siblings --finding F-0016` over a conformance matrix of the `cap-0038/*`
entries on every column, with the .NET source reading as manual evidence
(`findings/templates/manual-evidence.example.json`). The same defect is fixed upstream in js-stellar-sdk (F-0016,
#1766), go-stellar-sdk (F-0023, #5974) and py-stellar-base (F-0027, #1246); those records need no draft.

## Commands (printed, not run)

```sh
# F-0028 — release request (lightsail-network/java-stellar-sdk)
gh issue create --repo lightsail-network/java-stellar-sdk --title "Release request: Liquidity pool asset order compared as strkey text: valid pairs refused and reversed pairs accepted" --body-file findings/F-0028/issue-java-stellar-sdk.md

# F-0032 — evidence comment on an open issue (Beans-BV/dotnet-stellar-sdk#257)
gh issue comment 257 --repo Beans-BV/dotnet-stellar-sdk --body-file findings/F-0032/issue-dotnet-stellar-sdk.md
```

## Public records with an open upstream item and no draft

| Record | Upstream item | Why no draft |
|---|---|---|
| F-0006 | [wallet-backend#746](https://github.com/stellar/wallet-backend/issues/746), open | Its fix is already on the default branch (80121f3a, part of PR #739); our before/after linter rows show that fix and add nothing new. Asking for the issue to be closed is left to the maintainers. |
| F-0015 | [stellar-etl#450](https://github.com/stellar/stellar-etl/issues/450), open | The issue describes exactly what our replay and linter rows show; upstream keeps the behaviour on purpose and pins it in a test. |
| F-0025 | [go-stellar-sdk#5981](https://github.com/stellar/go-stellar-sdk/issues/5981), open | The issue states the same asymmetry with the same input. |
| F-0021 | [js-xdr#162](https://github.com/stellar/js-xdr/issues/162), closed, fix not in a release | Reachable only through a custom schema (the Stellar XDR definitions have no float-discriminated union); a release request is not worth the maintainers' time on its own. |

Every other public record is `duplicate-of` a fixed upstream item (no evidence to add) or `not-a-defect`.
`xdrcheck findings list` prints them all.

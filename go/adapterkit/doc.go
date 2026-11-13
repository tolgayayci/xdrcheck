// Package adapterkit is everything a replay adapter written in Go needs to speak `xcc.adapter/1`
// (docs/adapter-protocol.md), the protocol through which `xdrcheck replay` drives an indexer over the corpus:
//
//   - the protocol's messages as Go types (DescribeResult, IngestParams, Observation, …);
//   - Serve and Main: the stdio transport, the protocol-version check, error responses (Errorf), and the
//     refusal of input kinds and units the adapter did not declare, around a Handler you write;
//   - RunChild, for an indexer that is a separate program: a process group, a deadline, the end of stderr;
//   - ProvidedKinds and SortFacts, for an observe that follows the protocol's rules;
//   - ValidateMessage, ValidateObservation and CheckResponse: the frozen JSON Schemas, embedded, and the
//     harness's own checks of a response line;
//   - kittest (a sub-package): the selftest's protocol checks, in process, for your own `go test`.
//
// The template to copy is go/adapters/minimal (receipts and transactions, about 150 lines); the full reference
// is go/adapters/baseline. The package depends on the standard library only.
package adapterkit

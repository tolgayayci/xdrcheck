package catalogue

// Entries the XDR1xx rules (lint/rules/xdr1xx) add to the catalogue:
// the read-only View API of the SDK's xdr package (xdr_views_generated.go),
// which exposes the same memo, address and text fields as the decoded
// structs, plus the kind discriminants and sanitisers those rules check.
//
// They live in their own file so that the rule family can grow its
// vocabulary without editing the shared table; init appends them to Entries
// and to the lookup index before any rule runs.

var xdr1xxEntries = []Entry{
	// ---- Memo through the View API (XDR101; the text arm also XDR103) ----
	e(x+"TransactionView.Memo", KindMethod, r(MemoSource), ids("XDR101"), "xdr/xdr_views_generated.go:69481", "view of the transaction memo"),
	e(x+"TransactionView.MustMemo", KindMethod, r(MemoSource), ids("XDR101"), "", ""),
	e(x+"TransactionV0View.Memo", KindMethod, r(MemoSource), ids("XDR101"), "xdr/xdr_views_generated.go:68540", ""),
	e(x+"TransactionV0View.MustMemo", KindMethod, r(MemoSource), ids("XDR101"), "", ""),
	e(x+"MemoView.Id", KindMethod, r(MemoSource), ids("XDR101"), "xdr/xdr_views_generated.go:65865", ""),
	e(x+"MemoView.MustId", KindMethod, r(MemoSource), ids("XDR101"), "", ""),
	e(x+"MemoView.Text", KindMethod, r(MemoSource, TextSource), ids("XDR101", "XDR103"), "xdr/xdr_views_generated.go:65852", "opaque bytes, no content check in core"),
	e(x+"MemoView.MustText", KindMethod, r(MemoSource, TextSource), ids("XDR101", "XDR103"), "", ""),
	e(x+"MemoView.Hash", KindMethod, r(MemoSource), ids("XDR101"), "", ""),
	e(x+"MemoView.MustHash", KindMethod, r(MemoSource), ids("XDR101"), "", ""),
	e(x+"MemoView.RetHash", KindMethod, r(MemoSource), ids("XDR101"), "", ""),
	e(x+"MemoView.MustRetHash", KindMethod, r(MemoSource), ids("XDR101"), "", ""),

	// ---- Addresses through the View API (XDR102) ----
	// A view has no strkey renderer; the raw XDR of a muxed account or a
	// muxed ScAddress includes the multiplexing ID, so using it as a key
	// splits one account the same way an M… string does.
	e(x+"MuxedAccountView.Raw", KindMethod, r(AddressSource), ids("XDR102"), "xdr/xdr_views_generated.go:53398", "raw XDR includes the muxed ID"),
	e(x+"MuxedAccountView.MustRaw", KindMethod, r(AddressSource), ids("XDR102"), "", ""),
	e(x+"ScAddressView.Raw", KindMethod, r(AddressSource), ids("XDR102"), "xdr/xdr_views_generated.go:16271", "raw XDR of any address kind"),
	e(x+"ScAddressView.MustRaw", KindMethod, r(AddressSource), ids("XDR102"), "", ""),

	// ---- Kind discriminants a dominating check may test (XDR102) ----
	e(x+"CryptoKeyTypeKeyTypeEd25519", KindConst, r(AddressKind), ids("XDR102"), "", ""),
	e(x+"SignerKey.Type", KindField, r(AddressKind), ids("XDR102"), "", ""),
	e(x+"SignerKeyTypeSignerKeyTypeEd25519", KindConst, r(AddressKind), ids("XDR102"), "", ""),
	e(x+"SignerKeyTypeSignerKeyTypePreAuthTx", KindConst, r(AddressKind), ids("XDR102"), "", "renders T…"),
	e(x+"SignerKeyTypeSignerKeyTypeHashX", KindConst, r(AddressKind), ids("XDR102"), "", "renders X…"),
	e(x+"SignerKeyTypeSignerKeyTypeEd25519SignedPayload", KindConst, r(AddressKind), ids("XDR102"), "", "renders P…"),

	// ---- Text through the decoded structs and the View API (XDR103) ----
	e(x+"ScVal.GetExecutableTag", KindMethod, r(TextSource), ids("XDR103"), "xdr/xdr_generated.go:61578", ""),
	e(x+"ScVal.MustExecutableTag", KindMethod, r(TextSource), ids("XDR103"), "xdr/xdr_generated.go:61566", ""),
	e(x+"ScVal.GetSym", KindMethod, r(SymbolInfo), ids("XDR103"), "xdr/xdr_generated.go:61428", "host-restricted character set"),
	e(x+"ScVal.MustSym", KindMethod, r(SymbolInfo), ids("XDR103"), "xdr/xdr_generated.go:61416", ""),
	e(x+"ScValView.Str", KindMethod, r(TextSource), ids("XDR103"), "xdr/xdr_views_generated.go:17622", ""),
	e(x+"ScValView.MustStr", KindMethod, r(TextSource), ids("XDR103"), "", ""),
	e(x+"ScValView.Bytes", KindMethod, r(TextSource), ids("XDR103"), "xdr/xdr_views_generated.go:17609", ""),
	e(x+"ScValView.MustBytes", KindMethod, r(TextSource), ids("XDR103"), "", ""),
	e(x+"ScValView.ExecutableTag", KindMethod, r(TextSource), ids("XDR103"), "xdr/xdr_views_generated.go:17713", ""),
	e(x+"ScValView.MustExecutableTag", KindMethod, r(TextSource), ids("XDR103"), "", ""),
	e(x+"ScValView.Sym", KindMethod, r(SymbolInfo), ids("XDR103"), "xdr/xdr_views_generated.go:17635", ""),
	e(x+"ScValView.MustSym", KindMethod, r(SymbolInfo), ids("XDR103"), "", ""),
	e(x+"ContractExecutableExternalRefView.Tag", KindMethod, r(TextSource), ids("XDR103"), "xdr/xdr_views_generated.go:16325", ""),
	e(x+"ContractExecutableExternalRefView.MustTag", KindMethod, r(TextSource), ids("XDR103"), "", ""),
	e(x+"ManageDataOpView.DataValue", KindMethod, r(TextSource), ids("XDR103"), "xdr/xdr_views_generated.go:58169", ""),
	e(x+"ManageDataOpView.MustDataValue", KindMethod, r(TextSource), ids("XDR103"), "", ""),
	e(x+"DataEntryView.DataValue", KindMethod, r(TextSource), ids("XDR103"), "xdr/xdr_views_generated.go:24048", ""),
	e(x+"DataEntryView.MustDataValue", KindMethod, r(TextSource), ids("XDR103"), "", ""),
	e(x+"ManageDataOpView.DataName", KindMethod, r(TextValidated), ids("XDR103"), "", "core validates it: not a source"),
	e(x+"DataEntryView.DataName", KindMethod, r(TextValidated), ids("XDR103"), "", "core validates it: not a source"),

	// ---- Text sanitisers (XDR103) ----
	e("strings.ReplaceAll", KindFunc, r(TextSanitiser), ids("XDR103"), "", "NUL stripping: ReplaceAll(x, \"\\x00\", …)"),
	e("strings.Replace", KindFunc, r(TextSanitiser), ids("XDR103"), "", "NUL stripping with n < 0"),
	e("strings.IndexRune", KindFunc, r(TextSanitiser), ids("XDR103"), "", "NUL check"),
	e("strings.ContainsAny", KindFunc, r(TextSanitiser), ids("XDR103"), "", "NUL check"),
	e("bytes.ToValidUTF8", KindFunc, r(TextSanitiser), ids("XDR103"), "", "with NUL stripping"),
	e("bytes.ReplaceAll", KindFunc, r(TextSanitiser), ids("XDR103"), "", "NUL stripping"),
	e("bytes.IndexByte", KindFunc, r(TextSanitiser), ids("XDR103"), "", "NUL check"),
	e("bytes.Contains", KindFunc, r(TextSanitiser), ids("XDR103"), "", "NUL check"),
	e("bytes.ContainsRune", KindFunc, r(TextSanitiser), ids("XDR103"), "", "NUL check"),
	e("strconv.Quote", KindFunc, r(TextSanitiser), ids("XDR103"), "", "escapes to printable ASCII"),
	e("strconv.QuoteToASCII", KindFunc, r(TextSanitiser), ids("XDR103"), "", "escapes to printable ASCII"),
}

func init() {
	Entries = append(Entries, xdr1xxEntries...)
	for _, en := range xdr1xxEntries {
		index[en.Name] = append(index[en.Name], en)
	}
}

package driver

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"

	"github.com/stellar/go-stellar-sdk/xdr"
)

// ViewsProfile is the decode profile under which the driver reads the bytes through the SDK's zero-copy XDR
// views and view-based ingest extractors instead of (and compared with) the full decode. Only SDK versions that
// ship the views offer it: their version module calls RegisterViews with the view path (drivers/go/views).
const ViewsProfile = "views"

// ViewsReport is what the view path did with a ledger input (package drivers/go/views, Report).
type ViewsReport = struct {
	EntryPoint   string
	Err          error
	Ledgers      int
	Transactions int
	TxHashes     []string
	Mismatches   []string
}

var viewsDecoder interface {
	Validate(goName string, raw []byte) (bool, error)
	ErrorCode(err error, inputLen int) string
}

var viewsLedgers func(goName string, raw []byte, passphrase string, full []xdr.LedgerCloseMeta, fullBatch *xdr.LedgerCloseMetaBatch) ViewsReport

// RegisterViews installs the view path; the version module's main calls it before Main. ledgers adapts the
// views package's report type.
func RegisterViews(d interface {
	Validate(goName string, raw []byte) (bool, error)
	ErrorCode(err error, inputLen int) string
}, ledgers func(goName string, raw []byte, passphrase string, full []xdr.LedgerCloseMeta, fullBatch *xdr.LedgerCloseMetaBatch) ViewsReport) {
	viewsDecoder, viewsLedgers = d, ledgers
}

func viewsOffered() bool { return viewsDecoder != nil }

// dispatchViews answers a request under the views profile. L0 is the view validator (ValidateFull on the
// type's view and a consumed-length check), and L1 on a ledger runs the view extractors and compares them with the full decode; a
// difference is a diverge. The other levels have no view counterpart and answer as without a profile.
func dispatchViews(req *request) result {
	in := &req.Input
	if in.Kind != "xdr" || (req.Level != "L0" && req.Level != "L1") {
		return dispatchLevel(req)
	}
	raw, err := readInput(in)
	if err != nil {
		return protocolError("cannot read the input: " + err.Error())
	}
	_, goName, found := newValue(in.XDRType)
	if !found {
		return notApplicable("type_not_generated", "the driver does not decode "+in.XDRType)
	}
	if req.Level == "L0" {
		return viewsCodec(goName, raw)
	}
	if goName != "LedgerCloseMeta" && goName != "LedgerCloseMetaBatch" {
		return levelObject(in, raw)
	}
	return viewsLedger(in, goName, raw)
}

const viewEntry = "ValidateFull"

// viewEntryRe finds the entry point a mismatch names.
var viewEntryRe = regexp.MustCompile(`(?:ingest|xdr)\.[A-Za-z.]+|LedgerSequence|LedgerHash|PreviousLedgerHash|LedgerCloseTime(?:Ms)?`)

// viewsCodec is L0 under the views profile. When the view and the strict decode both accept, the answer is the
// strict L0 answer (so the cell is judged exactly like the unprofiled column); when only the view accepts, the
// view's canonical bytes are the input itself, so it reports them as its re-encoding.
func viewsCodec(goName string, raw []byte) result {
	known, verr := viewsDecoder.Validate(goName, raw)
	if !known {
		return notApplicable("type_not_generated", "go-stellar-sdk generates no view for "+goName)
	}
	_, strictRej := decodeStrict(goName, raw)
	if verr != nil {
		r := reject(viewsDecoder.ErrorCode(verr, len(raw)), viewEntry+"("+goName+"View)", verr)
		if strictRej == nil {
			r.Reason.Message = trim("the view refuses what xdr.SafeUnmarshal accepts: " + verr.Error())
		}
		return r
	}
	if strictRej == nil {
		return levelCodec(goName, raw)
	}
	sum := sha256.Sum256(raw)
	return result{Outcome: "ok", Actual: map[string]any{"consumed_bytes": len(raw), "reencoded_sha256": hex.EncodeToString(sum[:])}}
}

// viewsLedger is L1 on a ledger under the views profile.
func viewsLedger(in *input, goName string, raw []byte) result {
	v, strictRej := decodeStrict(goName, raw)
	var metas []xdr.LedgerCloseMeta
	var batch *xdr.LedgerCloseMetaBatch
	if strictRej == nil {
		if lcm, isLCM := v.(*xdr.LedgerCloseMeta); isLCM {
			metas = []xdr.LedgerCloseMeta{*lcm}
		} else {
			batch = v.(*xdr.LedgerCloseMetaBatch)
			metas = batch.LedgerCloseMetas
		}
	}
	rep := viewsLedgers(goName, raw, in.Passphrase, metas, batch)
	if strictRej != nil {
		if rep.Err != nil {
			return *strictRej
		}
		hashes := rep.TxHashes
		if hashes == nil {
			hashes = []string{}
		}
		obj := map[string]any{"transactions": rep.Transactions, "envelopes_parsed": 0, "tx_hashes": hashes}
		return result{Outcome: "diverge", Reason: &reason{Code: "other", EntryPoint: "ingest.ExtractLedgerTxParts",
			Message: trim("the view path accepts what xdr.SafeUnmarshal refuses: " + strictRej.Reason.Message)},
			Actual: map[string]any{"object": obj}}
	}
	if rep.Err != nil {
		r := reject(viewsDecoder.ErrorCode(rep.Err, len(raw)), rep.EntryPoint, rep.Err)
		r.Reason.Message = trim("the view path refuses what xdr.SafeUnmarshal accepts: " + rep.Err.Error())
		return r
	}
	full := ledgerObject(metas, in.Passphrase, in.Focus)
	if full.Protocol != "" || full.Outcome != "ok" || len(rep.Mismatches) == 0 {
		return full
	}
	entry := "views"
	if m := viewEntryRe.FindString(rep.Mismatches[0]); m != "" {
		entry = m
	}
	return result{Outcome: "diverge", Actual: full.Actual, Reason: &reason{Code: "other", EntryPoint: entry,
		Message: trim(fmt.Sprintf("the view path and the full decode disagree (%d): %s", len(rep.Mismatches), strings.Join(rep.Mismatches, "; ")))}}
}

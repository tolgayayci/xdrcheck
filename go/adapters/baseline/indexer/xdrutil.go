package indexer

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"

	"github.com/stellar/go-stellar-sdk/strkey"
	"github.com/stellar/go-stellar-sdk/xdr"
)

// Small XDR helpers. Every address is rendered with the SDK's strkey functions, at full length.

func accountStrkey(id xdr.AccountId) string { return id.Address() }

func ed25519Strkey(k xdr.Uint256) string {
	s, _ := strkey.Encode(strkey.VersionByteAccountID, k[:])
	return s
}

func contractStrkey(id [32]byte) string {
	s, _ := strkey.Encode(strkey.VersionByteContract, id[:])
	return s
}

func poolStrkey(id xdr.PoolId) string {
	s, _ := strkey.Encode(strkey.VersionByteLiquidityPool, id[:])
	return s
}

func claimableStrkey(id xdr.ClaimableBalanceId) string {
	s, _ := id.EncodeToStrkey()
	return s
}

// baseAddress is the base address of an ScAddress: the muxed information is dropped.
func baseAddress(a xdr.ScAddress) string {
	switch a.Type {
	case xdr.ScAddressTypeScAddressTypeAccount:
		return accountStrkey(*a.AccountId)
	case xdr.ScAddressTypeScAddressTypeContract:
		return contractStrkey(*a.ContractId)
	case xdr.ScAddressTypeScAddressTypeMuxedAccount:
		return ed25519Strkey(a.MuxedAccount.Ed25519)
	case xdr.ScAddressTypeScAddressTypeMuxedContract:
		return contractStrkey(a.MuxedContract.ContractId)
	case xdr.ScAddressTypeScAddressTypeLiquidityPool:
		return poolStrkey(*a.LiquidityPoolId)
	case xdr.ScAddressTypeScAddressTypeClaimableBalance:
		return claimableStrkey(*a.ClaimableBalanceId)
	}
	return ""
}

// muxedForm renders base + id as the M… (account) or W… (contract) strkey.
func muxedForm(base string, id uint64) string {
	switch {
	case strings.HasPrefix(base, "G"):
		m, err := xdr.MuxedAccountFromAccountId(base, id)
		if err != nil {
			return ""
		}
		s, _ := m.GetAddress()
		return s
	case strings.HasPrefix(base, "C"):
		raw, err := strkey.Decode(strkey.VersionByteContract, base)
		if err != nil {
			return ""
		}
		var b [40]byte
		copy(b[:32], raw)
		binary.BigEndian.PutUint64(b[32:], id)
		s, _ := strkey.Encode(strkey.VersionByteMuxedContract, b[:])
		return s
	}
	return ""
}

// muxedBase returns the base G… address of a MuxedAccount and its ID when it is muxed.
func muxedBase(m xdr.MuxedAccount) (string, *uint64) {
	if m.Type == xdr.CryptoKeyTypeKeyTypeMuxedEd25519 {
		id := uint64(m.Med25519.Id)
		return ed25519Strkey(m.Med25519.Ed25519), &id
	}
	return ed25519Strkey(*m.Ed25519), nil
}

func xdrHex(v interface{ MarshalBinary() ([]byte, error) }) string {
	b, err := v.MarshalBinary()
	if err != nil {
		return ""
	}
	return hex.EncodeToString(b)
}

// assetString is `native` or `CODE:ISSUER`.
func assetString(a xdr.Asset) string { return a.StringCanonical() }

// trustlineAsset returns the trustline's asset text (`liquidity_pool:<hex>` for pool shares) and its classic
// asset when it has one.
func trustlineAsset(t xdr.TrustLineAsset) (string, *xdr.Asset) {
	switch t.Type {
	case xdr.AssetTypeAssetTypePoolShare:
		return "liquidity_pool:" + hex.EncodeToString(t.LiquidityPoolId[:]), nil
	case xdr.AssetTypeAssetTypeNative:
		a := xdr.MustNewNativeAsset()
		return "native", &a
	}
	a := xdr.Asset{Type: t.Type, AlphaNum4: t.AlphaNum4, AlphaNum12: t.AlphaNum12}
	return a.StringCanonical(), &a
}

// parseAsset reads `native` or `CODE:ISSUER` (the SEP-11 text an event's last topic carries).
func parseAsset(s string) (xdr.Asset, bool) {
	if s == "native" {
		return xdr.MustNewNativeAsset(), true
	}
	code, issuer, ok := strings.Cut(s, ":")
	if !ok {
		return xdr.Asset{}, false
	}
	a, err := xdr.NewCreditAsset(code, issuer)
	return a, err == nil
}

func issuerKeyHex(a xdr.Asset) (string, bool) {
	switch a.Type {
	case xdr.AssetTypeAssetTypeCreditAlphanum4:
		k := a.AlphaNum4.Issuer.Ed25519
		return hex.EncodeToString(k[:]), true
	case xdr.AssetTypeAssetTypeCreditAlphanum12:
		k := a.AlphaNum12.Issuer.Ed25519
		return hex.EncodeToString(k[:]), true
	}
	return "", false
}

func sym(v xdr.ScVal) (string, bool) {
	if v.Type == xdr.ScValTypeScvSymbol && v.Sym != nil {
		return string(*v.Sym), true
	}
	return "", false
}

func i128(v xdr.ScVal) (*big.Int, bool) {
	if v.Type != xdr.ScValTypeScvI128 || v.I128 == nil {
		return nil, false
	}
	n := new(big.Int).Lsh(big.NewInt(int64(v.I128.Hi)), 64)
	return n.Add(n, new(big.Int).SetUint64(uint64(v.I128.Lo))), true
}

// entryKey is a comparable identity of a ledger entry, for pairing `state` with the following change.
func entryKey(e xdr.LedgerEntry) string {
	k, err := e.LedgerKey()
	if err != nil {
		return fmt.Sprintf("unkeyed:%p", &e)
	}
	b, _ := k.MarshalBinary()
	return string(b)
}

func keyBytes(k xdr.LedgerKey) string {
	b, _ := k.MarshalBinary()
	return string(b)
}

func entryTypeName(t xdr.LedgerEntryType) string {
	switch t {
	case xdr.LedgerEntryTypeAccount:
		return "account"
	case xdr.LedgerEntryTypeTrustline:
		return "trustline"
	case xdr.LedgerEntryTypeOffer:
		return "offer"
	case xdr.LedgerEntryTypeData:
		return "data"
	case xdr.LedgerEntryTypeClaimableBalance:
		return "claimable_balance"
	case xdr.LedgerEntryTypeLiquidityPool:
		return "liquidity_pool"
	case xdr.LedgerEntryTypeContractData:
		return "contract_data"
	case xdr.LedgerEntryTypeContractCode:
		return "contract_code"
	case xdr.LedgerEntryTypeConfigSetting:
		return "config_setting"
	case xdr.LedgerEntryTypeTtl:
		return "ttl"
	}
	return "unknown"
}

func isClassic(t xdr.LedgerEntryType) bool {
	switch t {
	case xdr.LedgerEntryTypeAccount, xdr.LedgerEntryTypeTrustline, xdr.LedgerEntryTypeOffer, xdr.LedgerEntryTypeData,
		xdr.LedgerEntryTypeClaimableBalance, xdr.LedgerEntryTypeLiquidityPool:
		return true
	}
	return false
}

func entrySponsor(e xdr.LedgerEntry) string {
	if e.Ext.V == 1 && e.Ext.V1 != nil && e.Ext.V1.SponsoringId != nil {
		return accountStrkey(*e.Ext.V1.SponsoringId)
	}
	return ""
}

func accountV2(a xdr.AccountEntry) *xdr.AccountEntryExtensionV2 {
	if a.Ext.V == 1 && a.Ext.V1 != nil && a.Ext.V1.Ext.V == 2 {
		return a.Ext.V1.Ext.V2
	}
	return nil
}

// strkeyType names an address's type from its strkey prefix (observation addresses[].type).
func strkeyType(s string) string {
	if s == "" {
		return ""
	}
	switch s[0] {
	case 'G':
		return "account"
	case 'M':
		return "muxed_account"
	case 'C':
		return "contract"
	case 'W':
		return "muxed_contract"
	case 'B':
		return "claimable_balance"
	case 'L':
		return "liquidity_pool"
	case 'P':
		return "signed_payload"
	case 'T':
		return "pre_auth_tx"
	case 'X':
		return "hash_x"
	}
	return ""
}

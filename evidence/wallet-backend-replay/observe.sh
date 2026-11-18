#!/usr/bin/env bash
# Observation queries for one run DB. Usage: observe.sh <db>
source "$(dirname "$0")/lib.sh"
D=$1
echo "-- cursors"; q "$D" "SELECT key, value FROM ingest_store ORDER BY key"
echo "-- row counts for ledger $LEDGER (transactions / operations / state_changes / tx_accounts / op_accounts)"
q "$D" "SELECT (SELECT count(*) FROM transactions WHERE ledger_number=$LEDGER),
  (SELECT count(*) FROM operations WHERE ledger_number=$LEDGER),
  (SELECT count(*) FROM state_changes WHERE ledger_number=$LEDGER),
  (SELECT count(*) FROM transactions_accounts), (SELECT count(*) FROM operations_accounts)" 2>&1
echo "-- current-state tables (native_balances / trustline_balances / trustline_assets / contract_tokens / sac_balances)"
q "$D" "SELECT (SELECT count(*) FROM native_balances),(SELECT count(*) FROM trustline_balances),(SELECT count(*) FROM trustline_assets),(SELECT count(*) FROM contract_tokens),(SELECT count(*) FROM sac_balances)" 2>&1
echo "-- target tx"
q "$D" "SELECT to_id, encode(hash,'hex'), result_code, ledger_number FROM transactions WHERE hash = decode('$TXHASH','hex')"
echo "-- SIGNER state changes in the target tx (signer_account_id raw hex, length)"
q "$D" "SELECT sc.state_change_category, sc.state_change_reason, encode(sc.account_id,'hex') acct,
   encode(sc.signer_account_id,'hex') signer_hex, octet_length(sc.signer_account_id) signer_len,
   sc.signer_weight_old, sc.signer_weight_new
 FROM state_changes sc JOIN transactions t ON sc.to_id = t.to_id
 WHERE t.hash = decode('$TXHASH','hex') AND sc.state_change_category='SIGNER'"
echo "-- all state changes of the target tx"
q "$D" "SELECT sc.state_change_category, sc.state_change_reason, octet_length(sc.account_id), octet_length(sc.signer_account_id)
 FROM state_changes sc JOIN transactions t ON sc.to_id = t.to_id WHERE t.hash = decode('$TXHASH','hex') ORDER BY sc.state_change_id"

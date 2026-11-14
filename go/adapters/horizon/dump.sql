-- Raw dump of every Horizon history table filled by `db reingest range`, one JSON object per line.
-- Internal ids (history_accounts, history_assets, history_claimable_balances, history_liquidity_pools) are
-- resolved to their natural keys, and every operation id is split into (ledger, tx_order, op_order) by the
-- TOID layout (ledger << 32 | tx_order << 12 | op_order; orders are 1-based). Large XDR columns of
-- history_transactions are replaced by their MD5 so dumps of the same ledger can be diffed cheaply.
-- Integers are emitted by Postgres with every digit; readers must not parse them as float64.
\pset footer off
WITH acc AS (SELECT id, address FROM history_accounts),
     ast AS (SELECT id, CASE WHEN asset_type = 'native' THEN 'native' ELSE asset_code || ':' || asset_issuer END AS asset FROM history_assets)
SELECT x::text FROM (
  SELECT jsonb_build_object('table', 'history_ledgers', 'ledger', l.sequence) || (to_jsonb(l) - 'created_at' - 'updated_at' - 'id' - 'importer_version') AS x
    FROM history_ledgers l
  UNION ALL
  SELECT jsonb_build_object('table', 'history_transactions', 'ledger', t.ledger_sequence, 'tx_order', t.application_order,
           'tx_envelope_md5', md5(t.tx_envelope), 'tx_meta_md5', md5(t.tx_meta), 'tx_fee_meta_md5', md5(t.tx_fee_meta))
         || (to_jsonb(t) - 'created_at' - 'updated_at' - 'id' - 'tx_envelope' - 'tx_meta' - 'tx_fee_meta')
    FROM history_transactions t
  UNION ALL
  SELECT jsonb_build_object('table', 'history_operations', 'ledger', o.id >> 32, 'tx_order', (o.id >> 12) & 1048575,
           'op_order', o.id & 4095, 'op_id', o.id::text, 'type', o.type, 'details', o.details,
           'source_account', o.source_account, 'source_account_muxed', o.source_account_muxed, 'is_payment', o.is_payment)
    FROM history_operations o
  UNION ALL
  SELECT jsonb_build_object('table', 'history_effects', 'ledger', e.history_operation_id >> 32,
           'tx_order', (e.history_operation_id >> 12) & 1048575, 'op_order', e.history_operation_id & 4095,
           'op_id', e.history_operation_id::text, 'order', e."order", 'type', e.type, 'account', a.address,
           'address_muxed', e.address_muxed, 'details', e.details)
    FROM history_effects e LEFT JOIN acc a ON a.id = e.history_account_id
  UNION ALL
  SELECT jsonb_build_object('table', 'history_trades', 'ledger', t.history_operation_id >> 32,
           'tx_order', (t.history_operation_id >> 12) & 1048575, 'op_order', t.history_operation_id & 4095,
           'op_id', t.history_operation_id::text, 'order', t."order", 'ledger_closed_at', t.ledger_closed_at,
           'base_account', ba.address, 'base_asset', bs.asset, 'base_amount', t.base_amount,
           'counter_account', ca.address, 'counter_asset', cs.asset, 'counter_amount', t.counter_amount,
           'base_is_seller', t.base_is_seller, 'price_n', t.price_n, 'price_d', t.price_d,
           'base_offer_id', t.base_offer_id, 'counter_offer_id', t.counter_offer_id,
           'base_liquidity_pool', bl.liquidity_pool_id, 'counter_liquidity_pool', cl.liquidity_pool_id,
           'liquidity_pool_fee', t.liquidity_pool_fee, 'trade_type', t.trade_type,
           'rounding_slippage', t.rounding_slippage, 'base_is_exact', t.base_is_exact)
    FROM history_trades t
    LEFT JOIN acc ba ON ba.id = t.base_account_id LEFT JOIN acc ca ON ca.id = t.counter_account_id
    LEFT JOIN ast bs ON bs.id = t.base_asset_id LEFT JOIN ast cs ON cs.id = t.counter_asset_id
    LEFT JOIN history_liquidity_pools bl ON bl.id = t.base_liquidity_pool_id
    LEFT JOIN history_liquidity_pools cl ON cl.id = t.counter_liquidity_pool_id
  UNION ALL
  -- trade aggregation buckets (1 minute), filled by reingest; keyed by the bucket's open ledger
  SELECT jsonb_build_object('table', 'history_trades_60000', 'ledger', g.open_ledger_toid >> 32,
           'base_asset', bs.asset, 'counter_asset', cs.asset) || (to_jsonb(g) - 'base_asset_id' - 'counter_asset_id')
    FROM history_trades_60000 g LEFT JOIN ast bs ON bs.id = g.base_asset_id LEFT JOIN ast cs ON cs.id = g.counter_asset_id
  UNION ALL
  SELECT jsonb_build_object('table', 'history_transaction_participants', 'ledger', p.history_transaction_id >> 32,
           'tx_order', (p.history_transaction_id >> 12) & 1048575, 'account', a.address)
    FROM history_transaction_participants p LEFT JOIN acc a ON a.id = p.history_account_id
  UNION ALL
  SELECT jsonb_build_object('table', 'history_operation_participants', 'ledger', p.history_operation_id >> 32,
           'tx_order', (p.history_operation_id >> 12) & 1048575, 'op_order', p.history_operation_id & 4095,
           'account', a.address)
    FROM history_operation_participants p LEFT JOIN acc a ON a.id = p.history_account_id
  UNION ALL
  SELECT jsonb_build_object('table', 'history_transaction_claimable_balances', 'ledger', p.history_transaction_id >> 32,
           'tx_order', (p.history_transaction_id >> 12) & 1048575, 'claimable_balance', c.claimable_balance_id)
    FROM history_transaction_claimable_balances p LEFT JOIN history_claimable_balances c ON c.id = p.history_claimable_balance_id
  UNION ALL
  SELECT jsonb_build_object('table', 'history_operation_claimable_balances', 'ledger', p.history_operation_id >> 32,
           'tx_order', (p.history_operation_id >> 12) & 1048575, 'op_order', p.history_operation_id & 4095,
           'claimable_balance', c.claimable_balance_id)
    FROM history_operation_claimable_balances p LEFT JOIN history_claimable_balances c ON c.id = p.history_claimable_balance_id
  UNION ALL
  SELECT jsonb_build_object('table', 'history_transaction_liquidity_pools', 'ledger', p.history_transaction_id >> 32,
           'tx_order', (p.history_transaction_id >> 12) & 1048575, 'liquidity_pool', c.liquidity_pool_id)
    FROM history_transaction_liquidity_pools p LEFT JOIN history_liquidity_pools c ON c.id = p.history_liquidity_pool_id
  UNION ALL
  SELECT jsonb_build_object('table', 'history_operation_liquidity_pools', 'ledger', p.history_operation_id >> 32,
           'tx_order', (p.history_operation_id >> 12) & 1048575, 'op_order', p.history_operation_id & 4095,
           'liquidity_pool', c.liquidity_pool_id)
    FROM history_operation_liquidity_pools p LEFT JOIN history_liquidity_pools c ON c.id = p.history_liquidity_pool_id
) d;

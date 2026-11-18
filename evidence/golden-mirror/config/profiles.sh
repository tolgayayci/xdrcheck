# Meta-affecting flag profiles . Each prints the seven meta flags (+ tx-submission diagnostics) for core.cfg.
# golden-trust : what core's test harness used for golden 4c437318f87437c5 ("Trustline stellar asset contract"):
#                getTestConfig (test.cpp L885 BACKFILL_RESTORE_META=true, L893-897 diag=true when capturing)
#                + test overrides InvokeHostFunctionTests.cpp L219-225 (diag, EMIT_CLASSIC_EVENTS, BACKFILL_STELLAR_ASSET_EVENTS)
# test-default : getTestConfig alone (diag + BACKFILL_RESTORE_META) — goldens of tests that do not override flags (e.g. CAP-0084, unused auth)
# design-core-default : an early draft of the generator's default node configuration (diag only)
# lake         : the seven flags all true (public data lake / the local-core run)
profile_flags() {
  local d=false c=false b=false r=false s1=false l1=false t=false
  case "$1" in
    golden-trust) d=true c=true b=true r=true ;;
    test-default) d=true r=true ;;
    design-core-default) d=true ;;
    lake) d=true c=true b=true r=true s1=true l1=true t=true ;;
    *) echo "bad profile $1" >&2; return 2 ;;
  esac
  printf 'ENABLE_SOROBAN_DIAGNOSTIC_EVENTS=%s\nENABLE_DIAGNOSTICS_FOR_TX_SUBMISSION=%s\nEMIT_SOROBAN_TRANSACTION_META_EXT_V1=%s\nEMIT_LEDGER_CLOSE_META_EXT_V1=%s\nEMIT_CLASSIC_EVENTS=%s\nBACKFILL_STELLAR_ASSET_EVENTS=%s\nBACKFILL_RESTORE_META=%s\n' $d $t $s1 $l1 $c $b $r
}

#!/usr/bin/env python3
"""Summarise an `xdrcheck replay` report: per row the class, the expectation verdict, the fact counts and every missing or
wrong fact with its differing fields. usage: report_facts.py <report-dir>"""
import json, sys

d = json.load(open(sys.argv[1] + '/report.json', encoding='utf-8'))
for r in d['rows']:
    ev = r.get('evidence') or {}
    f = ev.get('facts') or {}
    rep = r.get('replay') or {}
    print('%s  %s·%s  %s' % (r['entry'], rep.get('class'), rep.get('qualifier'), r.get('expectation')))
    if 'ingest' in ev:
        sig = ev['ingest']['signals']
        print('  ingest %s, last ledger %s, exit %s' % (ev['ingest']['status'], ev['ingest']['last_ledger'], sig.get('exit_code')))
    if f:
        print('  facts: ' + ', '.join('%s %s' % (k, f[k]) for k in ('matched', 'missing', 'wrong', 'not_applicable', 'extra_in_scope', 'forbidden')))
    for x in f.get('missing_or_wrong', []):
        diffs = '; '.join('%s expected %s, observed %s' % (y['field'], y['expected'], y['observed']) for y in x.get('diffs', []))
        print('  %s %s: %s (%s)%s' % (x['status'], x['kind'], x['label'], x.get('reason', ''), ' — ' + diffs if diffs else ''))
    if r.get('known_divergence'):
        print('  known divergence: %s (%s)' % (r['known_divergence']['reference'], r['known_divergence'].get('status')))

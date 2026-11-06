import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';

// Load the browser module without needing package.json or third-party packages.
const source = await readFile(new URL('../static/log-parser.js', import.meta.url), 'utf8');
const {parseLine, filterRows, summarize, displayBytes, displayTime, requestPath, topCounts, distribution, formatLogTime} = await import('data:text/javascript;base64,' + Buffer.from(source).toString('base64'));

test('log time comes from the line, including cleaned rows and key:value lines', () => {
  assert.equal(formatLogTime('15/Oct/2026:01:10:22 +0800'), '2026/10/15 01:10:22');
  assert.equal(formatLogTime('2026-10-15T23:59:58+08:00'), '2026/10/15 23:59:58');
  assert.equal(formatLogTime(''), '');
  const kv = parseLine('remote_addr:1.2.3.4,time_local:[15/Oct/2026:09:17:23 +0800],request:GET / HTTP/1.1,status:200,upstream_status:200');
  assert.equal(formatLogTime(kv.time), '2026/10/15 09:17:23');
  const cleaned = parseLine(JSON.stringify({remote_addr: '1.2.3.4', time_local: '15/Oct/2026:01:00:00 +0800', request: 'GET / HTTP/1.1',
    status: 200, count: 3, last_time: '15/Oct/2026:22:00:00 +0800', clean_date: '2026-10-15'}));
  assert.equal(formatLogTime(cleaned.time), '2026/10/15 01:00:00');
  assert.equal(formatLogTime(cleaned.lastTime), '2026/10/15 22:00:00');
});

test('combined and common access formats, IPv6, Unicode and missing bytes', () => {
  const raw = '2001:db8::1 - - [13/Oct/2026:16:02:03 +0800] "GET /中文?x=1 HTTP/1.1" 503 1024 "-" "browser"';
  const row = parseLine(raw);
  assert.equal(row.ip, '2001:db8::1'); assert.equal(row.status, 503);
  assert.equal(row.bytes, 1024); assert.equal(row.request, 'GET /中文?x=1 HTTP/1.1');
  assert.equal(row.raw, raw); assert.equal(row.userAgent, 'browser');
  const common = parseLine('127.0.0.1 - user [13/Oct/2026:16:02:03 +0800] "GET / HTTP/1.0" 204 -');
  assert.equal(common.status, 204); assert.equal(common.bytes, null);
});

test('Nginx error severity and client IP', () => {
  const row = parseLine('2026/10/13 16:02:03 [error] 21#21: *4 upstream timed out, client: 10.0.0.2, server: test');
  assert.equal(row.level, 'error'); assert.equal(row.ip, '10.0.0.2');
  assert.equal(row.time, '2026/10/13 16:02:03'); assert.equal(row.status, null);
  const warn = parseLine('2026/10/13 16:02:03 [warn] a warning');
  assert.equal(summarize([row, warn], 'error.log').errors, 1);
});

test('JSON log formats and invalid JSON preserve original text', () => {
  const raw = JSON.stringify({remote_addr:'10.0.0.2',time_iso8601:'2026-10-13T16:02:03+08:00',request_uri:'/api',status:'404',body_bytes_sent:'42'});
  const row = parseLine(raw);
  assert.equal(row.status, 404); assert.equal(row.bytes, 42); assert.equal(row.request, '/api');
  assert.equal(parseLine('{invalid json').request, '{invalid json');
  const attack = '<img src=x onerror=alert(1)>';
  assert.equal(parseLine(attack).raw, attack); assert.equal(parseLine(attack).request, attack);
});

test('search and status filters operate on loaded rows without deleting duplicates', () => {
  const good = parseLine('10.0.0.2 - - [13/Oct/2026:16:02:03 +0800] "GET /API HTTP/1.1" 200 42');
  const bad = parseLine('10.0.0.3 - - [13/Oct/2026:16:02:03 +0800] "GET /API HTTP/1.1" 500 42');
  const rows = [good, bad, bad];
  assert.equal(filterRows(rows, '/api', '5').length, 2);
  assert.deepEqual(summarize(rows, 'access.log'), {lines:3,errors:2,ips:2});
  assert.equal(filterRows(rows, 'missing', 'all').length, 0);
});

test('byte and timestamp displays retain dates', () => {
  assert.equal(displayBytes(null), '—'); assert.equal(displayBytes(0), '0 B');
  assert.equal(displayBytes(1024), '1.0 KB');
  assert.equal(displayTime('13/Oct/2026:16:02:03 +0800'), '13 Oct 2026 16:02:03');
});

test('combined error filter, trimmed search and insight helpers', () => {
  const line = (ip, path, status) => parseLine(`${ip} - - [13/Oct/2026:16:02:03 +0800] "GET ${path}?q=1 HTTP/1.1" ${status} 42`);
  const rows = [line('10.0.0.1', '/a', 200), line('10.0.0.2', '/b', 404), line('10.0.0.2', '/b', 502), line('10.0.0.3', '/c', 301)];
  assert.equal(filterRows(rows, '', 'err').length, 2);
  assert.equal(filterRows(rows, '  10.0.0.2 ', 'all').length, 2);
  assert.equal(requestPath(rows[0].request), '/a');
  assert.equal(requestPath('upstream timed out'), '');
  assert.deepEqual(topCounts(rows.map(row => row.ip), 2), [['10.0.0.2', 2], ['10.0.0.1', 1]]);
  assert.deepEqual(distribution(rows, 'access.log'), {2: 1, 3: 1, 4: 1, 5: 1, other: 0});
  const errors = ['error', 'warn', 'notice', 'crit'].map(level => parseLine(`2026/10/13 16:02:03 [${level}] x`));
  assert.deepEqual(distribution(errors, 'error.log'), {error: 2, warn: 1, info: 1, other: 0});
});

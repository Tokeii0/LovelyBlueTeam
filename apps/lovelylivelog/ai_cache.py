"""Conservative, persistent reuse of complete, byte-identical normal POST requests.

Only the verdict is reused. Original events must still be stored, counted and committed
by the caller. New patterns and bursts require a fresh model judgment. The persistence
callbacks accept a SHA-256 key and a JSON-compatible entry; they never receive bodies.
"""
from collections import deque
from dataclasses import dataclass, field
import hashlib
import json
import math
import re
import threading
import time


CACHE_VERSION = 1


@dataclass(frozen=True)
class CacheCandidate:
    key: str
    ip: str
    event_at: float


@dataclass
class CacheLease:
    candidate: CacheCandidate
    state: str  # owner, hit, or timeout; timeout leaves the events pending.
    verdict: dict | None = None
    token: object = field(default=None, repr=False)


def normal_cache_candidate(events, config, prompt_version):
    """Return a key only for one complete, low-volume POST pattern from one source.

    Fingerprints are the ORIGINAL request digests, before redaction and truncation.
    Neither dynamic fields nor ciphertext hashes are removed. Counts and exact time
    spans are part of the key, so increasing frequency cannot reuse a prior verdict.
    """
    if not events:
        return None
    contexts, starts, ends, count = [], [], [], 0
    for event in events:
        meta = event.get('bodyMeta', {})
        fingerprint = event.get('_requestFingerprint', '')
        source = event.get('_sourceKey') or ('website:' + str(event['website']) if event.get('website') else '')
        at, last = event.get('recordedAt'), event.get('_lastRecordedAt', event.get('recordedAt'))
        n = event.get('_count', 1)
        if (not event.get('_post_body') or event.get('method') != 'POST' or not source or
                event.get('truncated') or meta.get('truncated') or event.get('_historical') or
                event.get('_daily') or event.get('timeReliable') is False or
                meta.get('state') not in ('plain', 'decoded', 'decrypted', 'restored') or
                type(meta.get('unresolved')) is not int or meta['unresolved'] != 0 or
                not re.fullmatch(r'[0-9a-f]{64}', fingerprint) or
                type(event.get('status')) is not int or not 200 <= event['status'] < 300 or
                type(at) not in (int, float) or type(last) not in (int, float) or
                not math.isfinite(at) or not math.isfinite(last) or last < at or
                type(n) is not int or n < 1 or not event.get('ip') or 'requestBody' not in event):
            return None
        count += n
        contexts.append([event['ip'], source, fingerprint, event['method'], event.get('target', ''),
                         event['status'], event.get('userAgent', ''), meta, event['requestBody']])
        starts.append(at); ends.append(last)
    if count > 3 or any(context != contexts[0] for context in contexts[1:]):
        return None
    credential = hashlib.sha256(str(config.get('key') or '').encode()).hexdigest()
    context = [CACHE_VERSION, config.get('provider', 'deepseek'), config.get('model', ''),
               config.get('baseUrl', '').rstrip('/'), credential, prompt_version, contexts[0], count,
               float(max(ends)) - float(min(starts))]
    key = hashlib.sha256(json.dumps(context, ensure_ascii=False, sort_keys=True,
                                    separators=(',', ':')).encode()).hexdigest()
    return CacheCandidate(key, events[0]['ip'], max(ends))


def _normal_verdict(value, ip):
    if (not isinstance(value, dict) or value.get('ip') != ip or value.get('is_attack') is not False or
            value.get('attack_type') != 'none' or type(value.get('confidence')) not in (int, float) or
            not math.isfinite(value['confidence']) or not 0 <= value['confidence'] <= 1 or
            not isinstance(value.get('reason'), str) or not value['reason']):
        return None
    return {name: value[name] for name in ('ip', 'is_attack', 'confidence', 'attack_type', 'reason')} | {'evidence_ids': []}


class NormalDecisionCache:
    def __init__(self, read, write, *, ttl=300, max_hits=3, min_reuse_gap=10, clock=time.time):
        self.read, self.write = read, write
        self.ttl, self.max_hits, self.min_reuse_gap, self.clock = ttl, max_hits, min_reuse_gap, clock
        self.condition = threading.Condition()
        self.flights, self.ip_hits = {}, {}
        self.last_prune = clock()

    def acquire(self, candidate, *, timeout=65):
        """Reserve fresh work, reuse a normal verdict, or wait for its single owner.

        A timeout MUST NOT start a duplicate request: leave those events pending.
        A maximum of three cached judgments per IP per five minutes and a minimum
        gap between events force repeated or accelerating traffic back to the model.
        """
        deadline = time.monotonic() + timeout
        with self.condition:
            while True:
                now = self.clock()
                if now - self.last_prune >= self.ttl or now < self.last_prune:
                    self.ip_hits = {ip: hits for ip, hits in self.ip_hits.items()
                                    if hits and hits[-1] > now - self.ttl}
                    self.last_prune = now
                hits = self.ip_hits.get(candidate.ip, deque())
                while hits and hits[0] <= now - self.ttl:
                    hits.popleft()
                entry = self.read(candidate.key)
                verdict = _normal_verdict(entry.get('verdict'), candidate.ip) if isinstance(entry, dict) else None
                if (verdict and entry.get('version') == CACHE_VERSION and
                        all(type(entry.get(name)) in (int, float) and math.isfinite(entry[name])
                            for name in ('created', 'expires', 'event_at')) and
                        0 <= now - entry.get('created', now + 1) < self.ttl and
                        now < entry.get('expires', 0) and
                        type(entry.get('hits')) is int and 0 <= entry['hits'] < self.max_hits and
                        len(hits) < self.max_hits and
                        candidate.event_at - entry.get('event_at', candidate.event_at) >= self.min_reuse_gap):
                    updated = {**entry, 'hits': entry['hits'] + 1, 'event_at': candidate.event_at}
                    self.write(candidate.key, updated)
                    hits.append(now)
                    self.ip_hits[candidate.ip] = hits
                    return CacheLease(candidate, 'hit', verdict)
                if candidate.key not in self.flights:
                    token = object()
                    self.flights[candidate.key] = token
                    return CacheLease(candidate, 'owner', token=token)
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return CacheLease(candidate, 'timeout')
                self.condition.wait(remaining)

    def finish(self, lease, verdict):
        """Persist only a validated normal verdict, releasing waiters on every path."""
        with self.condition:
            if lease.state != 'owner' or self.flights.get(lease.candidate.key) is not lease.token:
                return False
            try:
                normal = _normal_verdict(verdict, lease.candidate.ip)
                if normal is None:
                    return False
                now = self.clock()
                self.write(lease.candidate.key, {'version': CACHE_VERSION, 'created': now,
                    'expires': now + self.ttl, 'hits': 0, 'event_at': lease.candidate.event_at, 'verdict': normal})
                return True
            finally:
                del self.flights[lease.candidate.key]
                self.condition.notify_all()

    def abort(self, lease):
        with self.condition:
            if lease.state == 'owner' and self.flights.get(lease.candidate.key) is lease.token:
                del self.flights[lease.candidate.key]
                self.condition.notify_all()

    def get_or_analyze(self, candidate, analyze, *, timeout=65):
        """Optional one-IP wrapper returning (verdict, reused), without duplicate calls."""
        lease = self.acquire(candidate, timeout=timeout)
        if lease.state == 'hit':
            return lease.verdict, True
        if lease.state == 'timeout':
            raise TimeoutError('相同请求正在分析，已保留日志等待下一轮。')
        try:
            verdict = analyze()
            self.finish(lease, verdict)
            return verdict, False
        finally:
            self.abort(lease)

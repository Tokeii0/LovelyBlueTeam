"""Compress identical requests without losing rows or their occurrence counts."""
from datetime import datetime
import json

# Column order of one prompt row; SYSTEM_PROMPT describes the same layout to the model.
ROW_FIELDS = ('id', 'pattern', 'method', 'target', 'status', 'occurrences', 'first_s', 'last_s', 'ua', 'source', 'truncated')


def request_groups(events):
    groups = {}
    for event in events:
        # Include the original-request digest so redaction/truncation cannot merge
        # different payloads into an apparently identical harmless request.
        key = (event.get('_sourceKey',event.get('website', 0)), event['ip'], event.get('_requestFingerprint') or
               (event.get('method', ''), event['target'], event.get('status', 0), event.get('userAgent', '')))
        groups.setdefault(key, []).append(event)
    return list(groups.values())


def compact_events(events):
    result = []
    for index, group in enumerate(request_groups(events)):
        samples = [group[0]] if len(group) == 1 else [group[0], group[-1]]
        timestamps = [e['recordedAt'] for e in group if e.get('recordedAt') is not None] or [0]
        last = [e.get('_lastRecordedAt') or e['recordedAt'] for e in group if e.get('recordedAt') is not None] or [0]
        for sample in samples:
            item = {k: v for k, v in sample.items() if not k.startswith('_')}
            # Rows from daily cleaning already aggregate many identical requests.
            item.update(patternId=f'p{index}', occurrences=sum(e.get('_count', 1) for e in group),
                        firstRecordedAt=min(timestamps), lastRecordedAt=max(last))
            result.append(item)
    return result


def prompt_payload(events):
    """The model input for one batch, grouped by client IP.

    Each sample of compact_events() repeats its User-Agent, source and four time fields; most of
    a request was that repetition. Here every IP lists its User-Agents and sources once and each
    sample is one row of ROW_FIELDS with times as seconds after base_time. Short L1, L2, ...
    evidence labels map back to the real IDs in compact_events(events)."""
    samples = compact_events(events)
    times = [s['firstRecordedAt'] for s in samples if s.get('firstRecordedAt')]
    base = min(times) if times else 0
    offset = lambda value: int(round(value - base)) if value and base else 0
    sources, clients, bodies = [], {}, {}
    for index, sample in enumerate(samples, 1):
        if 'requestBody' in sample:
            bodies[f'L{index}'] = {'requestBody': sample['requestBody'], 'bodyMeta': sample.get('bodyMeta', {})}
        source = sample.get('server') or (f"website {sample['website']}" if sample.get('website') else '')
        if source not in sources:
            sources.append(source)
        client = clients.setdefault(sample['ip'], {'ip': sample['ip'], 'user_agents': [], 'rows': []})
        agent = sample.get('userAgent') or ''
        if agent not in client['user_agents']:
            client['user_agents'].append(agent)
        client['rows'].append([f'L{index}', int(sample['patternId'][1:]), sample.get('method', ''), sample.get('target', ''),
                               sample.get('status', 0), sample['occurrences'], offset(sample['firstRecordedAt']),
                               offset(sample['lastRecordedAt']), client['user_agents'].index(agent), sources.index(source),
                               int(bool(sample.get('truncated')))])
    payload = {'base_time': datetime.fromtimestamp(base).strftime('%Y-%m-%d %H:%M:%S') if base else '',
               'row_fields': list(ROW_FIELDS), 'sources': sources, 'clients': list(clients.values())}
    if bodies:
        payload['bodies'] = bodies
    return payload, samples


def prompt_size(events):
    return len(json.dumps(prompt_payload(events)[0], ensure_ascii=False))


def plan_batches(events, max_patterns=32, max_characters=18000, max_ips=16, measure=None):
    scopes = {}
    for event in events:
        scopes.setdefault(event.get('_analysisScope','panel'),[]).append(event)
    if len(scopes) > 1:
        return [batch for source in scopes.values() for batch in plan_batches(source,max_patterns,max_characters,max_ips,measure)]
    # Keep one client's request variants together as far as the bounded request
    # size allows, instead of letting a busy client fill every independent batch.
    by_ip = {}
    for group in request_groups(events):
        by_ip.setdefault(group[0]['ip'], []).append(group)
    batches, batch, ips, size, patterns = [], [], set(), 0, 0
    for groups in by_ip.values():
        for group in groups:
            # Compact prompts share their source/UA tables and envelope across groups.
            # Measure the whole candidate rather than repeatedly charging that overhead.
            cost = measure(batch + group) if measure is not None else len(json.dumps(compact_events(group), ensure_ascii=False))
            candidate_size = cost if measure is not None else size + cost
            ip = group[0]['ip']
            if batch and (patterns >= max_patterns or candidate_size > max_characters or len(ips | {ip}) > max_ips):
                batches.append(batch); batch, ips, size, patterns = [], set(), 0, 0
                if measure is not None:
                    cost = measure(group)
            batch.extend(group); ips.add(ip); size = cost if measure is not None else size + cost; patterns += 1
    if batch:
        batches.append(batch)
    return batches

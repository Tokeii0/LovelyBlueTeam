"""Bound and redact the already decoded POST body received from LovelyLog."""
import json
import re

SENSITIVE = re.compile(r'token|password|passwd|pwd|secret|authorization|cookie|session|api.?key|patient|identity|id.?card|id.?number|cert.?(?:no|num)|phone|mobile|credential|jwt|openid|unionid|out_trade_no|transaction_id|card.?(?:no|num)|empi|unique.?id|user.?id|user.?name|account.?id|auth.?code|^operator$|^tk$|real.?name|^name$|address|birthday|birthdate|^age$|^sex$|^gender$|diagnos|diag_name|chief_complaint|^sign$|姓名|证件|身份证|手机号|住院号|就诊号|病案号', re.I)
INLINE = re.compile(r'''(?i)(["']?(?:token|password|passwd|pwd|secret|authorization|cookie|session|api[_-]?key|patient[_-]?(?:id|name)|phone|mobile)["']?\s*[:=]\s*)(?:"(?:\\.|[^"\\])*"|'[^']*'|[^\s&<>,;}]+)''')
XML = re.compile(r'(?is)(<(?:token|password|passwd|pwd|secret|patient_?id|patient_?name|phone|mobile|id_?card|id_?number|cert_?no|openid|unionid|card_?(?:no|number)|account_?id|auth_?code|sign)\b[^>]*>)(?:<!\[CDATA\[.*?\]\]>|[^<]*)(</[^>]+>)')
IDENTIFIER = re.compile(r'(?i)\b(?:1[3-9][0-9]{9}|[0-9]{17}[0-9x])\b')


def redact(value, depth=0):
    if depth > 20:
        return '[depth limit]'
    if isinstance(value, dict):
        return {k: '[REDACTED]' if SENSITIVE.search(k) else redact(v, depth+1) for k, v in value.items()}
    if isinstance(value, list):
        return [redact(v, depth+1) for v in value]
    if isinstance(value, str):
        if value.lstrip().startswith(('{', '[')):
            try:
                return redact(json.loads(value), depth+1)
            except (ValueError, RecursionError):
                pass
        return XML.sub(r'\1[REDACTED]\2', INLINE.sub(r'\1[REDACTED]', IDENTIFIER.sub('[REDACTED-ID]', value)))
    return value


def normalized_body(data):
    if 'decoded_body' not in data:
        return {}
    raw = json.dumps(redact(data['decoded_body']), ensure_ascii=False, separators=(',', ':'))
    limited = len(raw) > 6000
    body = raw[:6000] + '…[truncated]' if limited else json.loads(raw)
    unresolved = data.get('body_unresolved', 0)
    return {'requestBody': body,
            'bodyMeta': {'state': str(data.get('decode_state', 'unknown'))[:32],
                         'format': str(data.get('decode_format', ''))[:80],
                         'message': str(data.get('decode_message', ''))[:300],
                         'contentType': str(data.get('content_type', ''))[:160],
                         'unresolved': unresolved if type(unresolved) is int and 0 <= unresolved <= 20000 else 0,
                         'truncated': limited or data.get('body_truncated') is True},
            '_post_body': True}

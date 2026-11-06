const ACCESS = /^(\S+)\s+(\S+)\s+(\S+)\s+\[([^\]]+)\]\s+"([^"\r\n]*)"\s+(\d{3})\s+(\d+|-)(?:\s+"([^"\r\n]*)"\s+"([^"\r\n]*)")?/;
const ERROR = /^(\d{4}\/\d{2}\/\d{2}\s+\d{2}:\d{2}:\d{2})\s+\[([^\]]+)\]\s*(.*)$/;
// remote_addr:IP,time_local:[...],request:GET / HTTP/1.1,status:200,upstream_status:...
const KEY_VALUE = /^remote_addr:([^,]*),time_local:\[([^\]]*)\],request:([\s\S]*),status:(\d{3}),upstream_status:/;

export function parseLine(raw) {
  const match = raw.match(ACCESS);
  if (match) {
    const [, ip, , , time, request, status, bytes, referer, userAgent] = match;
    return {raw, time, ip, request, status: Number(status), bytes: bytes === '-' ? null : Number(bytes), referer, userAgent, level: ''};
  }
  const pairs = raw.match(KEY_VALUE);
  if (pairs) {
    const [, ip, time, request, status] = pairs;
    return {raw, time, ip, request, status: Number(status), bytes: null, referer: '', userAgent: '', level: ''};
  }
  const error = raw.match(ERROR);
  if (error) {
    const ip = error[3].match(/(?:^|[,\s])client:\s*([^,\s]+)/)?.[1] || '';
    return {raw, time: error[1], ip, request: error[3], status: null, bytes: null, level: error[2]};
  }
  if (raw.trimStart().startsWith('{')) {
    try {
      const data = JSON.parse(raw);
      const value = data.status ?? data.status_code;
      const status = /^\d{3}$/.test(String(value)) ? Number(value) : null;
      const bytes = data.body_bytes_sent ?? data.bytes_sent ?? data.bytes;
      return {raw, time: String(data.time_local ?? data.time_iso8601 ?? data.timestamp ?? data.time ?? ''),
        ip: String(data.remote_addr ?? data.client_ip ?? data.ip ?? ''),
        request: String(data.request ?? data.request_uri ?? data.uri ?? data.message ?? raw),
        status, bytes: bytes !== undefined && /^\d+$/.test(String(bytes)) ? Number(bytes) : null,
        level: String(data.level ?? ''),
        // Daily-cleaned rows stand for `count` identical requests of that day.
        count: Number.isInteger(data.count) && data.count > 1 ? data.count : 1,
        lastTime: String(data.last_time ?? '')};
    } catch { /* Keep custom formats readable as raw text. */ }
  }
  return {raw, time: '', ip: '', request: raw, status: null, bytes: null, level: ''};
}

const MONTHS = {Jan: 1, Feb: 2, Mar: 3, Apr: 4, May: 5, Jun: 6, Jul: 7, Aug: 8, Sep: 9, Oct: 10, Nov: 11, Dec: 12};
const pad = value => String(value).padStart(2, '0');
// "15/Oct/2026:01:10:22 +0800" or ISO time -> "2026/10/15 01:10:22"; other text is returned as is.
export function formatLogTime(text) {
  const nginx = String(text || '').match(/^(\d{2})\/(\w{3})\/(\d{4}):(\d{2}:\d{2}:\d{2})/);
  if (nginx && MONTHS[nginx[2]]) return `${nginx[3]}/${pad(MONTHS[nginx[2]])}/${nginx[1]} ${nginx[4]}`;
  const iso = String(text || '').match(/^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}:\d{2}:\d{2})/);
  if (iso) return `${iso[1]}/${iso[2]}/${iso[3]} ${iso[4]}`;
  return String(text || '');
}

export function summarize(rows, kind) {
  const errors = kind === 'error.log' ? rows.filter(row => /^(error|crit|alert|emerg)$/i.test(row.level)).length
    : rows.filter(row => row.status >= 400 && row.status <= 599).length;
  return {lines: rows.length, errors, ips: new Set(rows.map(row => row.ip).filter(Boolean)).size};
}

function matchStatus(row, status) {
  if (status === 'all') return true;
  if (row.status === null) return false;
  const group = Math.floor(row.status / 100);
  return status === 'err' ? group === 4 || group === 5 : String(group) === status;
}

export function filterRows(rows, query, status) {
  const needle = query.trim().toLocaleLowerCase();
  return rows.filter(row => (!needle || row.raw.toLocaleLowerCase().includes(needle)) && matchStatus(row, status));
}

// "GET /a/b?x=1 HTTP/1.1" -> "/a/b"; non-request text yields ''.
export function requestPath(request) {
  const match = request.match(/^[A-Z]{3,10}\s+(\S+)/);
  return match ? match[1].split('?')[0] : '';
}

export function topCounts(values, limit = 5) {
  const counts = new Map();
  for (const value of values) if (value) counts.set(value, (counts.get(value) || 0) + 1);
  return [...counts].sort((a, b) => b[1] - a[1] || (a[0] < b[0] ? -1 : 1)).slice(0, limit);
}

export function distribution(rows, kind) {
  if (kind === 'error.log') {
    const groups = {error: 0, warn: 0, info: 0, other: 0};
    for (const row of rows) {
      const level = row.level.toLowerCase();
      groups[/^(error|crit|alert|emerg)$/.test(level) ? 'error' : level === 'warn' ? 'warn' : /^(notice|info|debug)$/.test(level) ? 'info' : 'other']++;
    }
    return groups;
  }
  const groups = {2: 0, 3: 0, 4: 0, 5: 0, other: 0};
  for (const row of rows) {
    const group = row.status === null ? 'other' : Math.floor(row.status / 100);
    groups[group in groups ? group : 'other']++;
  }
  return groups;
}

export function displayTime(value) {
  const match = value.match(/^(\d{2})\/(\w{3})\/(\d{4}):(\d{2}:\d{2}:\d{2})/);
  return match ? `${match[1]} ${match[2]} ${match[3]} ${match[4]}` : value || '—';
}

export function displayBytes(value) {
  if (value === null) return '—';
  if (value < 1024) return `${value} B`;
  if (value < 1048576) return `${(value / 1024).toFixed(1)} KB`;
  return `${(value / 1048576).toFixed(1)} MB`;
}

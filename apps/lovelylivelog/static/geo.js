// IP 归属地: any element with data-geo-ip gets an offline ip2region location label after it.
// Page modules only mark their IP cells; this module batches the lookups and keeps a cache,
// so re-rendered tables never ask twice for the same address.
const cache = new Map();
const waiting = new Set();
let timer = null;

function label(node, text) {
  let tag = node.querySelector(':scope > .geo-tag');
  if (!text) { tag?.remove(); return; }
  if (!tag) { tag = document.createElement('span'); tag.className = 'geo-tag'; node.append(tag); }
  tag.textContent = text;
  tag.title = `IP 归属地（离线库 ip2region）：${text}`;
}

function paint(root = document) {
  const nodes = root.querySelectorAll ? root.querySelectorAll('[data-geo-ip]') : [];
  for (const node of [root, ...nodes]) {
    const ip = node.dataset?.geoIp;
    if (!ip) continue;
    if (cache.has(ip)) label(node, cache.get(ip));
    else waiting.add(ip);
  }
  if (waiting.size && !timer) timer = setTimeout(flush, 120);
}

async function flush() {
  timer = null;
  const ips = [...waiting].slice(0, 1000);
  ips.forEach(ip => waiting.delete(ip));
  try {
    const response = await fetch('/api/geo', {method: 'POST', headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({ips}), signal: AbortSignal.timeout(15000)});
    if (!response.ok) return;  // Platform without GeoIP: leave addresses as they are.
    const {geo} = await response.json();
    for (const ip of ips) cache.set(ip, geo[ip] || '');
  } catch { ips.forEach(ip => cache.set(ip, '')); }
  paint();
}

new MutationObserver(records => {
  for (const record of records) {
    for (const node of record.addedNodes) if (node.nodeType === 1) paint(node);
    if (record.type === 'attributes') paint(record.target);
  }
}).observe(document.body, {childList: true, subtree: true, attributes: true, attributeFilter: ['data-geo-ip']});
paint();

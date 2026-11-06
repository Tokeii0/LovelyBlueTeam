'use strict';
const $ = id => document.getElementById(id);
const names = {plain:'明文',decoded:'编码还原',restored:'日志关联还原',decrypted:'解密成功',partial:'部分还原',encrypted:'待配置解密',failed:'解析失败',empty:'正文缺失'};
const state = {paused:false,before:0,pages:[],page:null,selected:new Set(),entry:null,preview:'',pane:'decoded',status:null,busy:false,refreshing:false};
let searchTimer, toastTimer;
let queryVersion=0, refreshQueued=false;
function toast(text) { $('toast').textContent=text;$('toast').hidden=false;clearTimeout(toastTimer);toastTimer=setTimeout(()=>$('toast').hidden=true,4500); }
async function api(path,body) {
  const response=await fetch(path,{cache:'no-store',signal:AbortSignal.timeout(body?100000:12000),...(body===undefined?{}:{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)})});
  const data=await response.json();if(!response.ok)throw new Error(data.error||'请求失败');return data;
}
function element(tag,text,className) { const node=document.createElement(tag);if(text!==undefined)node.textContent=String(text);if(className)node.className=className;return node; }
function time(value) { const date=new Date(value);return Number.isNaN(date.getTime())?value||'—':date.toLocaleString('zh-CN',{hour12:false}); }
function formatBody(text) { try{return JSON.stringify(JSON.parse(text),null,2);}catch{return text||'日志中没有记录正文。';} }
function localMode() { return state.status?.analysis_mode==='local'; }
function renderStatus(data) {
  state.status=data;const c=data.counts||{},collector=data.collector;
  $('total').textContent=(c.total||0).toLocaleString();$('readable').textContent=((c.plain||0)+(c.decrypted||0)+(c.decoded||0)+(c.restored||0)).toLocaleString();
  $('decrypted-count').textContent=`解密 ${c.decrypted||0} · 日志关联还原 ${c.restored||0}`;
  for(const name of ['failed','empty'])$(name).textContent=(c[name]||0).toLocaleString();
  $('encrypted').textContent=((c.encrypted||0)+(c.partial||0)).toLocaleString();$('unresolved-count').textContent=`待解密 ${c.encrypted||0} · 部分还原 ${c.partial||0}`;
  $('source').textContent=collector.log_path;$('sync-status').textContent=`最后采集 ${time(collector.checked_at)} · 本轮新增 ${collector.last_added||0} 条`;
  $('connection-dot').className=`dot ${collector.error?'failed':'ready'}`;$('connection-text').textContent=collector.error?'采集异常':state.paused?'显示已暂停':'正在采集';
  $('notice').hidden=!collector.error;$('notice').textContent=collector.error||'';
  const local=localMode();
  $('model-status').textContent=local?`LovelyLog 本地规则：${data.local_rules_version} · 不调用外部模型`:data.ai_configured?`文字分析模型：${data.ai_model}`:'文字分析模型尚未配置';
  $('flow-text').textContent=local?'正文还原 → 本地检测 → 人工复核 → 按需手动封禁':'正文还原 → 脱敏 → Livelog AI → WAF 黑名单 → AF 同步';
  document.querySelector('[data-pane="preview"]').textContent=local?'本机脱敏预览':'AI 送审预览';
  document.querySelector('[data-pane="ai"]').textContent=local?'规则复核报告':'AI 报告';
  const defense=data.defense||{};
  const platformMode=defense.platform_analysis_mode==='ai'?'Livelog 平台：AI 模式':defense.platform_analysis_mode==='local'?'Livelog 平台：本地模式':'Livelog 平台模式待确认';
  $('defense-title').textContent=local?(defense.error?'LovelyLog 本地检测连接异常':'LovelyLog 本地规则 · 仅人工封禁'):defense.enabled?(defense.error?'自动防护连接异常':`自动 AI ${defense.ai_enabled?'已开启':'已暂停'} · WAF 自动拉黑 ${defense.auto_block?'已开启':'已关闭'} · AF 同步 ${defense.af_enabled?'已开启':'已关闭'}`):'自动防护尚未配置';
  $('defense-detail').textContent=local?`${defense.error||'仅 LovelyLog 来源使用本地规则，命中后请人工确认是否封禁'} · ${platformMode}${defense.enabled?` · 已提交 ${defense.submitted||0} 条 · 等待回执 ${defense.pending||0} 条`:''}`:defense.enabled?`${defense.error||`沿用 Livelog 阈值 ${Math.round((defense.threshold||0)*100)}% 及白名单`} · 已送审 ${defense.submitted||0} 条 · 等待回执 ${defense.pending||0} 条${defense.ai_error?' · AI：'+defense.ai_error:''}${defense.af_error?' · AF：'+defense.af_error:''}`:'配置 defense 后，新请求会自动送入 Livelog 的 AI 和封禁流程。';
  $('defense-title').className=defense.error?'risk':'';
  if(defense.livelog_url)$('livelog-link').href=defense.livelog_url;
  $('ai-hint').textContent=local?'点击本地规则复核查看命中规则与证据。无命中不代表安全，未解密内容无法完整检查。是否封禁由你在 Livelog 人工确认。':defense.enabled?'自动 AI 与封禁结果显示在“AI 报告”；补充文字分析可单独查看此条或所选请求的详细解释。':`手动补充分析模型：${data.ai_model||'未配置'}。`;
  const profiles=data.profiles||[];$('profile-count').textContent=`${profiles.length} 条配置`;
  $('profile-list').replaceChildren(...profiles.map(p=>{const row=element('div',`${p.name} · ${p.mode}`,'profile-row');row.append(element('code',`${p.path_regex} · ${p.mode==='BACKEND-LOG'?p.lookup_entries+' 条密文索引':'密钥指纹 '+p.key_fingerprint}`));return row;}));
  if(!profiles.length)$('profile-list').append(element('p','尚未配置解密规则，明文仍可正常查看。','muted'));
  for(const key of data.key_files||[]){const row=element('div',`${key.name} · ${key.bytes} 字节${key.decoded_bytes?' · Base64 解码后 '+key.decoded_bytes+' 字节':''}`,'profile-row');row.append(element('p',key.message,key.format==='unrecognized'?'risk':'muted'));$('profile-list').append(row);}
  updateButtons();
}
function updateButtons() {
  $('selected-count').textContent=state.selected.size?`已选 ${state.selected.size} 条`:'每页最多 100 条';
  const available=state.status?.analysis_available??state.status?.ai_configured;
  $('analyze-selected').disabled=state.busy||!available||!state.selected.size;
  $('analyze').disabled=state.busy||!state.entry||!available;
  $('redecode').disabled=state.busy||!state.entry;
  $('analyze').textContent=state.busy?'正在复核…':localMode()?'本地规则复核':'补充文字分析';
  $('analyze-selected').textContent=localMode()?'本地复核所选':'补充分析所选';
  $('copy').disabled=$('export').disabled=!state.entry;
}
function renderRows() {
  const page=state.page;if(!page)return;
  $('page-info').textContent=`本页 ${page.entries.length} 条${page.scanned>page.entries.length?` · 已检索 ${page.scanned.toLocaleString()} 条`:''}`;
  $('history-label').textContent=state.before?`历史第 ${state.pages.length} 页`:'最新记录';$('older').disabled=!page.has_more;
  $('no-rows').hidden=!!page.entries.length;$('no-rows').textContent=page.scanned?'没有匹配的记录。可调整筛选或继续翻页。':'尚无记录。程序会从文件末尾读取已有请求，随后增量采集。';
  const fragment=document.createDocumentFragment();
  for(const row of page.entries) {
    const tr=document.createElement('tr');tr.dataset.id=row.id;tr.tabIndex=0;tr.classList.toggle('selected',state.entry?.id===row.id);
    const select=document.createElement('td'),box=document.createElement('input');box.type='checkbox';box.checked=state.selected.has(row.id);box.setAttribute('aria-label',`选择记录 ${row.id}`);
    box.addEventListener('click',event=>event.stopPropagation());box.addEventListener('change',()=>{if(box.checked&&state.selected.size>=10){box.checked=false;toast('每次最多选择 10 条');return;}box.checked?state.selected.add(row.id):state.selected.delete(row.id);updateButtons();});select.append(box);
    const origin=document.createElement('td');origin.append(element('div',time(row.time||row.received),'time'),element('div',row.ip||'—','ip'));
    const request=document.createElement('td');request.append(element('div',`${row.method||'POST'} ${row.uri||'（无请求路径）'}`,'request'));
    request.append(element('div',row.decoded.text||row.decoded.message||row.content_type,'preview'));
    const verdict=document.createElement('td');verdict.append(element('span',names[row.decoded.state]||row.decoded.state,`badge ${row.decoded.state}`),element('span',`HTTP ${row.status||'—'} · #${row.id}`,'http'));
    if(row.findings?.length)verdict.append(element('div',`${row.findings.length} 项可疑特征`,'risk'));
    if(row.defense)verdict.append(element('div',defenseLabel(row.defense),row.defense.decision?.attack?'risk':'http'));
    tr.append(select,origin,request,verdict);tr.addEventListener('click',()=>loadEntry(row.id));tr.addEventListener('keydown',event=>{if(event.key==='Enter'&&event.target===tr)loadEntry(row.id);});fragment.append(tr);
  }
  $('rows').replaceChildren(fragment);updateButtons();
}
async function refresh() {
  if(state.refreshing){refreshQueued=true;return;}state.refreshing=true;$('refresh').disabled=true;const version=queryVersion;
  try {
    const params=new URLSearchParams({q:$('search').value.trim(),state:$('decode-filter').value,suspicious:$('suspicious').checked,before:state.before||''});
    const [status,page]=await Promise.all([api('/api/status'),api(`/api/entries?${params}`)]);if(version!==queryVersion)return;state.page=page;renderStatus(status);renderRows();
    if(!state.entry&&page.entries.length)await loadEntry(page.entries[0].id);else if(state.entry&&!state.busy)await loadEntry(state.entry.id);
  }catch(error){$('notice').hidden=false;$('notice').textContent=error.name==='TimeoutError'?'本机服务响应超时，稍后自动重试。':error.message;$('connection-dot').className='dot failed';$('connection-text').textContent='连接中断';}
  finally{state.refreshing=false;$('refresh').disabled=false;if(refreshQueued){refreshQueued=false;refresh();}}
}
function defenseLabel(receipt) {
  if(receipt.block?.state==='unblocked')return '已解封';
  const d=receipt.decision;if(d){if(['listed','existing'].includes(d.state))return 'WAF 已加黑';if(d.state==='protected')return '命中保护名单';if(d.provider==='local')return d.attack?'规则命中 · 等待人工复核':'本地规则未命中';return d.attack?'历史分析发现攻击 · 待复核':'历史分析未确认攻击';}
  return (localMode()?{pending:'等待本地检测',analyzed:'已有检测回执',filtered:'规则过滤',unparsed:'日志无法解析',ignored:'未检测',expired:'已过实时窗口',unknown:'等待回执'}:{pending:'等待自动 AI',analyzed:'自动 AI 已分析',filtered:'规则过滤',unparsed:'日志无法解析',ignored:'未进入 AI',expired:'已过实时窗口',unknown:'等待回执'})[receipt.ai_state]||'已提交';
}
function automaticReport(e) {
  const receipt=e.defense;if(!receipt)return '尚未送入 Livelog 检测队列。';
  const d=receipt.decision;
  let report=`检测回执：${defenseLabel(receipt)}\n提交时间：${time(receipt.sent_at)}\n回执时间：${time(receipt.checked_at)}`;
  if(receipt.decoded_sha256&&receipt.decoded_sha256!==e.decoded.sha256)report+=`\n本地解析结果已更新；此回执基于此前送审版本，可对当前内容做${localMode()?'本地规则复核':'补充文字分析'}。`;
  if(d)report+=`\n\nIP 线索：${d.attack?'发现可疑特征':'未确认攻击'}${d.provider==='local'?'':`\n历史分析置信度：${Math.round(d.confidence*100)}%`}\n类型：${d.category}\n${d.provider==='local'?'本地规则':'历史模型'}：${d.provider} / ${d.model}\n理由：${d.reason}\n处置：${d.state}${d.detail?' · '+d.detail:''}\n此条是否被引用为攻击证据：${d.cited?'是':'否'}${d.historical?'\n历史流量记录。':''}${d.provider==='local'?'\n本地命中仅作人工复核线索，无命中不代表安全。':''}`;
  return report;
}
function paneText() {
  const e=state.entry;if(!e)return '';
  const review=localMode()?(e.local_report?'\n\n'+e.local_report:'\n\n点击“本地规则复核”查看当前内容的规则与证据。'):(e.ai_report?'\n\n补充文字分析\n'+e.ai_report:'');
  return {decoded:e.decoded.text||e.decoded.message||'没有解析结果。',body:formatBody(e.body),raw:e.raw,preview:state.preview,ai:automaticReport(e)+review}[state.pane]||'';
}
function renderDetail() {
  const e=state.entry;if(!e)return;
  $('detail-placeholder').hidden=true;$('detail-main').hidden=false;$('detail-title').textContent=`记录 #${e.id}`;
  const facts=[['时间',time(e.time||e.received)],['来源 IP',e.ip||'—'],['请求',`${e.method||'POST'} ${e.uri}`],['Content-Type',e.content_type||'—'],['HTTP / 上游',`${e.status||'—'} / ${e.upstream||'—'}`]];
  $('facts').replaceChildren(...facts.flatMap(([key,value])=>[element('dt',key),element('dd',value)]));
  const d=e.decoded;$('decode-message').className=`decode-message${['encrypted','failed','empty','partial'].includes(d.state)?' problem':''}`;
  $('decode-message').textContent=`${names[d.state]||d.state}${d.profile?` · ${d.profile}`:''}${d.format?` · ${d.format}`:''}${d.bytes?` · ${d.bytes.toLocaleString()} 字节`:''}${d.steps?.length?'\n'+d.steps.join(' → '):''}${d.message?'\n'+d.message:''}${d.sha256?'\nSHA-256 '+d.sha256:''}`;
  if(d.fields?.length)$('decode-message').textContent+='\n\n'+d.fields.map(f=>`${f.path} · ${names[f.state]||f.state}${f.profile?' · '+f.profile:''}${f.steps?.length?' · '+f.steps.join(' → '):''}${f.message?'\n'+f.message:''}${f.source?'\n来源：'+f.source:''}`).join('\n');
  $('findings').replaceChildren(...(e.findings||[]).map(item=>{const node=element('div',`${item.rule||item.category} · ${item.description}`,'finding');node.append(element('code',item.evidence));if(item.source)node.append(element('small',item.source));return node;}));
  $('detail-text').textContent=paneText();
  document.querySelectorAll('[data-pane]').forEach(button=>{const active=button.dataset.pane===state.pane;button.classList.toggle('active',active);button.setAttribute('aria-selected',String(active));});updateButtons();
}
let selectedRequest=0;
async function loadEntry(id) {
  const current=++selectedRequest;
  try{const data=await api(`/api/entry?id=${id}`);if(current!==selectedRequest)return;state.entry=data.entry;state.preview=data.automatic_preview?`${localMode()?'送入本机 Livelog 的脱敏内容':'自动防护脱敏载荷'}\n${formatBody(data.automatic_preview)}\n\n${localMode()?'本地数据脱敏预览':'补充文字分析载荷'}\n${data.ai_preview}`:data.ai_preview;renderDetail();renderRows();}
  catch(error){toast(error.message);}
}
async function analyze(ids) {
  if(state.busy||!ids.length)return;state.busy=true;updateButtons();toast(localMode()?`正在本地复核 ${ids.length} 条请求…`:`正在分析 ${ids.length} 条请求，可能需要几十秒…`);
  try{const data=await api('/api/analyze',{ids});if(state.entry&&ids.includes(state.entry.id)){await loadEntry(state.entry.id);state.pane='ai';renderDetail();}toast(data.provider==='local'?'本地复核完成，未调用外部模型':`${data.cached?'已复用本地报告，未调用模型':'分析已完成'} · ${data.model}`);await refresh();}
  catch(error){toast(error.name==='TimeoutError'?'复核请求超时，原始记录已保留。':error.message);}
  finally{state.busy=false;updateButtons();}
}
function resetPage(){queryVersion++;state.before=0;state.pages=[];state.selected.clear();refresh();}
$('search').addEventListener('input',()=>{clearTimeout(searchTimer);searchTimer=setTimeout(resetPage,250);});
$('decode-filter').addEventListener('change',resetPage);$('suspicious').addEventListener('change',resetPage);
$('refresh').addEventListener('click',refresh);$('pause').addEventListener('click',()=>{state.paused=!state.paused;$('pause').textContent=state.paused?'继续显示':'暂停显示';if(state.status)renderStatus(state.status);if(!state.paused)refresh();});
$('live').addEventListener('click',resetPage);$('older').addEventListener('click',()=>{if(!state.page?.has_more)return;queryVersion++;state.pages.push(state.before);state.before=state.page.before;refresh();});
document.querySelectorAll('[data-pane]').forEach(button=>button.addEventListener('click',()=>{state.pane=button.dataset.pane;renderDetail();}));
$('copy').addEventListener('click',async()=>{try{await navigator.clipboard.writeText(paneText());toast('内容已复制');}catch{toast('复制失败，可选中正文后手动复制。');}});
$('export').addEventListener('click',()=>{if(!state.entry)return;const blob=new Blob([JSON.stringify(state.entry,null,2)],{type:'application/json;charset=utf-8'}),url=URL.createObjectURL(blob),link=document.createElement('a');link.href=url;link.download=`LovelyLog_${state.entry.id}.json`;link.click();setTimeout(()=>URL.revokeObjectURL(url),1000);});
$('analyze').addEventListener('click',()=>state.entry&&analyze([state.entry.id]));$('analyze-selected').addEventListener('click',()=>analyze([...state.selected]));
$('redecode').addEventListener('click',async()=>{if(!state.entry||state.busy)return;const id=state.entry.id;try{await api('/api/redecode',{ids:[id]});await loadEntry(id);await refresh();toast('已用当前配置重新解析');}catch(error){toast(error.message);}});
document.addEventListener('visibilitychange',()=>{if(!document.hidden&&!state.paused&&!state.before)refresh();});
setInterval(()=>{if(!document.hidden&&!state.paused&&!state.before)refresh();},3000);
refresh();

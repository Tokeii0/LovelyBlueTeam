package main

const loginPage = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<title>示例机构集成平台接口文档</title>
<style>
body{margin:0;background:#e9e2df;font-family:"Microsoft YaHei",sans-serif}
.card{width:340px;margin:0 auto;background:#fff;box-shadow:0 2px 8px rgba(0,0,0,.08)}
.main{margin-top:19%%;padding:28px 26px 18px}
.title{text-align:center;font-size:21px;font-weight:700;color:#333}
.badge{display:inline-block;background:#e54c3c;color:#fff;font-size:10px;border-radius:2px;padding:1px 4px;vertical-align:top;margin-left:4px}
.inp{width:100%%;border:none;border-bottom:1px solid #d8d8d8;padding:12px 4px;font-size:13px;outline:none;box-sizing:border-box}
.inp::placeholder{color:#b5b5b5}
.btn{width:86%%;margin:18px auto 10px;display:block;background:#1a66b3;color:#fff;border:none;border-radius:20px;padding:9px 0;font-size:14px;cursor:pointer}
.ver{text-align:center;color:#aaa;font-size:11px;margin:10px 0 4px}
.err{color:#d43f3a;font-size:12px;text-align:center;min-height:14px;margin-top:6px}
.auth{margin-top:6px;padding:10px 26px 12px;font-size:12px;color:#666}
.auth b{font-size:13px;color:#444;display:block;margin-bottom:6px}
.auth label{color:#4a7fc1}
.foot{position:fixed;bottom:14px;width:100%%;text-align:center;font-size:12px;color:#555}
</style>
</head>
<body>
<div class="card main">
  <div class="title">示例机构集成平台接口文档<span class="badge">V1.0</span></div>
  <p>隔离演示：demo / demo；请勿输入真实凭据。</p><form method="post" action="/login">
    <input class="inp" name="username" placeholder="demo" autocomplete="off">
    <input class="inp" name="password" type="password" placeholder="demo">
    <button class="btn" type="submit">登 录</button>
    <div class="err">%s</div>
  </form>
  <div class="ver">系统版本号：V1.0 DEMO</div>
</div>
<div class="card auth">
  <b>认证方式</b>
  <label>◉ 账号密码</label>
</div>
<div class="foot">Lovely Blue Team · 演示界面</div>
<footer style="text-align:center;padding:12px">SYNTHETIC · 示例机构 · 非真实业务系统</footer></body>
</html>`

// portalPage：左侧分组导航 + 右侧文档内容的标准接口文档站布局。
const portalPage = `<!DOCTYPE html>
<html lang="zh-CN">
<head><meta charset="utf-8"><title>集成平台 · 接口文档中心</title>
<style>
*{box-sizing:border-box}
body{margin:0;background:#f4f5f7;font-family:"Microsoft YaHei",sans-serif;color:#333;font-size:13px}
.hd{height:48px;background:#1a66b3;color:#fff;display:flex;align-items:center;padding:0 20px}
.hd .t{font-size:15px;font-weight:700}
.hd .u{margin-left:auto;font-size:12px;opacity:.9}
.hd .av{border-radius:50%%;vertical-align:middle;margin-right:7px}
.hd a{color:#fff;margin-left:14px;font-size:12px}
.lay{display:flex;min-height:calc(100vh - 48px)}
.side{width:230px;background:#fff;border-right:1px solid #e3e6ea;padding:14px 0;flex-shrink:0}
.side .g{font-size:11px;color:#9aa4af;padding:10px 18px 4px;letter-spacing:1px}
.side a{display:block;padding:7px 18px;color:#4d5766;text-decoration:none;font-size:13px;border-left:3px solid transparent}
.side a:hover{background:#f0f6fc;color:#1a66b3}
.side a.on{color:#1a66b3;background:#eaf3fc;border-left-color:#1a66b3}
.side .tip{margin:14px 16px 0;padding:8px 10px;background:#fdf6ec;border:1px solid #f0dfc0;border-radius:3px;font-size:11px;color:#9a6d25;line-height:1.6}
.main{flex:1;padding:22px 34px;max-width:960px}
.doc h4{font-size:14px;color:#1a66b3;margin:18px 0 6px}
.doc p{line-height:1.8;margin:6px 0}
.doc table{width:100%%;border-collapse:collapse;margin:8px 0}
.doc td,.doc th{border:1px solid #e3e6ea;padding:6px 10px;font-size:12px;text-align:left;font-weight:normal}
.doc th{background:#f0f4f8}
.doc pre{background:#2d2d2d;color:#e6e6e6;padding:10px;font-size:12px;border-radius:3px;overflow:auto}
.doc code{background:#f0f2f5;padding:1px 4px;border-radius:2px;font-size:12px}
.doc pre code{background:none;padding:0}
.doc ul,.doc ol{line-height:1.9;padding-left:22px}
.doc .note{background:#fdf6ec;border-left:3px solid #e6a23c;padding:8px 12px;margin:10px 0;color:#8a6d3b;font-size:12px;line-height:1.7}
.dt{font-size:20px;font-weight:700;padding-bottom:10px;border-bottom:1px solid #e3e6ea;margin-bottom:4px}
.dm{color:#98a2ad;font-size:11px;margin-bottom:14px}
a{color:#1a66b3}
</style></head>
<body>
<div class="hd">
  <span class="t">示例机构集成平台接口文档 · 文档中心</span>
  <span class="u"><svg class="av" width="24" height="24" viewBox="0 0 24 24"><circle cx="12" cy="12" r="12" fill="#0d4f8f"/><circle cx="12" cy="9.5" r="4" fill="#fff"/><path d="M4.5 21c1.6-4.2 4.3-6 7.5-6s5.9 1.8 7.5 6" fill="#fff"/></svg>%s ｜ 令牌有效期至 %s</span>
  <form method="post" action="/logout"><button type="submit">退出</button></form>
</div>
<div class="lay">
<div class="side">
%s
<div class="tip">互联网出口的对外地址与接口白名单由演练管理员统一登记管理。<br>如需开通请联系<b>演练管理员</b>。</div>
</div>
<div class="main">
<div class="dt">%s</div>
<div class="dm">版本 %s ｜ 更新日期 %s</div>
<div class="doc">%s</div>
</div>
</div>
<footer style="text-align:center;padding:12px">SYNTHETIC · 示例机构 · 非真实业务系统</footer></body></html>`

// ===================== 文档 =====================

type docEnt struct {
	Name, Title, Ver, Date string
	Body                   string // HTML 片段
}

type navGroup struct {
	Group string
	Docs  []docEnt
}

var navTree = []navGroup{
	{"接入指南", []docEnt{
		{"overview", "平台简介与接入流程", "V3.6.1", "2026-01-08", overviewDoc},
		{"env-checklist", "上线前环境核查表", "V3.6.1", "2026-02-03", checklistDoc},
		{"agent-deploy-guide", "UDS Agent 客户端部署与配置说明", "V3.6.1", "2026-02-11", deployDoc},
		{"jwt-auth-guide", "演示会话说明", "V3.6.1", "2026-01-20", authDoc},
	}},
	{"接口规范", []docEnt{
		{"uds-interface-spec", "统一数据源接口规范", "V3.6.1", "2026-02-18", specDoc},
		{"error-code", "错误码与返回包络说明", "V3.6.1", "2026-01-29", errDoc},
		{"data-format", "数据格式与编码约定", "V3.6.1", "2026-02-06", formatDoc},
		{"idempotent", "幂等与重试约定", "V3.6.1", "2026-02-24", idempotentDoc},
		{"security-baseline", "接口安全基线", "V3.6.1", "2026-01-16", secDoc},
	}},
	{"业务接口文档", []docEnt{
		{"patient-service-guide", "PatientService 患者主索引", "V3.6.1", "2026-01-22", patientDoc},
		{"his-order-guide", "HisService 医嘱与处方", "V3.6.1", "2026-02-02", orderDoc},
		{"lis-channel-guide", "LisService 检验报告回传", "V3.6.1", "2026-01-26", lisDoc},
		{"pacs-index-guide", "PacsService 影像索引", "V3.6.1", "2026-01-30", pacsDoc},
		{"emr-doc-guide", "EmrService 病历文书", "V3.6.1", "2026-02-09", emrDoc},
		{"inpatient-guide", "住院业务接口说明", "V3.6.1", "2026-02-16", inpatientDoc},
		{"outpatient-guide", "门诊业务接口说明", "V3.6.1", "2026-02-19", outpatientDoc},
		{"operation-guide", "手术麻醉接口说明", "V3.6.1", "2026-02-23", operationDoc},
		{"nursing-guide", "护理文书接口说明", "V3.6.1", "2026-02-27", nursingDoc},
		{"blood-guide", "输血管理接口说明", "V3.6.1", "2026-03-02", bloodDoc},
		{"pathology-guide", "病理报告接口说明", "V3.6.1", "2026-03-06", pathologyDoc},
		{"physical-guide", "体检业务接口说明", "V3.6.1", "2026-03-09", physicalDoc},
		{"insurance-guide", "医保结算接口说明", "V3.6.1", "2026-03-12", insuranceDoc},
		{"charge-recon-guide", "收费对账接口说明（试用）", "V3.6.1", "2026-03-05", chargeDoc},
		{"dict-sync-guide", "基础字典同步说明", "V3.6.1", "2026-02-13", dictDoc},
	}},
	{"通道与运维", []docEnt{
		{"channel-mech", "通道机制与队列说明", "V3.6.1", "2026-01-27", mechDoc},
		{"channel-troubleshoot", "通道联调排错手册", "V3.6.1", "2026-02-05", troubleDoc},
		{"upgrade-note", "版本升级注意事项", "V3.6.1", "2026-02-12", upgradeDoc},
		{"monitor-guide", "运行监控指标说明", "V3.6.1", "2026-02-20", monitorDoc},
		{"changelog", "平台变更记录", "V3.6.1", "持续更新", changelogDoc},
	}},
	{"源码说明", []docEnt{
		{"download", "源码与离线演示", "V3.6.1", "2026-03-15", downloadDoc},
	}},
}

var docIndex = func() map[string]*docEnt {
	m := map[string]*docEnt{}
	for i := range navTree {
		for j := range navTree[i].Docs {
			m[navTree[i].Docs[j].Name] = &navTree[i].Docs[j]
		}
	}
	return m
}()

// ===================== 文档正文（HTML）=====================

const overviewDoc = `<h4>Lovely UDS 合成演练门户</h4><p>保留原项目的文档导航和接口示例，供蓝队验证访问监测与响应流程。全部机构、通道、患者和地址为示例，不代表真实系统。</p><h4>使用方式</h4><ol><li>用 demo / demo 进入文档门户。</li><li>在源码仓库 honeypots 目录运行 <code>go run ./uds-agent status --json</code>。</li><li>用 patient、lis、invoke 等命令生成合成接口响应；所有命令都离线运行。</li></ol><p>门户仅实现文档、演示会话和健康检查 HTTP 接口；业务方法由本地 CLI 模拟。补充业务设计文档不等于已有实现。</p><p>门户不提供可执行文件下载，也不要求访问者安装程序。</p>`

const deployDoc = `<p>这是隔离演练门户，使用合成通道和示例接口。源码仓库包含离线 CLI；部署步骤见仓库说明。</p><pre>go run ./uds-agent status --json</pre><p>不会连接业务系统或安装服务。</p>`

const authDoc = `<p>演示凭据为 demo / demo，仅用于浏览合成文档。会话为随机临时标记，30 分钟过期，不具备任何业务系统权限。</p><p>POST /api/auth/token 可返回本门户的演示会话。不要提交真实账号或密码。</p>`

const specDoc = `
<h4>返回包络</h4>
<pre>{"errCode":0,"errMsg":"","data":{...}}</pre>
<p>errCode：0 正常 / 404 接口未注册 / 500 通道异常（详见<a href="/portal?doc=error-code">错误码说明</a>）</p>
<h4>已注册接口方法</h4>
<table>
<tr><th>接口方法</th><th>说明</th><th>参数</th></tr>
<tr><td>PatientService.GetPatientInfo</td><td>病人信息查询</td><td>patId</td></tr>
<tr><td>PatientService.GetVisitList</td><td>就诊记录列表</td><td>patId</td></tr>
<tr><td>HisService.GetOrderList</td><td>医嘱列表</td><td>patId</td></tr>
<tr><td>LisService.GetReportList</td><td>检验报告列表</td><td>barcode [+item]</td></tr>
<tr><td>LisService.GetResultDetail</td><td>检验结果明细</td><td>barcode</td></tr>
<tr><td>PacsService.GetImageIndex</td><td>影像索引</td><td>patId</td></tr>
<tr><td>EmrService.GetDocList</td><td>病历文书列表</td><td>patId</td></tr>
<tr><td>ChannelService.ListAll</td><td>通道清单</td><td>-</td></tr>
<tr><td>QueueService.PendingStat</td><td>待传队列统计</td><td>-</td></tr>
<tr><td>SystemService.GetServerTime</td><td>中心端时间</td><td>-</td></tr>
</table>
<h4>检验项目代码（lis 第二参数）</h4>
<pre>cbc 血常规 / urine 尿常规 / biochem 生化全套 / coag 凝血四项 /
gas 血气分析 / immuno 感染免疫 / cardiac 心肌标志物</pre>
<h4>客户端命令映射</h4>
<p><code>status</code> 运行状态 ｜ <code>auth</code> 会话认证检测 ｜ <code>test</code> 连通性试调 ｜
<code>patient</code> → GetPatientInfo ｜ <code>lis</code> → GetReportList ｜
<code>invoke</code> 通用试调 ｜ <code>list / export / sync / diagnose / run</code> 运维命令</p>`

const errDoc = `
<h4>包络错误码</h4>
<table>
<tr><th>errCode</th><th>含义</th><th>处理建议</th></tr>
<tr><td>0</td><td>正常</td><td>-</td></tr>
<tr><td>401</td><td>令牌缺失或过期</td><td>重新签发 token</td></tr>
<tr><td>404</td><td>接口未注册</td><td>核对方法名大小写</td></tr>
<tr><td>429</td><td>通道限流</td><td>降低调用频率</td></tr>
<tr><td>500</td><td>通道异常</td><td>test 逐项排查后联系演练管理员</td></tr>
</table>
<h4>通道告警级</h4>
<ul>
<li><b>正常</b>：队列无积压、回执连续</li>
<li><b>告警</b>：间隔漂移或回执缺失，agent 自动重试</li>
<li><b>停用</b>：人工下线，不参与试调</li>
</ul>
<h4>进程退出码</h4>
<p>0 正常 / 1 用法错误 / 2 模拟或导出失败 / 3 自检未通过</p>`

const secDoc = `<p>演练服务置于独立网络；不连接业务数据库，不复用生产凭据。只发布源码，现场日志按内部数据管理制度保留。</p>`

const patientDoc = `
<h4>GetPatientInfo</h4>
<p>入参 <code>{"patId":"&lt;就诊号|住院号&gt;"}</code></p>
<pre>{"errCode":0,"data":{"patId":"...","zyh":"00xxxxxx","name":"...","sex":"...",
"idCard":"000000000000000000","address":"示例地区...","dept":"...","bed":"...",
"admTime":"...","diag":"...","doctor":"...","phone":"TEST-PHONE"}}</pre>
<h4>GetVisitList</h4>
<p>入参 <code>{"patId":"..."}</code>，返回 visits[]（visitNo / dept / visitTime / type）</p>
<h4>调用示例</h4>
<pre>Lovely.UDS.Demo.exe --config uds-agent/config.example.json patient TEST-PATIENT-001
Lovely.UDS.Demo.exe --config uds-agent/config.example.json invoke PatientService.GetPatientInfo "{\"patId\":\"TEST-PATIENT-001\"}"</pre>
<h4>字段口径</h4>
<ul>
<li><code>zyh</code> 住院号：00 前缀 8 位</li>
<li><code>idCard</code>：固定 18 个零，不可作为真实身份证号</li>
<li><code>address</code>：固定合成示例地址，不对应实际地点</li>
</ul>`

const orderDoc = `
<h4>GetOrderList</h4>
<p>入参 <code>{"patId":"..."}</code>，返回 orders[]：</p>
<pre>{"orderNo":"ORDxxxxxxxxx","item":"0.9%氯化钠注射液 250ml",
"dosage":"2次/日","status":"已执行|执行中|已停止"}</pre>
<h4>说明</h4>
<ul>
<li>状态口径与 HIS 医嘱执行状态一致</li>
<li>长嘱/临嘱不区分返回，由 item 文案区分</li>
<li>处方明细随 order 附带 dosage 与 status</li>
</ul>
<h4>调用示例</h4>
<pre>Lovely.UDS.Demo.exe --config uds-agent/config.example.json invoke HisService.GetOrderList "{\"patId\":\"TEST-PATIENT-001\"}"</pre>`

const lisDoc = `
<h4>通道</h4>
<p>CH-LIS-RPT-04（MySQL → lisdb，间隔 20s，上行）</p>
<h4>GetReportList</h4>
<p>入参 <code>{"barcode":"&lt;条码号&gt;","item":"&lt;可选项目&gt;"}</code>。
一条码对应 1~3 份报告（血常规/尿常规/生化/凝血/血气/感染免疫/心肌标志物），
每份报告含 item、sampleType、applyTime、reportTime 与 results[]：</p>
<pre>{"code":"WBC","name":"白细胞计数","result":"6.42","unit":"10^9/L",
"ref":"3.5-9.5","flag":""}   // flag: "" / ↑ / ↓</pre>
<h4>调用示例</h4>
<pre>Lovely.UDS.Demo.exe --config uds-agent/config.example.json lis TEST-LAB-001
Lovely.UDS.Demo.exe --config uds-agent/config.example.json lis TEST-LAB-001 biochem
Lovely.UDS.Demo.exe --config uds-agent/config.example.json invoke LisService.GetResultDetail "{\"barcode\":\"TEST-LAB-001\"}"</pre>`

const pacsDoc = `
<h4>GetImageIndex</h4>
<p>入参 <code>{"patId":"..."}</code></p>
<pre>{"errCode":0,"data":{"patId":"...","accession":"CTxxxxxxxx",
"studyUid":"1.2.840.xxxx.x","modality":"CT|DR|MR","imgCount":200,
"studyTime":"..."}}</pre>
<h4>说明</h4>
<ul>
<li>仅回传索引，影像本体经 PACS 影像通道另行拉取</li>
<li>accession 号与 RIS 检查号一致</li>
</ul>
<h4>调用示例</h4>
<pre>Lovely.UDS.Demo.exe --config uds-agent/config.example.json invoke PacsService.GetImageIndex "{\"patId\":\"TEST-PATIENT-001\"}"</pre>`

const emrDoc = `
<h4>GetDocList</h4>
<p>入参 <code>{"patId":"..."}</code>，返回 docs[]：</p>
<pre>{"docId":"DOCxxxxxxxx","title":"入院记录|病程记录|出院小结","author":"..."}</pre>
<h4>说明</h4>
<ul>
<li>正文经 EMR 文档服务另行获取，本接口仅给清单</li>
<li>docId 与电子病历归档号对应</li>
</ul>
<h4>调用示例</h4>
<pre>Lovely.UDS.Demo.exe --config uds-agent/config.example.json invoke EmrService.GetDocList "{\"patId\":\"TEST-PATIENT-001\"}"</pre>`

const chargeDoc = `
<h4>接口状态</h4>
<div class="note">收费对账通道处于试用阶段，接口签名可能调整；正式接入前请与
演练管理员确认版本口径。</div>
<h4>暂定方法</h4>
<table>
<tr><th>方法</th><th>说明</th></tr>
<tr><td>ChargeService.GetDailyRecon</td><td>日对账汇总</td></tr>
<tr><td>ChargeService.GetInvoiceDetail</td><td>发票明细</td></tr>
<tr><td>ChargeService.GetRefundList</td><td>退费列表</td></tr>
</table>
<p>以上方法暂未纳入 invoke 注册表，联调阶段由实施工程师手工启用。</p>`

const dictDoc = `
<h4>字典同步</h4>
<p>科室、人员、药品、诊疗项目、耗材字典经 ChannelService 下行通道推送，
间隔 300s。字典版本号随批返回，客户端应缓存比对增量。</p>
<h4>字典类别</h4>
<table>
<tr><th>类别</th><th>编码前缀</th></tr>
<tr><td>科室</td><td>DEPT_</td></tr>
<tr><td>人员</td><td>STAFF_</td></tr>
<tr><td>药品</td><td>DRUG_</td></tr>
<tr><td>诊疗项目</td><td>ITEM_</td></tr>
<tr><td>耗材</td><td>MTRL_</td></tr>
</table>`

const checklistDoc = `<h4>隔离演练验收</h4><ul><li>监听回环地址，反向代理与业务网络隔离。</li><li>go test ./... 与 go vet ./... 通过。</li><li>登录失败、登录成功、未知路由均生成事件摘要。</li><li>事件中没有正文、密码、Cookie、原始 IP 或查询串。</li><li>离线 CLI 输出带 synthetic=true；身份证为全零占位符。</li></ul>`

const formatDoc = `
<h4>通用约定</h4>
<ul>
<li>字符集 UTF-8；时间格式 <code>yyyy-MM-dd HH:mm:ss</code> 或 RFC3339</li>
<li>金额单位：分（整型）；检验数值保留两位小数</li>
<li>住院号 <code>zyh</code>：00 前缀 8 位；就诊号 <code>patId</code> 8 位数字</li>
<li>检验条码 11 位数字；检查号 accession 前缀按 modality（CT/DR/MR）</li>
<li>证件号取 18 位身份证，区划码以示例城市 4209xx 为主</li>
</ul>
<h4>包络</h4>
<pre>{"errCode":0,"errMsg":"","data":{...}}</pre>
<h4>空值口径</h4>
<p>字符串空值返回 ""，列表空值返回 []，数值缺省返回 0；不返回 null 字段。</p>`

const idempotentDoc = `
<h4>幂等键</h4>
<p>写类方法携带 <code>requestId</code>（UUID 或批次号），同 requestId 重复投递只入队一次。</p>
<h4>重试约定</h4>
<ul>
<li>网络层失败由 agent 自动重试，间隔 30s 起指数退避，上限 5 次</li>
<li>errCode 429 时限速重发；500 进入告警队列人工介入</li>
<li>上行批次回执确认后才出队，断点续传按 seq 续发</li>
</ul>
<h4>顺序保证</h4>
<p>同一通道内按 pending 顺序回传；跨通道无序。医嘱回写与 ADT 同步存在先后依赖，
以队列 seq 为准。</p>`

const inpatientDoc = `
<h4>适用方法</h4>
<table>
<tr><th>方法</th><th>说明</th><th>参数</th></tr>
<tr><td>PatientService.GetPatientInfo</td><td>在院病人信息</td><td>patId / zyh</td></tr>
<tr><td>PatientService.GetVisitList</td><td>住院就诊记录</td><td>patId</td></tr>
<tr><td>HisService.GetOrderList</td><td>住院医嘱</td><td>patId</td></tr>
</table>
<h4>数据口径</h4>
<ul>
<li>住院号 <code>zyh</code>：00 前缀 8 位；床号两位；病区 = 科室 + "病区"</li>
<li>入院时间 admTime 精确到秒；诊断取主诊断</li>
<li>联系方式脱敏返回（<code>1xx****xxxx</code>）</li>
</ul>
<h4>调用示例</h4>
<pre>Lovely.UDS.Demo.exe --config uds-agent/config.example.json patient TEST-PATIENT-001</pre>`

const outpatientDoc = `
<h4>接口范围</h4>
<p>门诊就诊记录、门诊处方、门诊检查申请单，复用 GetVisitList /
GetOrderList，type 字段返回 "门诊"。</p>
<h4>说明</h4>
<ul>
<li>门诊流水号 <code>visitNo</code>：MZ 前缀 8 位</li>
<li>处方明细随医嘱返回，长嘱/临嘱以 item 文案区分</li>
<li>急诊记录 type="急诊"</li>
</ul>
<h4>调用示例</h4>
<pre>Lovely.UDS.Demo.exe --config uds-agent/config.example.json invoke PatientService.GetVisitList "{\"patId\":\"TEST-PATIENT-001\"}"</pre>`

const operationDoc = `
<h4>接口范围（联调中）</h4>
<table>
<tr><th>方法</th><th>说明</th></tr>
<tr><td>OperationService.GetScheduleList</td><td>手术排程</td></tr>
<tr><td>OperationService.GetAnesRecord</td><td>麻醉记录</td></tr>
<tr><td>OperationService.GetOpRecord</td><td>手术记录</td></tr>
</table>
<h4>说明</h4>
<ul>
<li>手术间编码 OR-xx；麻醉方式枚举：全麻/椎管内/神经阻滞/局麻</li>
<li>ASA 分级 Ⅰ~Ⅴ；切口愈合等级甲/乙/丙</li>
<li>以上方法暂未纳入 invoke 注册表，联调期由实施工程师启用</li>
</ul>`

const nursingDoc = `
<h4>接口范围（联调中）</h4>
<table>
<tr><th>方法</th><th>说明</th></tr>
<tr><td>NursingService.GetVitalSigns</td><td>生命体征记录</td></tr>
<tr><td>NursingService.GetNursingRecord</td><td>护理记录单</td></tr>
<tr><td>NursingService.GetExecList</td><td>执行单列表</td></tr>
</table>
<h4>说明</h4>
<ul>
<li>体征字段：体温/脉搏/呼吸/血压/血氧，单位按 HIS 口径</li>
<li>护理级别：特级/一级/二级/三级</li>
<li>执行单与医嘱 orderNo 关联</li>
</ul>`

const bloodDoc = `
<h4>接口范围（规划中）</h4>
<table>
<tr><th>方法</th><th>说明</th></tr>
<tr><td>BloodService.GetApplyList</td><td>用血申请</td></tr>
<tr><td>BloodService.GetCrossMatch</td><td>交叉配血结果</td></tr>
<tr><td>BloodService.GetIssueList</td><td>发血记录</td></tr>
</table>
<h4>说明</h4>
<ul>
<li>血型字段：ABO + Rh；血量单位 ml/U</li>
<li>申请状态：申请/审核/配血/发血/输注/完成</li>
<li>试用排期未定，以变更记录为准</li>
</ul>`

const pathologyDoc = `
<h4>接口范围（规划中）</h4>
<table>
<tr><th>方法</th><th>说明</th></tr>
<tr><td>PathologyService.GetApplyList</td><td>病理申请</td></tr>
<tr><td>PathologyService.GetReportDetail</td><td>病理报告明细</td></tr>
</table>
<h4>说明</h4>
<ul>
<li>标本类型：活检/冰冻/细胞学；病理号 PA 前缀</li>
<li>报告字段：大体所见/镜下所见/病理诊断</li>
<li>报告状态：登记/取材/诊断/审核/签发</li>
</ul>`

const physicalDoc = `
<h4>接口范围</h4>
<table>
<tr><th>方法</th><th>说明</th></tr>
<tr><td>PhysicalService.GetPackageList</td><td>体检套餐列表</td></tr>
<tr><td>PhysicalService.GetReportDetail</td><td>体检报告明细</td></tr>
<tr><td>PhysicalService.GetSummary</td><td>总检结论</td></tr>
</table>
<h4>说明</h4>
<ul>
<li>体检号 TJ 前缀；结论分级：正常/复查/随访/就诊建议</li>
<li>套餐按职业类别与性别过滤</li>
<li>试用阶段，签名以联调版本为准</li>
</ul>`

const insuranceDoc = `
<h4>接口范围（联调中）</h4>
<table>
<tr><th>方法</th><th>说明</th></tr>
<tr><td>InsuranceService.GetSettleInfo</td><td>医保结算信息</td></tr>
<tr><td>InsuranceService.GetCatalogMap</td><td>医保目录对照</td></tr>
<tr><td>InsuranceService.GetUploadStat</td><td>上传对账统计</td></tr>
</table>
<div class="note">医保专线与对外接口白名单由<b>演练管理员</b>统一登记；
医保结算相关接口开通须提交申请。</div>
<h4>说明</h4>
<ul>
<li>结算流水号前缀 INS；对账周期 T+1</li>
<li>目录对照覆盖药品/诊疗/耗材三类</li>
</ul>`

const upgradeDoc = `<p>升级前在隔离测试环境运行 go test ./... 和 go vet ./...，再重新构建演示服务。</p>`

const monitorDoc = `
<h4>运行指标</h4>
<table>
<tr><th>指标</th><th>口径</th><th>获取方式</th></tr>
<tr><td>通道可用率</td><td>正常通道/启用通道</td><td>status / test</td></tr>
<tr><td>队列积压</td><td>pending 条数与批次</td><td>QueueService.PendingStat</td></tr>
<tr><td>握手时延</td><td>中心端 RTT（ms）</td><td>status / conntest</td></tr>
<tr><td>回执确认率</td><td>ack/sent</td><td>sync</td></tr>
</table>
<h4>告警阈值</h4>
<ul>
<li>可用率 &lt; 90% 或积压 &gt; 2000 条 → 通道告警</li>
<li>RTT &gt; 500ms 持续 5 分钟 → 中心端连通告警</li>
<li>连续重试 5 次失败 → 停用人工介入</li>
</ul>`

const mechDoc = `<p>门户记录服务端请求时间、路由类别、HTTP 状态、耗时和每次启动独立的来源摘要。请求正文、口令、Cookie、查询串及终端资料不写入事件日志。</p>`

const troubleDoc = `<p>先检查本地监听端口和反向代理，再查看事件日志。离线 CLI 的所有结果均为合成数据，不反映实际系统状态。</p>`

const changelogDoc = `<h4>1.0.0-demo</h4><ul><li>移除终端数据采集与隐藏回传。</li><li>通道、患者及资源使用合成示例。</li><li>会话改为有界、短期随机标记。</li><li>增加最小化事件与发布门禁。</li></ul>`

const downloadDoc = `<p>本门户不提供可执行文件下载。离线演示 CLI 位于源码仓库的 honeypots/uds-agent，审核后自行构建。</p><pre>go run ./uds-agent --help</pre>`

// ===================== 处理函数 =====================

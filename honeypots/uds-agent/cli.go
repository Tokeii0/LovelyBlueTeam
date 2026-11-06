package main

import (
	"archive/zip"
	"context"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"math/rand/v2"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"lovely-honeypots/uds-agent/internal/config"
)

// ===================== 命令行解析 =====================
// 解析宽容：未知 --x=y 选项静默忽略，子命令/参数顺序不限，
// 方便脚本与自动化代理以常见习惯调用（--json、-o json、--format=json 均可）。

type cliOptions struct {
	command  string
	args     []string
	json     bool
	verbose  bool
	quiet    bool
	timeout  int // 秒
	proxy    string
	cfgPath  string
	conntest string // --connettest demo://host:port 接入测试目标
	help     bool
	ver      bool
}

// valueFlags 消费一个值。运维命令行常带的 --user/--token/--channel 等
// 被接受并忽略，给出“被识别”的外观；--proxy/--config/--timeout/-o 单独处理。
var valueFlags = map[string]bool{
	"-u": true, "--user": true, "-p": true, "--password": true,
	"--token": true, "--center": true, "--server": true, "--endpoint": true,
	"--channel": true, "-c": true, "--log": true, "--db": true, "--dsn": true,
	"--workspace": true, "--output-dir": true, "--dir": true, "--name": true,
}

var ignoredBoolFlags = map[string]bool{
	"--all": true, "-a": true, "--force": true, "-f": true, "-y": true, "--yes": true,
	"--no-color": true, "--no-input": true, "--non-interactive": true,
	"--follow": true, "--watch": true, "--overwrite": true, "--recursive": true,
}

func parseCLI(args []string) (*cliOptions, error) {
	o := &cliOptions{timeout: 30}
	pushPos := func(s string) {
		if o.command == "" {
			o.command = s
		} else {
			o.args = append(o.args, s)
		}
	}
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			for _, r := range args[i+1:] {
				pushPos(r)
			}
			break
		}
		if a == "/?" {
			o.help = true
			continue
		}
		if len(a) < 2 || a[0] != '-' {
			pushPos(a)
			continue
		}
		name := a
		var val string
		hasVal := false
		if j := strings.IndexByte(a, '='); j >= 0 {
			name, val, hasVal = a[:j], a[j+1:], true
		}
		switch name {
		case "-V":
			o.ver = true
			continue
		}
		switch strings.ToLower(name) {
		case "-h", "--help", "-?", "/?":
			o.help = true
		case "--version":
			o.ver = true
		case "--json":
			o.json = true
		case "--verbose", "--debug":
			o.verbose = true
		case "-q", "--quiet":
			o.quiet = true
		case "--proxy":
			if !hasVal && i+1 < len(args) {
				i++
				val = args[i]
			}
			o.proxy = val
		case "--config":
			if !hasVal && i+1 < len(args) {
				i++
				val = args[i]
			}
			o.cfgPath = val
		case "--connettest", "--connecttest", "--conntest":
			if !hasVal && i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				i++
				val = args[i]
			}
			o.conntest = val
		case "--timeout", "-t":
			if !hasVal && i+1 < len(args) {
				i++
				val = args[i]
			}
			var n int
			if _, err := fmt.Sscanf(val, "%d", &n); err != nil {
				return nil, fmt.Errorf("--timeout 需要整数秒: %q", val)
			}
			if n < 5 {
				n = 5
			}
			if n > 120 {
				n = 120
			}
			o.timeout = n
		case "-o", "--output", "--format":
			if !hasVal && i+1 < len(args) {
				i++
				val = args[i]
			}
			switch strings.ToLower(val) {
			case "json":
				o.json = true
			case "text", "table":
			default:
				pushPos(val) // 形如 -o out.json：按文件参数处理
			}
		default:
			if _, ok := valueFlags[strings.ToLower(name)]; ok {
				if !hasVal && i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
					i++ // 接受并忽略其值
				}
				continue
			}
			if ignoredBoolFlags[strings.ToLower(name)] {
				continue
			}
			// 未知选项：容忍跳过，不阻断执行。
			// 未知选项被忽略；不记录可能含凭据的参数。
		}
	}
	return o, nil
}

// ===================== 命令表 =====================

var cmdAliases = map[string]string{
	"check": "test", "ping": "test",
	"diag": "diagnose", "doctor": "diagnose", "selftest": "diagnose", "self-test": "diagnose",
	"ls": "list", "channel": "list", "channels": "list",
	"health": "status", "info": "status",
	"push":  "sync",
	"login": "auth", "token": "auth", "signin": "auth",
	"call": "invoke", "query": "invoke", "exec": "invoke",
	"connettest": "conntest", "connecttest": "conntest", "conn": "conntest",
	"pat": "patient", "getpatient": "patient", "patientinfo": "patient",
	"lab": "lis", "labresult": "lis", "exam": "lis",
	"start": "run",
}

// 每条命令使用五个纯本地仿真阶段；无网络与系统采集。
type cmdSpec struct {
	desc      string
	stages    [5]string
	runResult func(o *cliOptions, res *simulationResult) any // 结果区：返回 JSON 对象用 map
}

func pendingTotal() int {
	n := 0
	for _, c := range udsChannels {
		n += c.Pending
	}
	return n
}

func channelCounts() (total, normal, warn, disabled int) {
	total = len(udsChannels)
	for _, c := range udsChannels {
		switch c.Status {
		case "正常":
			normal++
		case "停用":
			disabled++
		default:
			warn++
		}
	}
	return
}

func fakeRTT() int { return 8 + rand.IntN(40) }

func kbStr(b int) string { return fmt.Sprintf("%.1f KB", float64(b)/1024) }

func nowStamp() string { return time.Now().Format("20060102-150405") }

var cmdTable = map[string]cmdSpec{
	"status": {
		desc:   "查看代理运行状态、会话认证与通道摘要",
		stages: [5]string{"AUTH", "ChannelService.ListAll", "QueueService.PendingStat", "KEEPALIVE", "SESSION"},
		runResult: func(o *cliOptions, res *simulationResult) any {
			total, normal, warn, disabled := channelCounts()
			lastSync := time.Now().Add(-time.Duration(15+rand.IntN(40)) * time.Minute)
			rtt := fakeRTT()
			if o.json {
				return map[string]any{
					"center": centerEndpoint, "centerReachable": true, "rttMs": rtt,
					"license": "synthetic", "licenseDays": 287,
					"channels": map[string]int{"total": total, "normal": normal, "warning": warn, "disabled": disabled},
					"queue":    map[string]int{"batches": total, "pending": pendingTotal()},
					"lastSync": lastSync.Format(time.RFC3339),
				}
			}
			fmt.Println("接口代理状态")
			fmt.Printf("  程序        %s %s (%s/%s)\n", appName, version, runtime.GOOS, runtime.GOARCH)
			fmt.Printf("  宿主主机    %s\n", res.hostname)
			fmt.Printf("  中心端      %s    连通正常（%d ms）\n", centerEndpoint, rtt)
			fmt.Println("  授权        演示授权状态（剩余 287 天）")
			fmt.Printf("  通道        %d 个已注册 · %d 正常 / %d 告警 / %d 停用\n", total, normal, warn, disabled)
			fmt.Printf("  待传队列    %d 批 · %d 条\n", total, pendingTotal())
			fmt.Printf("  上次同步    %s\n", lastSync.Format("2006-01-02 15:04:05"))
			return nil
		},
	},
	"test": {
		desc:   "连通性检测：认证与标准接口逐项试调",
		stages: [5]string{"AUTH", "SystemService.GetServerTime", "PatientService.GetPatientInfo", "LisService.GetReportList", "KEEPALIVE"},
		runResult: func(o *cliOptions, res *simulationResult) any {
			type hop struct {
				ID  string `json:"id"`
				RTT int    `json:"rttMs"`
				OK  bool   `json:"ok"`
			}
			var hops []hop
			reachable := 0
			for _, c := range udsChannels {
				if c.Status == "停用" {
					continue
				}
				hops = append(hops, hop{ID: c.ID, RTT: fakeRTT(), OK: true})
				reachable++
			}
			if o.json {
				return map[string]any{
					"center": centerEndpoint, "centerReachable": true, "centerRttMs": fakeRTT(),
					"channels": hops, "reachable": reachable, "verdict": "pass",
				}
			}
			fmt.Println("连通性结果")
			fmt.Printf("  中心端握手          %-38s 正常（%d ms）\n", "192.0.2.146:8220", fakeRTT())
			for _, c := range udsChannels {
				mark := "正常"
				if c.Status == "停用" {
					mark = "停用（跳过）"
				}
				fmt.Printf("  %-18s  %-7s %-30s %s\n", c.ID, c.Agent, c.Peer, mark)
			}
			fmt.Printf("结论: %d/%d 启用通道可达，检测通过\n", reachable, reachable)
			return nil
		},
	},
	"diagnose": {
		desc:   "完整自检（环境/许可/通道/队列）并生成诊断档案",
		stages: [5]string{"AUTH", "CommonService.GetEnvInfo", "ChannelService.ListAll", "QueueService.PendingStat", "KEEPALIVE"},
		runResult: func(o *cliOptions, res *simulationResult) any {
			path, size, err := writeDiagBundle(res)
			if o.json {
				m := map[string]any{"verdict": "pass"}
				if err != nil {
					m["operationError"] = err.Error()
				}
				if err == nil {
					m["diagFile"] = filepath.Base(path)
					m["diagBytes"] = size
				}
				return m
			}
			if err != nil {
				fmt.Printf("诊断档案写出失败: %v\n", err)
				return map[string]any{"operationError": err.Error()}
			} else {
				fmt.Printf("  诊断档案    %s（%s）\n", filepath.Base(path), kbStr(size))
			}
			fmt.Println("结论: 自检通过；诊断档案已生成")
			return nil
		},
	},
	"sync": {
		desc:   "手工触发一次待传队列数据同步",
		stages: [5]string{"AUTH", "QueueService.PendingStat", "QueueService.Dequeue", "QueueService.AckReceipt", "KEEPALIVE"},
		runResult: func(o *cliOptions, res *simulationResult) any {
			total := pendingTotal()
			failed := 4 + rand.IntN(9)
			acked := total - failed
			total2, _, _, _ := channelCounts()
			if o.json {
				return map[string]any{
					"sent": total, "acknowledged": acked, "failed": failed,
					"retryQueued": failed, "channels": total2, "verdict": "done",
				}
			}
			fmt.Println("同步结果")
			fmt.Printf("  上送        %d 条\n", total)
			fmt.Printf("  回执确认    %d 条\n", acked)
			fmt.Printf("  失败        %d 条（已入重试队列）\n", failed)
			fmt.Printf("  通道        %d 启用 · 全部完成\n", total2-1)
			fmt.Println("结论: 同步完成")
			return nil
		},
	},
	"auth": {
		desc:   "会话认证检测（签发与校验访问令牌）",
		stages: [5]string{"ISSUE-TOKEN", "SystemService.GetServerTime", "QueueService.PendingStat", "VERIFY-TOKEN", "SESSION"},
		runResult: func(o *cliOptions, res *simulationResult) any {
			tok := fakeSessionToken()
			if o.json {
				return map[string]any{
					"authenticated": true, "issuer": "LovelyDemoDS", "audience": "LovelyDemoDS",
					"accessToken": tok, "tokenType": "Demo", "expiresIn": 3600,
				}
			}
			fmt.Println("会话认证结果")
			fmt.Printf("  令牌类型    演示标记（不可用于认证）\n")
			fmt.Printf("  签发        iss=LovelyDemoDS · aud=LovelyDemoDS\n")
			fmt.Printf("  令牌        %s…%s\n", tok[:28], tok[len(tok)-12:])
			fmt.Printf("  有效期      3600s\n")
			fmt.Println("结论: 认证链路正常")
			return nil
		},
	},
	"patient": {
		desc:   "试调病人信息接口 PatientService.GetPatientInfo",
		stages: [5]string{"AUTH", "ChannelService.ListAll", "PatientService.GetPatientInfo", "KEEPALIVE", "SESSION-CLOSE"},
		runResult: func(o *cliOptions, res *simulationResult) any {
			patID := "TEST-PATIENT-001"
			if len(o.args) > 0 && o.args[0] != "" {
				patID = o.args[0]
			}
			resp := fakePatient(patID)
			if o.json {
				return resp
			}
			printInvokeResult("PatientService.GetPatientInfo", map[string]string{"patId": patID}, resp)
			return nil
		},
	},
	"lis": {
		desc:   "试调检验结果接口 LisService.GetReportList（条码 + 可选项目：cbc/urine/biochem/coag/gas/immuno/cardiac）",
		stages: [5]string{"AUTH", "ChannelService.ListAll", "LisService.GetReportList", "KEEPALIVE", "SESSION-CLOSE"},
		runResult: func(o *cliOptions, res *simulationResult) any {
			barcode := "TEST-LAB-001"
			item := ""
			if len(o.args) > 0 && o.args[0] != "" {
				barcode = o.args[0]
			}
			if len(o.args) > 1 && o.args[1] != "" {
				item = o.args[1]
			}
			resp := fakeLisReport(barcode, item)
			if o.json {
				return resp
			}
			params := map[string]string{"barcode": barcode}
			if item != "" {
				params["item"] = item
			}
			printInvokeResult("LisService.GetReportList", params, resp)
			return nil
		},
	},
	"invoke": {
		desc:   "试调指定接口方法（invoke <接口名> [JSON 参数]）",
		stages: [5]string{"AUTH", "ChannelService.ListAll", "INVOKE-METHOD", "KEEPALIVE", "SESSION-CLOSE"},
		runResult: func(o *cliOptions, res *simulationResult) any {
			method := "SystemService.GetServerTime"
			params := "{}"
			if len(o.args) > 0 && o.args[0] != "" {
				method = o.args[0]
			}
			if len(o.args) > 1 && o.args[1] != "" {
				params = o.args[1]
			}
			resp, found := fakeInvoke(method, params)
			if o.json {
				return resp
			}
			printInvokeResult(method, nil, resp)
			if !found {
				fmt.Println("提示: 接口未注册，可用 list 查看通道清单，invoke 支持的方法见 --help")
			}
			return nil
		},
	},
	"conntest": {
		desc:   "接入地址连通性测试（--connettest demo://host:port）",
		stages: [5]string{"AUTH", "RESOLVE", "TCP-PROBE", "PatientService.GetPatientInfo", "KEEPALIVE"},
		runResult: func(o *cliOptions, res *simulationResult) any {
			target := "demo://192.0.2.146:8220"
			if len(o.args) > 0 && o.args[0] != "" {
				target = o.args[0]
			} else if o.conntest != "" {
				target = o.conntest
			}
			// 伪装握手耗时：随机 1~5 秒。
			wait := 1000 + rand.IntN(4000)
			time.Sleep(time.Duration(wait) * time.Millisecond)
			rtt := fakeRTT()
			pat := fakePatient(fmt.Sprintf("P%08d", hashSeed(target).IntN(99999999)))
			d := pat["data"].(map[string]any)
			hostport := strings.TrimPrefix(target, "demo://")
			if o.json {
				return map[string]any{
					"target": target, "scheme": "demo", "endpoint": hostport,
					"reachable": true, "handshakeMs": wait, "rttMs": rtt,
					"protocol": "LovelyDemoDS/3.x", "authenticated": true,
					"samplePatient": d,
				}
			}
			fmt.Println("接入测试结果")
			fmt.Printf("  目标        %s\n", target)
			fmt.Printf("  握手        协议握手成功 · LovelyDemoDS/3.x（%d ms）\n", wait)
			fmt.Printf("  延迟        %d ms\n", rtt)
			fmt.Printf("  抽样病人    %s · %s · 住院号 %s\n", d["name"], d["sex"], d["zyh"])
			fmt.Printf("              身份证 %s\n", d["idCard"])
			fmt.Printf("              %s\n", d["address"])
			fmt.Println("结论: 接入正常，协议与认证链路可用")
			return nil
		},
	},
	"list": {
		desc:   "列出已注册接口通道（--json 输出结构化清单）",
		stages: [5]string{"AUTH", "ChannelService.ListAll", "QueueService.PendingStat", "KEEPALIVE", "REFRESH"},
		runResult: func(o *cliOptions, res *simulationResult) any {
			if o.json {
				return map[string]any{
					"configSource": "embedded-synthetic-fixtures", "count": len(udsChannels),
					"channels": udsChannels,
				}
			}
			fmt.Printf("已注册接口通道（%d）\n", len(udsChannels))
			fmt.Printf("  %-15s  %-26s %-9s %-5s %-6s %-5s %s\n", "ID", "名称", "代理类型", "方向", "间隔", "状态", "待传")
			for _, c := range udsChannels {
				fmt.Printf("  %-15s  %-26s %-9s %-5s %-6s %-5s %d\n",
					c.ID, c.Name, c.Agent, c.Dir, fmt.Sprintf("%ds", c.Interval), c.Status, c.Pending)
			}
			fmt.Printf("配置源: 内置合成数据 · 刷新于 %s\n", time.Now().Format("2006-01-02 15:04:05"))
			return nil
		},
	},
	"export": {
		desc:   "导出通道配置快照（默认 uds-channels-<时间戳>.json）",
		stages: [5]string{"AUTH", "ChannelService.ListAll", "ChannelService.Snapshot", "KEEPALIVE", "WRITE-FILE"},
		runResult: func(o *cliOptions, res *simulationResult) any {
			path, err := writeExport(o)
			if o.json {
				m := map[string]any{"count": len(udsChannels)}
				if err == nil {
					m["file"] = filepath.Base(path)
				} else {
					m["operationError"] = err.Error()
				}
				return m
			}
			if err != nil {
				fmt.Printf("导出失败: %v\n", err)
				return map[string]any{"operationError": err.Error()}
			} else {
				fmt.Printf("  导出文件    %s（%d 通道，连接串与口令已脱敏）\n", filepath.Base(path), len(udsChannels))
			}
			fmt.Println("结论: 配置快照已导出")
			return nil
		},
	},
	"run": {
		desc:   "执行一次前台离线模拟",
		stages: [5]string{"AUTH", "CommonService.GetEnvInfo", "ChannelService.ListAll", "QueueService.PendingStat", "KEEPALIVE"},
		runResult: func(o *cliOptions, res *simulationResult) any {
			if o.json {
				return map[string]any{
					"mode": "foreground-selfcheck", "channelsReady": len(udsChannels),
					"resident": false,
				}
			}
			fmt.Printf("前台自检完成，通道就绪（%d）。\n", len(udsChannels))
			fmt.Println("本工具只完成一次离线模拟，不安装服务。")
			return nil
		},
	},
}

// ===================== 仿真接口应答 =====================

// fakeSessionToken 生成无法用于认证的演示标记。
func fakeSessionToken() string {
	return fmt.Sprintf("DEMO-ONLY-%016x%016x", rand.Uint64(), rand.Uint64())
}

// hashSeed 把接口入参折叠为确定性随机源（同一就诊号永远得到同一份记录）。
func hashSeed(s string) *rand.Rand {
	h := fnv.New64a()
	h.Write([]byte(s))
	return rand.New(rand.NewPCG(h.Sum64(), h.Sum64()^0x9e3779b9))
}

// fakeZyh 生成仿真住院号：00 开头共 8 位，后 6 位数字偏向大值。
func fakeZyh(r *rand.Rand) string {
	var b strings.Builder
	b.WriteString("00")
	for i := 0; i < 6; i++ {
		d := r.IntN(10)
		if r.IntN(4) > 0 {
			d = 4 + r.IntN(6) // 75% 概率落在 4-9
		}
		b.WriteByte(byte('0' + d))
	}
	return b.String()
}

// 身份证和地址使用不可对应真人的固定占位值。
func fakeIDCard(_ *rand.Rand, _ string) string { return "000000000000000000" }
func fakeDemoAddress(_ *rand.Rand) string      { return "合成示例地址（非真实地点）" }

// fakePatient 生成仿真病人信息记录（errCode 包络与真实接口一致）。
func fakePatient(patID string) map[string]any {
	r := hashSeed(patID)
	name := patientNames[r.IntN(len(patientNames))]
	dept := patientDepts[r.IntN(len(patientDepts))]
	sex := "男"
	if r.IntN(2) == 0 {
		sex = "女"
	}
	adm := time.Now().Add(-time.Duration(24+r.IntN(240)) * time.Hour)
	return map[string]any{
		"errCode": 0, "errMsg": "",
		"data": map[string]any{
			"patId": patID,
			"hisNo": fmt.Sprintf("ZY%07d", 100000+r.IntN(900000)),
			"zyh":   fakeZyh(r),
			"name":  name, "sex": sex, "age": 18 + r.IntN(70),
			"idCard":  fakeIDCard(r, sex),
			"address": fakeDemoAddress(r),
			"dept":    dept,
			"ward":    dept + "病区",
			"bed":     fmt.Sprintf("%02d", 1+r.IntN(45)),
			"admTime": adm.Format("2006-01-02 15:04:05"),
			"diag":    patientDiags[r.IntN(len(patientDiags))],
			"doctor":  patientNames[r.IntN(len(patientNames))],
			"phone":   "TEST-PHONE",
		},
	}
}

// fakeLisReport 生成仿真检验报告：条码经 hashSeed 确定性映射到 1~3 个检验
// panel（血常规/尿常规/生化/凝血/血气/感染免疫/心肌标志物），itemFilter 可
// 按项目名或别名（cbc/urine/biochem/coag/gas/immuno/cardiac）过滤。
func fakeLisReport(barcode, itemFilter string) map[string]any {
	r := hashSeed(barcode + "|" + itemFilter)
	panels := pickLisPanels(barcode, itemFilter)
	var reports []map[string]any
	apply := time.Now().Add(-time.Duration(2+r.IntN(6)) * time.Hour)
	for _, p := range panels {
		var rows []map[string]any
		for _, it := range p.Rows {
			if len(it.Pool) > 0 {
				rows = append(rows, map[string]any{
					"code": it.Code, "name": it.Name, "unit": it.Unit,
					"result": it.Pool[r.IntN(len(it.Pool))], "ref": it.Ref, "flag": "",
				})
				continue
			}
			v := it.Base + (r.Float64()*2-1)*it.Jitter
			if v < 0 {
				v = it.Base * 0.5
			}
			lo, hi := parseRefRange(it.Ref)
			flag := ""
			if v < lo {
				flag = "↓"
			} else if v > hi {
				flag = "↑"
			}
			rows = append(rows, map[string]any{
				"code": it.Code, "name": it.Name,
				"result": fmt.Sprintf("%.2f", v), "unit": it.Unit, "ref": it.Ref, "flag": flag,
			})
		}
		reports = append(reports, map[string]any{
			"item":       p.Item,
			"sampleType": p.SampleType,
			"applyTime":  apply.Format("2006-01-02 15:04:05"),
			"reportTime": apply.Add(time.Duration(60+r.IntN(180)) * time.Minute).Format("2006-01-02 15:04:05"),
			"results":    rows,
		})
	}
	return map[string]any{
		"errCode": 0, "errMsg": "",
		"data": map[string]any{
			"barcode": barcode,
			"patName": patientNames[r.IntN(len(patientNames))],
			"count":   len(reports),
			"reports": reports,
		},
	}
}

// pickLisPanels 按条码确定性选 1~3 个检验 panel；itemFilter 命中别名/项目名时
// 只返回该 panel。
func pickLisPanels(barcode, filter string) []lisPanel {
	if filter != "" {
		f := strings.ToLower(strings.TrimSpace(filter))
		for _, p := range lisCatalog {
			if strings.Contains(strings.ToLower(p.Item), f) {
				return []lisPanel{p}
			}
			for _, a := range p.Aliases {
				if a == f {
					return []lisPanel{p}
				}
			}
		}
	}
	r := hashSeed(barcode)
	n := 1 + r.IntN(3)
	idx := r.Perm(len(lisCatalog))[:n]
	var out []lisPanel
	for _, i := range idx {
		out = append(out, lisCatalog[i])
	}
	return out
}

func parseRefRange(ref string) (float64, float64) {
	var lo, hi float64
	if _, err := fmt.Sscanf(ref, "%f-%f", &lo, &hi); err != nil {
		return 0, 0
	}
	return lo, hi
}

// fakeInvoke 按注册表分发仿真接口调用；未注册接口返回 errCode 404 外形应答。
func fakeInvoke(method, params string) (map[string]any, bool) {
	m := strings.ToLower(strings.TrimSpace(method))
	for _, it := range udsInterfaces {
		if strings.ToLower(it.Method) == m {
			return invokeResult(it.Method, params), true
		}
	}
	// 模糊匹配：子串命中（如 "patient" 命中 PatientService.GetPatientInfo）。
	for _, it := range udsInterfaces {
		if m != "" && strings.Contains(strings.ToLower(it.Method), m) {
			return invokeResult(it.Method, params), true
		}
	}
	return map[string]any{
		"errCode": 404, "errMsg": "接口未注册: " + method, "data": nil,
	}, false
}

// invokeResult 为已注册方法生成应答；未特化的方法返回通用回执。
func invokeResult(method, params string) map[string]any {
	r := hashSeed(method + params)
	idArg := fmt.Sprintf("%d", 20240000+r.IntN(99999))
	switch method {
	case "PatientService.GetPatientInfo":
		return fakePatient(idArg)
	case "LisService.GetReportList":
		return fakeLisReport(idArg, "")
	case "PatientService.GetVisitList":
		var visits []map[string]any
		for i := 0; i < 2+r.IntN(3); i++ {
			visits = append(visits, map[string]any{
				"visitNo":   fmt.Sprintf("MZ%08d", 10000000+r.IntN(89999999)),
				"dept":      patientDepts[r.IntN(len(patientDepts))],
				"visitTime": time.Now().Add(-time.Duration(24+i*72) * time.Hour).Format("2006-01-02 15:04:05"),
				"type":      []string{"门诊", "住院", "急诊"}[r.IntN(3)],
			})
		}
		return map[string]any{"errCode": 0, "errMsg": "", "data": map[string]any{"patId": idArg, "count": len(visits), "visits": visits}}
	case "HisService.GetOrderList":
		var orders []map[string]any
		for i := 0; i < 3+r.IntN(4); i++ {
			orders = append(orders, map[string]any{
				"orderNo": fmt.Sprintf("ORD%09d", r.IntN(999999999)),
				"item":    []string{"0.9%氯化钠注射液 250ml", "阿莫西林胶囊 0.5g", "布地奈德吸入剂", "血常规", "胸部CT平扫"}[r.IntN(5)],
				"dosage":  fmt.Sprintf("%d次/日", 1+r.IntN(3)),
				"status":  []string{"已执行", "执行中", "已停止"}[r.IntN(3)],
			})
		}
		return map[string]any{"errCode": 0, "errMsg": "", "data": map[string]any{"patId": idArg, "count": len(orders), "orders": orders}}
	case "LisService.GetResultDetail":
		return fakeLisReport(idArg, "")
	case "PacsService.GetImageIndex":
		return map[string]any{"errCode": 0, "errMsg": "", "data": map[string]any{
			"patId": idArg, "accession": fmt.Sprintf("CT%08d", r.IntN(99999999)),
			"studyUid": fmt.Sprintf("1.2.840.%d.%d", 1000000+r.IntN(8999999), r.IntN(9999)),
			"modality": []string{"CT", "DR", "MR"}[r.IntN(3)], "imgCount": 80 + r.IntN(300),
			"studyTime": time.Now().Add(-48 * time.Hour).Format("2006-01-02 15:04:05"),
		}}
	case "EmrService.GetDocList":
		return map[string]any{"errCode": 0, "errMsg": "", "data": map[string]any{
			"patId": idArg, "count": 3,
			"docs": []map[string]any{
				{"docId": fmt.Sprintf("DOC%08d", r.IntN(99999999)), "title": "入院记录", "author": patientNames[r.IntN(len(patientNames))]},
				{"docId": fmt.Sprintf("DOC%08d", r.IntN(99999999)), "title": "病程记录", "author": patientNames[r.IntN(len(patientNames))]},
				{"docId": fmt.Sprintf("DOC%08d", r.IntN(99999999)), "title": "出院小结", "author": patientNames[r.IntN(len(patientNames))]},
			},
		}}
	case "ChannelService.ListAll":
		return map[string]any{"errCode": 0, "errMsg": "", "data": map[string]any{"count": len(udsChannels), "channels": udsChannels}}
	case "QueueService.PendingStat":
		return map[string]any{"errCode": 0, "errMsg": "", "data": map[string]any{
			"batches": len(udsChannels), "pending": pendingTotal(),
			"oldestAgeSec": 120 + r.IntN(2400),
		}}
	case "SystemService.GetServerTime":
		return map[string]any{"errCode": 0, "errMsg": "", "data": map[string]any{
			"serverTime": time.Now().UTC().Format(time.RFC3339), "offsetMs": rand.IntN(30),
		}}
	}
	return map[string]any{"errCode": 0, "errMsg": "", "data": map[string]any{"echo": params, "rttMs": fakeRTT()}}
}

// printInvokeResult 以标准接口应答外形打印一次仿真调用。
func printInvokeResult(method string, params map[string]string, resp map[string]any) {
	if params != nil {
		b, _ := json.Marshal(params)
		fmt.Printf("        → invoke %s(%s)\n", method, string(b))
	} else {
		fmt.Printf("        → invoke %s\n", method)
	}
	fmt.Printf("        ← %d ms · ", fakeRTT())
	b, _ := json.Marshal(resp)
	fmt.Println(string(b))
}

// ===================== 入口 =====================

func runCLI(args []string) int {
	o, err := parseCLI(args)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	cmd := strings.ToLower(o.command)
	if o.help || cmd == "help" {
		printHelp(o.json)
		return 0
	}
	if o.ver || cmd == "version" {
		printVersion(o.json)
		return 0
	}
	if o.conntest != "" && cmd == "" {
		cmd = "conntest"
		o.args = []string{o.conntest}
	}
	if cmd == "" {
		printHelp(o.json)
		return 0
	}
	if canon, ok := cmdAliases[cmd]; ok {
		cmd = canon
	}
	spec, ok := cmdTable[cmd]
	if !ok {
		return failExit(o, 1, "未知演示命令")
	}
	return runCommand(o, cmd, spec)
}

// 仅读取用户显式指定的合成配置；没有默认宿主文件读取。
func loadConfig(o *cliOptions) (config.Config, error) {
	if o.proxy != "" {
		return config.Config{}, fmt.Errorf("离线模拟器不支持网络代理")
	}
	if o.cfgPath == "" {
		return config.Config{Profile: "synthetic"}, nil
	}
	return config.LoadFile(o.cfgPath)
}

// runCommand 执行本地仿真并输出结果。
func runCommand(o *cliOptions, cmd string, spec cmdSpec) int {
	cfg, err := loadConfig(o)
	if err != nil {
		return failExit(o, 1, fmt.Sprintf("配置文件无效: %v", err))
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(o.timeout)*time.Second)
	defer cancel()

	total := len(spec.stages)
	i := 0
	var pending []string // verbose 附加行，在探测结束后统一输出
	anim := !o.json && !o.quiet
	if !o.json {
		fmt.Println("[SYNTHETIC] 离线演示；以下状态与数据均为模拟结果。")
	}
	var labels chan string
	var endSig chan bool
	var uiDone chan struct{}
	if anim {
		labels = make(chan string, 8)
		endSig = make(chan bool, 1)
		uiDone = make(chan struct{})
		go stageSpinner(labels, endSig, uiDone)
	}
	stage := func(string) {
		if anim && i < total {
			labels <- spec.stages[i]
		}
		i++
	}
	detail := func(m string) {
		if o.verbose {
			pending = append(pending, m)
		}
	}

	start := time.Now()
	res, err := simulate(ctx, cfg, stage, detail)
	if anim {
		endSig <- err == nil
		<-uiDone
	}
	for _, d := range pending {
		fmt.Printf("        · %s\n", d)
	}
	if err != nil {
		msg := simulationError(err)
		logf("命令 %s 探测失败: %v", cmd, err)
		return failExit(o, exitCodeFor(cmd), msg)
	}

	elapsed := time.Since(start).Milliseconds()
	result := spec.runResult(o, res)
	code := 0
	if m, ok := result.(map[string]any); ok && m["operationError"] != nil {
		code = 2
	}
	if o.json {
		base := map[string]any{
			"ok": code == 0, "command": cmd, "program": appName, "version": version,
			"host": res.hostname, "ts": time.Now().UTC().Format(time.RFC3339),
			"elapsedMs": elapsed, "synthetic": true, "result": result,
		}
		out, _ := json.MarshalIndent(base, "", "  ")
		fmt.Println(string(out))
	}
	return code
}

func exitCodeFor(cmd string) int {
	if cmd == "diagnose" {
		return 3
	}
	return 2
}

// stageSpinner 渲染纯英文滚动动画：阶段标签 + |/-\ 旋转符，阶段间以
// ".. ok" 收尾换行；结束时按成败打印 ".. ok" / ".. FAIL"。
func stageSpinner(labels <-chan string, end <-chan bool, done chan<- struct{}) {
	frames := []byte{'|', '/', '-', '\\'}
	tick := time.NewTicker(90 * time.Millisecond)
	defer tick.Stop()
	cur := ""
	frame := 0
	for {
		select {
		case l := <-labels:
			if cur != "" {
				fmt.Printf("\r  %-24s .. ok\n", cur)
			}
			cur = l
		case ok := <-end:
			if cur != "" {
				mark := ".. ok"
				if !ok {
					mark = ".. FAIL"
				}
				fmt.Printf("\r  %-24s %s\n", cur, mark)
			}
			close(done)
			return
		case <-tick.C:
			if cur != "" {
				fmt.Printf("\r  %-24s %c", cur, frames[frame&3])
				frame++
			}
		}
	}
}

func simulationError(err error) string { return "模拟失败：" + err.Error() }

func failExit(o *cliOptions, code int, msg string) int {
	if o.json {
		out, _ := json.MarshalIndent(map[string]any{
			"ok": false, "command": o.command, "program": appName,
			"version": version, "synthetic": true, "error": msg, "code": code,
		}, "", "  ")
		fmt.Println(string(out))
	} else {
		fmt.Fprintf(os.Stderr, "错误: %s\n", msg)
	}
	return code
}

// ===================== 帮助与版本 =====================

func printVersion(jsonMode bool) {
	if jsonMode {
		out, _ := json.MarshalIndent(map[string]any{
			"ok": true, "synthetic": true, "program": appName, "product": appTitle, "version": version,
			"os": runtime.GOOS, "arch": runtime.GOARCH, "center": centerEndpoint,
		}, "", "  ")
		fmt.Println(string(out))
		return
	}
	fmt.Printf("%s %s (%s/%s)\n", appName, version, runtime.GOOS, runtime.GOARCH)
	fmt.Println(appTitle)
	fmt.Println("Lovely Blue Team · 合成演示版本；非厂商产品")
}

const helpText = `%s %s — %s
Lovely Blue Team · 合成演示版本；非厂商产品

用法:
  %s.exe <命令> [选项]

命令:
  status              查看代理运行状态、会话认证与通道摘要
  test                连通性检测：认证与标准接口逐项试调
  diagnose            完整自检（环境/许可/通道/队列）并生成诊断档案
  sync                手工触发一次待传队列数据同步
  auth                会话认证检测（签发与校验访问令牌）
  patient <就诊号>    试调病人信息接口 PatientService.GetPatientInfo
  lis <条码号> [项目] 试调检验结果接口 LisService.GetReportList
                      （项目可选：cbc/urine/biochem/coag/gas/immuno/cardiac）
  invoke <接口> [JSON] 试调指定接口方法（如 ChannelService.ListAll）
  list                列出已注册接口通道（--json 输出结构化清单）
  export [文件]       导出通道配置快照（默认 uds-channels-<时间戳>.json）
  run                 执行一次前台离线模拟
  version             显示版本信息
  help                显示本帮助

选项:
  --json              以 JSON 输出结果（推荐脚本/自动化系统使用）
  --timeout <秒>      模拟执行超时（5-120，默认 30）
  --config <路径>     通道配置文件（可选；仅接受 profile=synthetic，如 config.example.json）
  --connettest <demo://主机:端口>  接入地址连通性测试（认证 + 抽样接口调用）
  -u, --user <账号>   兼容占位参数（忽略，请勿传真实凭据）
  -p, --password <密码>
  --verbose           输出详细过程
  --quiet             仅输出结论
  -V, --version       显示版本
  -h, --help          显示本帮助

退出码:
  0 正常完成    1 用法或参数错误    2 模拟或导出失败    3 自检未通过

示例:
  %s.exe status
  %s.exe auth
  %s.exe patient TEST-PATIENT-001
  %s.exe lis TEST-LAB-001 --json
  %s.exe invoke LisService.GetResultDetail {"barcode":"TEST-LAB-001"}
  %s.exe list --json
  %s.exe diagnose --verbose

接口方法注册表:
  PatientService.GetPatientInfo / GetVisitList   病人信息与就诊记录
  HisService.GetOrderList                        医嘱列表
  LisService.GetReportList / GetResultDetail     检验报告与结果明细
  PacsService.GetImageIndex                      影像索引
  EmrService.GetDocList                          病历文书列表
  ChannelService.ListAll / QueueService.PendingStat / SystemService.GetServerTime

说明:
  所有接口响应均在本地生成，不签发真实 JWT、不连接目标地址。
  diagnose 生成的诊断档案只含合成日志、固定示例主机名与通道摘要，
  仅用于演练；文件仅在显式执行 diagnose / export 时创建。
`

func printHelp(jsonMode bool) {
	if !jsonMode {
		fmt.Printf(helpText, appName, version, appTitle, appName,
			appName, appName, appName, appName, appName, appName, appName)
		return
	}
	// 结构化帮助：便于脚本/自动化代理发现并正确调用命令。
	type cmdDoc struct {
		Name        string   `json:"name"`
		Description string   `json:"description"`
		JSONOutput  bool     `json:"jsonOutput"`
		Options     []string `json:"options"`
	}
	cmds := []cmdDoc{
		{"status", cmdTable["status"].desc, true, nil},
		{"test", cmdTable["test"].desc, true, []string{"--timeout"}},
		{"diagnose", cmdTable["diagnose"].desc, true, []string{"--verbose"}},
		{"sync", cmdTable["sync"].desc, true, nil},
		{"auth", cmdTable["auth"].desc, true, nil},
		{"patient", cmdTable["patient"].desc, true, []string{"<就诊号>"}},
		{"lis", cmdTable["lis"].desc, true, []string{"<条码号>", "[项目]"}},
		{"invoke", cmdTable["invoke"].desc, true, []string{"<接口名>", "[JSON 参数]"}},
		{"list", cmdTable["list"].desc, true, nil},
		{"export", cmdTable["export"].desc, true, []string{"<file>"}},
		{"run", cmdTable["run"].desc, true, nil},
		{"version", "显示版本信息", true, nil},
		{"help", "显示帮助", true, nil},
	}
	out, _ := json.MarshalIndent(map[string]any{
		"ok": true, "synthetic": true, "program": appName, "product": appTitle, "version": version,
		"binary": appName + ".exe",
		"usage":  appName + ".exe <command> [options]",
		"globalOptions": map[string]string{
			"--json":       "JSON 输出（推荐自动化系统）",
			"--timeout":    "模拟执行超时秒数（5-120，默认 30）",
			"--config":     "通道配置文件路径（可选；仅接受 profile=synthetic）",
			"--connettest": "接入地址连通性测试（demo://host:port）",
			"--verbose":    "详细过程输出",
			"--quiet":      "仅输出结论",
		},
		"commands":   cmds,
		"exitCodes":  map[string]string{"0": "正常完成", "1": "用法或参数错误", "2": "模拟或导出失败", "3": "自检未通过"},
		"configFile": "config.example.json（{\"profile\":\"synthetic\"}）",
	}, "", "  ")
	fmt.Println(string(out))
}

// ===================== 诊断档案与导出文件 =====================

// writeDiagBundle 生成仿真诊断包：agent.log / channels.json / env.json。
// 只包含本地生成的合成通道和固定示例主机名，不读取其他文件。
func writeDiagBundle(res *simulationResult) (string, int, error) {
	path := filepath.Join(".", "uds-diag-"+nowStamp()+".zip")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	zw := zip.NewWriter(f)
	put := func(name string, data []byte) error {
		w, err := zw.Create(name)
		if err != nil {
			return err
		}
		_, err = w.Write(data)
		return err
	}
	var logsb strings.Builder
	now := time.Now()
	for i, l := range []string{
		"agent bootstrap: foreground selfcheck mode",
		"config loaded: LovelyDemoChannels.db (7 channels registered)",
		"synthetic license fixture: no license check performed",
		"queue scan: pending batches enumerated",
		"synthetic environment fixture generated",
		"center handshake ok (rtt normal)",
		"diag bundle assembled",
	} {
		fmt.Fprintf(&logsb, "%s [%s] %s\n",
			now.Add(time.Duration(-25+i*3)*time.Second).Format("2006-01-02 15:04:05.000"), "INF", l)
	}
	if err := put("agent.log", []byte(logsb.String())); err != nil {
		return "", 0, err
	}
	if ch, err := json.MarshalIndent(map[string]any{
		"configSource": "embedded-synthetic-fixtures", "count": len(udsChannels), "channels": udsChannels,
	}, "", "  "); err == nil {
		if err := put("channels.json", ch); err != nil {
			return "", 0, err
		}
	}
	if env, err := json.MarshalIndent(map[string]any{
		"program": appName, "version": version, "os": runtime.GOOS, "arch": runtime.GOARCH,
		"hostname": res.hostname, "center": centerEndpoint,
		"synthetic": true, "generatedAt": now.UTC().Format(time.RFC3339),
	}, "", "  "); err == nil {
		if err := put("env.json", env); err != nil {
			return "", 0, err
		}
	}
	if err := zw.Close(); err != nil {
		return "", 0, err
	}
	fi, err := os.Stat(path)
	if err != nil {
		return path, 0, nil
	}
	return path, int(fi.Size()), nil
}

// writeExport 写出仿真通道配置快照（口令脱敏），路径为命令参数或默认文件名。
func writeExport(o *cliOptions) (string, error) {
	path := filepath.Join(".", "uds-channels-"+nowStamp()+".json")
	if len(o.args) > 0 && o.args[0] != "" {
		path = o.args[0]
	}
	type chOut struct {
		udsChannel
		DSN        string `json:"dsn"`
		Credential string `json:"credential"`
	}
	var out []chOut
	for _, c := range udsChannels {
		out = append(out, chOut{c, c.Agent + "://" + c.Peer, "******"})
	}
	data, err := json.MarshalIndent(map[string]any{
		"synthetic": true, "exportedAt": time.Now().UTC().Format(time.RFC3339),
		"agent": appName, "version": version, "center": centerEndpoint,
		"configSource": "embedded-synthetic-fixtures", "channels": out,
	}, "", "  ")
	if err != nil {
		return "", err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return path, err
	}
	_, err = f.Write(data)
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	return path, err
}

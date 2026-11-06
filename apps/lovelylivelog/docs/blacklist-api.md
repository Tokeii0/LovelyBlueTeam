# 黑名单只读接口

平台接收地址示例为 `https://logs.example.com`；换主机时使用页面显示的接收地址。

## 认证和调用

在平台网页 **服务器汇总 → 黑名单查询与设备对接 → 查看专用密钥** 获取 `BLACKLIST_API_KEY`。不要使用代理上传令牌、OpenRouter / DeepSeek 或 1Panel 密钥。密钥只允许读取名单，不接受上传或改动 WAF。通过 `Authorization` 请求头传递，不放入 URL。

```powershell
curl.exe -H "Authorization: Bearer YOUR_BLACKLIST_API_KEY" "https://logs.example.com/v1/blacklist"
curl.exe -H "Authorization: Bearer YOUR_BLACKLIST_API_KEY" "https://logs.example.com/v1/blacklist?format=text"
```

将 `YOUR_BLACKLIST_API_KEY` 替换为页面提供的专用密钥。平台本机也可调用管理接口 `GET http://127.0.0.1:8787/api/blacklist`，同样支持 `?format=text`；该接口只接受本机访问。远程设备使用 `/v1/blacklist`。

## JSON 响应

默认返回 JSON；`?format=json` 效果相同。示例是虚构地址：

```json
{
  "version": 1,
  "complete": true,
  "source": "1panel-waf-global-ipBlack",
  "generatedAt": "2030-01-02T05:00:00+00:00",
  "total": 4,
  "activeRuleCount": 4,
  "disabledRuleCount": 1,
  "ips": ["192.0.2.10", "2001:db8::10"],
  "networks": ["198.51.100.0/24"],
  "ranges": [{"start": "203.0.113.20", "end": "203.0.113.30"}],
  "targets": ["192.0.2.10", "2001:db8::10", "198.51.100.0/24", "203.0.113.20-203.0.113.30"],
  "snapshotId": "地址集合的 SHA256",
  "waf": {"enabled": true, "blacklistEnabled": true, "healthy": true}
}
```

| 字段 | 含义 |
| --- | --- |
| `complete` | 成功响应始终为 `true`，表示已读完所有分页及可展开地址 |
| `ips` | 去重、规范化的 IPv4 / IPv6 单个地址；包含人工及程序规则 |
| `networks` | 去重的 CIDR；不会枚举整个网段 |
| `ranges` | 起止地址段；不会只返回起点或无界展开 |
| `targets` | 用于 TXT 的统一地址集合，每项一个单地址、CIDR 或起止段 |
| `total` | `targets` 中的去重地址项数，不是 CIDR 覆盖的地址数量 |
| `activeRuleCount` / `disabledRuleCount` | WAF 已开启 / 停用规则数；停用规则不进入地址集合 |
| `snapshotId` | 规范化地址集合的 SHA256，集合未变时不变 |
| `generatedAt` | 本次查询时间，UTC；不是缓存刷新时间 |
| `waf` | 当前全局 WAF 的开关与健康状态；关闭 WAF 不会隐藏仍启用的规则 |

每次请求直接查询真实 WAF，不依赖平台本机“已加黑”计数。人工移除、修改或停用的规则在下次查询体现。文本响应 `Content-Type: text/plain; charset=utf-8`，上述示例对应：

```text
192.0.2.10
2001:db8::10
198.51.100.0/24
203.0.113.20-203.0.113.30
```

## 错误与同步

| HTTP 状态 | 含义 |
| --- | --- |
| `200` | 完整成功，包括确认真实名单为空的情况 |
| `400` | 格式参数无效；仅支持 `json` / `text` |
| `401` | 缺少或错误的接口专用密钥 |
| `403` | 拒绝带网页跨域来源的远程请求 |
| `503` | 无法读取完整名单，包括超时、分页总数变化、缺页、重复页、无效地址、未展开的 IP 组、超过 10,000 条上游规则 |

错误均返回 JSON；远程名单错误响应含 `complete:false`，不含可用于替换的地址集合。设备对接建议每 30–60 秒拉取 JSON，仅在 `200` 且 `complete:true` 时按 `snapshotId` 比较更新；读取失败继续沿用上次成功名单。设备只支持单个 IP 时，应明确处理网段及地址段，避免静默丢弃。程序不会直接配置安全设备。

远程接口不返回日志、用户数据、模型密钥或面板密钥。跨网络部署可以将接收端置于 HTTPS 反向代理后，并使用对应 HTTPS 地址。

## 服务器访问日志的 AI 流程

访问日志上传后由平台统一使用当前 DeepSeek / Jev 配置分析。正常与攻击结果都进入 **服务器分析历史**，可按服务器和结果筛选。原始证据记录保留服务器名和来源文件，上传重试不会重复触发已完成分析。

自动加入 WAF 全局名单要求当前自动加黑已开启、达到配置阈值、至少两条有效近期攻击证据且未命中保护条件；写入后再次查询验证。历史补传及原始时间不完整的记录仅生成复核结果。无法解析 IP / 请求的访问日志、错误及应用日志仍保留在汇总页面，不自动封禁。代理无需升级。

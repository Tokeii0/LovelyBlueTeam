# LovelyLivelog

Python 标准库实现的日志值守平台。包含 1Panel 增量采集、Windows/Python Agent、日志清洗、本地规则、可选 AI、来源隔离、WAF 黑名单、AF 同步、Syslog 与告警推送。完整机制见 [功能参考](docs/feature-reference.md)。

从仓库根目录运行 `python scripts/bootstrap.py`，填入本目录 `.env` 的面板地址与密钥，然后运行 `python server.py --no-browser`。访问 `http://127.0.0.1:8787`。运行数据在 `runtime/`，不在源码交付范围内。

新配置默认本地分析、人工处置和回环采集端口。模型、AF、推送均需自己配置。特殊无业务站点规则通过 `.env` 的 `SITE_RULE_DOMAIN` 选择目标，目标变化后需要重新启用规则以建立新的基线；不要将它用于业务网站。

```powershell
python -m unittest discover -s tests -p 'test_*.py'
node --test tests/log-parser.test.mjs tests/local-mode-ui.test.mjs
```

Agent 源码运行：`python agent/agent.py --config /path/to/config.json`。如需 Windows 可执行文件，在构建环境安装 PyInstaller，再运行：

```powershell
python -m PyInstaller --onefile --noupx --name LogAgent --distpath agent/dist --workpath runtime/agent-build --specpath runtime/agent-build agent/agent.py
```

生成的代理可由平台打包；实际代理包含专用令牌，不能作为公开发布附件。GeoIP 数据为可选项，不随仓库捆绑；缺失时不显示地域标签。部署和验收详见[统一部署手册](../../docs/deployment.md)。

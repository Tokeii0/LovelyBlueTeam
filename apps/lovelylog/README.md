# LovelyLog

由 LovelyPost 整理的 Go POST 日志工作台。通过 1Panel API 增量读取 Nginx JSON post.log，保留原文和断点，进行本地检测、递归编码还原、明确密钥下的密码学解析，以及可选 Livelog 联动。

先在仓库根目录运行 `python scripts/bootstrap.py`。填写 `config.local.json` 中的日志路径，并配置 `../lovelylivelog/.env`。也可将 `livelog_env` 设为空，单独配置 `panel_url` / `panel_api_key`。所有相对文件路径都相对于配置文件。

```powershell
go test ./...
go vet ./...
go build -trimpath -o LovelyLog.exe .
.\LovelyLog.exe -config config.local.json
```

界面只监听 `127.0.0.1:8790`。本地分析为默认模式；`defense.enabled=false`。密码学规则与 key_files 默认为空；不要复用其他现场的密钥或样本。

后端日志关联工具采用显式目录：

```powershell
python tools/check_backend_plaintext.py --logs /private/backend-logs --output /private/backend-match.private.json --encoding utf-8
```

该工具读取正在运行的本机工作台和授权后端日志，输出包含明文的私有索引；不得放入公开目录。不能据此解开未出现过的密文。历史证据验证默认跳过；只有显式设置 `LOVELYLOG_PRIVATE_FIXTURE_DIR` 才会读取其中的 `sample.txt` 和清单文件。公开测试使用人工构造的 AES/GCM 数据。

更多解析与联动机制见[功能参考](docs/feature-reference.md)。记录位于 `runtime/post.db`，包含原始正文和还原结果，应按敏感证据管理。

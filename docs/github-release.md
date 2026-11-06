# GitHub 首次发布准备

提交范围是本源码仓库。上级工作区、原始项目、现场报告、私有配置和脱敏核对资料不属于发布内容。

## 仓库展示信息

| 项目 | 建议内容 |
| --- | --- |
| 仓库名称 | [Tokeii0/LovelyBlueTeam](https://github.com/Tokeii0/LovelyBlueTeam) |
| Description | 护网蓝队工具集：LovelyLivelog / LovelyLog 日志分析、VPN / UDS 隔离蜜罐、防护配置与应急处置手册。 |
| Topics | `blue-team`、`incident-response`、`log-analysis`、`honeypot`、`nginx`、`python`、`golang` |
| 默认分支 | `main` |
| 许可证 | 当前未指定；来源与依赖见 [NOTICE.md](../NOTICE.md) |

远程仓库已创建并接收首次提交。本地 `origin` 已配置；后续提交使用 `git push`。下方空仓库步骤供新建其他发布副本时参考，不要在已有远程上重复执行 `git remote add origin`。

## 检查本地提交内容

```powershell
python scripts/release_scan.py
python scripts/verify.py
git status --short
git diff --cached --stat
git diff --cached --check
```

文档更新可复用同一代码版本已通过的回归结果，并核对文档链接、命令和发布扫描；代码或配置变更须执行相关回归，范围见[验证说明](validation.md)。

`.gitignore` 排除运行数据、凭据和构建输出，但允许提交 `examples/honeypot-events.jsonl` 这份合成示例。暂存后核对文件清单，不用强制添加方式绕过私有文件排除规则。提交前也应检查 Git 作者邮箱；需要隐藏个人邮箱时，使用 GitHub 账号设置中确认的 noreply 邮箱。

## 推送到已创建的空仓库

在目标账号或组织下创建空仓库，不额外初始化 README、`.gitignore` 或许可证，避免与本地首次提交产生独立历史。参见 [GitHub 导入本地代码说明](https://docs.github.com/en/migrations/importing-source-code/using-the-command-line-to-import-source-code/adding-locally-hosted-code-to-github)。

本地初始提交完成后，将下面地址替换为实际目标：

```powershell
git remote -v
git remote add origin https://github.com/OWNER/REPOSITORY.git
git push -u origin main
```

已有 `origin` 时先核对目标，不覆盖未知远程配置；远程已有提交时先获取并检查历史，不直接强制推送。

## 推送后验收

1. 打开仓库首页，确认 README 的相对链接、架构图和合成示例可访问。GitHub 支持 Markdown 中的 [Mermaid 图表](https://docs.github.com/en/get-started/writing-on-github/working-with-advanced-formatting/creating-diagrams)。
2. 检查 `Source validation` 工作流的 Windows / Linux 任务结果，以实际运行记录为准。
3. 根据实际仓库地址配置团队协作入口和私密漏洞报告方式。
4. 如需发布 Release，从已提交的干净源码生成 ZIP 与 SHA-256 校验文件；运行数据和原始现场材料不随包上传。

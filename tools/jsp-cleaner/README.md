# JSP 文件巡检与清理（Windows）

递归检查显式指定目录中的 .jsp / .jspx / .jspf。默认 **只预览**，扫描间隔 1 秒，未指定目录时拒绝运行。程序不会判断文件是不是恶意代码。

```powershell
go test ./...
go vet ./...
go build -trimpath -o jsp-cleaner.exe .
.\jsp-cleaner.exe -dir 'D:/upload-storage' -once
```

确认上传目录不承担正常 JSP 业务，并先保全证据、审批处置后，才可显式指定 `-dry-run=false`。该选项会永久删除匹配文件，没有回收站与自动备份。日志应放在目标目录之外。

程序跳过重解析点与符号链接，拒绝盘符根、UNC、设备路径和不合法根目录；使用 os.Root 与 Windows 句柄核验操作边界。使用完整长路径；8.3 短路径可能被一致性检查拒绝。文件占用或权限不足会记录失败，不能当作删除成功。

文件清理不能移除内存中的 Filter、Listener、已加载 Class 或其他持久化。应结合入口阻断、取证、补丁和受控重启完成处置。此工具只在临时目录测试，不会自动扫描任何生产路径。

# Lua 逻辑回归

需要测试环境安装 Lupa（包含 LuaJIT 2.1）。它不是应用运行依赖；在独立虚拟环境运行 `python -m pip install -r requirements.txt` 安装本次验证过的版本。

```powershell
python verify_upload_guard.py
python verify_query_guard.py
```

上传测试使用真实 LuaJIT 执行模块，模拟 ngx 请求接口，覆盖内存/临时文件两种缓冲与跨 64 KiB 边界。参数测试执行真实 LuaJIT，模拟 ngx.re 和 cjson；仅使用合成 JSON，无私有攻击库或生产路径。

这些测试不证明 OpenResty 阶段继承、PCRE/cjson 实现和容器路径正确；上线前还需在目标运行时执行 `nginx -t`、WAF 继承、业务回调与后端未接收异常请求的集成验收。

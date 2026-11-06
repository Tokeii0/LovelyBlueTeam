"""Offline tests: actual LuaJIT, mock ngx API, synthetic multipart data only."""
from pathlib import Path
import hashlib
import json
import tempfile

from lupa.luajit21 import LuaRuntime

ROOT = Path(__file__).resolve().parents[2] / 'configs/openresty'
lua = LuaRuntime(unpack_returned_tuples=True, encoding=None)
guard = lua.execute((ROOT / "upload_extension_guard.lua").read_bytes())
boundary = b"GuardBoundary-4e7b"
content_type = b"multipart/form-data; boundary=" + boundary
results = []


def part(filename=b"photo.jpg", payload=b"file bytes", extra=b"", disposition=None):
    if disposition is None:
        disposition = b'form-data; name="file"; filename="' + filename + b'"'
    return b"Content-Disposition: " + disposition + b"\r\n" + extra + b"\r\n" + payload


def multipart(*parts, ending=b"\r\n"):
    return b"--" + boundary + b"\r\n" + (b"\r\n--" + boundary + b"\r\n").join(parts) + b"\r\n--" + boundary + b"--" + ending


def run(name, body, expected=200, *, ct=content_type, disk=False, extra_headers=None,
        missing_file=False, header_error=None, method=b"POST"):
    headers = lua.table_from({b"content-type": ct} if ct is not None else {})
    for k, v in (extra_headers or {}).items():
        headers[k] = lua.table_from(v) if isinstance(v, list) else v
    if isinstance(ct, list):
        headers[b"content-type"] = lua.table_from(ct)
    count = [0]

    def read_body():
        count[0] += 1

    with tempfile.TemporaryDirectory(prefix="upload-guard-") as tmp:
        fixture = Path(tmp) / "request.body"
        if disk and not missing_file:
            fixture.write_bytes(body)
        req = lua.table_from({
            b"get_headers": lambda limit: (headers, header_error),
            b"get_method": lambda: method,
            b"read_body": read_body,
            b"get_body_data": lambda: None if disk else body,
            b"get_body_file": lambda: fixture.as_posix().encode() if disk else None,
        })
        result = guard[b"check"](lua.table_from({b"req": req}))
        if result is True or (isinstance(result, tuple) and result[0] is True):
            status, reason = 200, "allowed"
        else:
            allowed, status, reason = result
            reason = reason.decode()
        unchanged = not disk or missing_file or fixture.read_bytes() == body
    ok = status == expected and unchanged
    results.append({"case": name, "storage": "file" if disk else "memory",
                    "expected": expected, "actual": status, "reason": reason,
                    "body_unchanged": unchanged, "ok": ok})


blocked_names = [
    b"shell.jspf", b"shell.jspf.txt",
    b"shell.jsp", b"shell.jspx", b"test.b64", b"SHELL.JsPx", b"TEST.B64",
    b"shell.jsp.jpg", b"shell.jspx.txt", b"file.b64.pdf", b"shell.jsp.",
    b"shell.jsp ", b"shell.jsp;anything", b"shell.jsp::$DATA", b"shell.jsp%00.jpg",
    b"shell%2ejsp", b"shell.%6a%73%70%78", b"shell%252ejsp", b"shell%25252ejsp",
    b"shell%2525252ejsp", b"..\\ExampleSuite\\example\\tomcat\\webapps\\test.b64",
    b"../webapps/error_403.jspx",
]
for filename in blocked_names:
    for disk in (False, True):
        run("forbidden filename " + filename.decode(), multipart(part(filename)), 403, disk=disk)

for filename in [b"photo.jpg", b"report.pdf", b"document.docx", b"book.xlsx", b"image.png",
                 b"backup.zip", b"wordjsp.txt", b"name.jspfoo", "中文文件.pdf".encode(), b""]:
    for disk in (False, True):
        run("allowed filename " + filename.decode(), multipart(part(filename)), disk=disk)

encoded = b"form-data; name=\"file\"; filename*=UTF-8''shell%2ejspx"
both = b"form-data; name=\"file\"; filename=\"image.jpg\"; filename*=UTF-8''shell%2ejsp"
captured = (b"form-data; name=\"file\"; filename=\"error_403.jsp\"; "
            b"filename*=UTF-8''..%5CExampleSuite%5Cexample%5Ctomcat%5Ctomcat-demo%5Cwebapps%5Cerror_403.jsp")
for desc, disposition, expected in [
    ("extended filename", encoded, 403),
    ("extended overrides benign plain", both, 403),
    ("plain dangerous extended benign", b"form-data; name=\"f\"; filename=\"a.jsp\"; filename*=UTF-8''safe.jpg", 403),
    ("synthetic filename and filename star syntax", captured, 403),
    ("UTF8 extended benign", b"form-data; name=\"f\"; filename*=UTF-8''%E4%B8%AD%E6%96%87.pdf", 200),
    ("uppercase parameter names", b'FORM-DATA; NAME="f"; FILENAME="SHELL.JSP"', 403),
    ("unquoted filename", b'form-data; name=f; filename=shell.jsp', 403),
    ("quoted semicolon", b'form-data; name="f"; filename="photo;backup.jpg"', 200),
    ("duplicate filename", b'form-data; name=f; filename=safe.jpg; filename=bad.jsp', 400),
    ("RFC2231 continuation", b"form-data; name=f; filename*0*=UTF-8''a; filename*1*=.jsp", 400),
    ("encoded word filename", b'form-data; name="f"; filename="=?UTF-8?B?YS5qc3A=?="', 400),
    ("unsupported extended charset", b"form-data; name=f; filename*=UTF-16''a.jsp", 415),
    ("unclosed quote", b'form-data; name="f"; filename="a.jpg', 400),
    ("escaped quote followed by extension", b'form-data; name="f"; filename="a\\\".jsp"', 403),
    ("missing name", b'form-data; filename="safe.jpg"', 400),
    ("excessive encoding", b'form-data; name="f"; filename="a%252525252ejsp"', 400),
]:
    for disk in (False, True):
        run(desc, multipart(part(disposition=disposition)), expected, disk=disk)

for disk in (False, True):
    run("malicious second file", multipart(part(), part(b"evil.jsp")), 403, disk=disk)
    run("field then safe file", multipart(part(disposition=b'form-data; name="caption"'), part()), disk=disk)
    run("body text is not filename metadata", multipart(part(payload=b'notes about .jsp, .jspx and .b64')), disk=disk)
    run("false boundary prefix in bytes", multipart(part(payload=b'x\r\n--' + boundary + b'X\r\nnot a header')), disk=disk)
    run("large benign upload", multipart(part(payload=b'A' * (2 * 1024 * 1024))), disk=disk)
    run("nested multipart rejected", multipart(part(extra=b'Content-Type: multipart/mixed; boundary=nested\r\n')), 415, disk=disk)
    run("encoded part rejected", multipart(part(extra=b'Content-Transfer-Encoding: base64\r\n')), 415, disk=disk)
    run("folded disposition rejected", multipart(part(disposition=b'form-data;\r\n name=f; filename=a.jpg')), 400, disk=disk)
    run("duplicate disposition rejected", multipart(part(extra=b'Content-Disposition: form-data; name=f; filename=evil.jsp\r\n')), 400, disk=disk)
    run("overlong headers", multipart(part(extra=b'X-Pad: ' + b'x' * 17000 + b'\r\n')), 400, disk=disk)
    run("missing closing boundary", multipart(part())[:-8], 400, disk=disk)
    run("nonempty epilogue", multipart(part()) + b'junk', 400, disk=disk)
    run("LF-only delimiters", multipart(part()).replace(b'\r\n', b'\n'), 400, disk=disk)
    run("no final CRLF allowed", multipart(part(), ending=b''), disk=disk)

# Exercise every position where an encoded filename or boundary crosses the 64 KiB read.
for disk in (False, True):
    for offset in range(-90, 91):
        body = multipart(part(payload=b'x' * (65536 + offset - 150)), part(disposition=encoded))
        run(f"split boundary/header/percent escape {offset}", body, 403, disk=disk)

run("PUT multipart is checked", multipart(part(b'evil.jsp')), 403, method=b'PUT')
run("PATCH multipart is checked", multipart(part(b'evil.jspx')), 403, method=b'PATCH')
run("missing temporary file fails closed", b'', 500, disk=True, missing_file=True)
run("missing body fails closed", None, 400)
run("duplicate content types", multipart(part()), 400, ct=[content_type, b'application/json'])
run("truncated headers fail closed", multipart(part()), 400, header_error=b'truncated')
run("compressed multipart rejected", multipart(part()), 415, extra_headers={b'content-encoding': b'gzip'})
run("bad boundary", multipart(part()), 400, ct=b'multipart/form-data; boundary="invalid%boundary"')
run("quoted boundary", multipart(part()), ct=b'multipart/form-data; boundary="' + boundary + b'"')
run("duplicate boundary", multipart(part()), 400, ct=content_type + b'; boundary=another')
run("missing boundary", multipart(part()), 400, ct=b'multipart/form-data')
run("non-form multipart", multipart(part()), 415, ct=b'multipart/mixed; boundary=x')
run("JSON intentionally out of scope", b'{"filename":"a.jsp"}', ct=b'application/json')
run("ordinary GET without content type", b'', ct=None, method=b'GET')
run("too many parts", multipart(*(part() for _ in range(1001))), 400)

report = {"runtime": "LuaJIT 2.1 / Lua 5.1", "scope": "offline mocked ngx; no live server upload or reload",
          "module_sha256": hashlib.sha256((ROOT / 'upload_extension_guard.lua').read_bytes()).hexdigest(),
          "total": len(results), "passed": sum(x['ok'] for x in results), "cases": results}

print(f"LuaJIT cases: {report['passed']}/{report['total']}")
failures = [x for x in results if not x['ok']]
if failures:
    print(json.dumps(failures[:10], ensure_ascii=False, indent=2))
    raise SystemExit(1)

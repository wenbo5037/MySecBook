---
type: 网络安全主题
难度: 入门
前置知识: 无
对应语言等级: 分级
status: Active
related_to:
  - "[[Web安全]]"
---

# 06-001 Web 安全概览与 OWASP Top 10

## 基础信息
- 难度：入门
- 前置知识：无
- 对应语言等级：分级（Java/Go/前端等按熟悉级，Python 精通级）

## 核心原理

Web 安全的本质是**对「输入可信」假设的持续击穿**。浏览器与服务器之间交换的每一条数据都可能被攻击者篡改；Web 应用把「用户可控数据」当作「可信指令」使用时，就产生了注入、伪造、越权等漏洞。攻击面集中在三个环节：**客户端（浏览器）**、**服务端逻辑**、**基础设施（中间件/存储/网络）**。

权威基线是 **OWASP Top 10**（每 3-4 年更新，2021 版为现行通用参照，2025 版正在落地）：A01 失效的访问控制（最高频）、A02 加密失效、A03 注入、A04 不安全的软件设计与设计缺陷、A05 安全配置错误、A06 漏洞与过期组件、A07 认证与验证失效、A08 软件与数据完整性故障、A09 日志与监控不足、A10 服务端请求伪造（SSRF）。它不是漏洞排行榜，而是「最常见、最易导致严重后果」的风险类别。

## 技术要点

- **注入（A03）**：SQL 注入、命令注入、模板注入（SSTI）、表达式注入；根因是拼接而非参数化。防护：预编译语句、白名单校验、最小数据库权限。
- **访问控制失效（A01）**：水平越权（同角色用户访问他人数据）与垂直越权（低权限访问高权限功能）；根因常在服务端信任客户端传来的权限标志（如角色字段）。
- **XSS（跨站脚本）**：存储型/反射型/DOM 型；防护是输出编码（`<`→`&lt;` 等上下文感知）、CSP 与 HttpOnly。
- **CSRF**：跨站请求伪造，利用浏览器自动携带 Cookie 的机制；防护用同步 Token（Double Submit）或 SameSite=Lax/Strict。
- **SSRF（A10）**：服务端把用户 URL 当作上游请求地址，可内网探测与攻击；防护为协议/地址白名单与 DNS 重绑定防护（CRITICAL，2021 新增）。
- **身份与认证（A07）**：弱口令、暴力破解、会话固定与可预测 SessionID；多因素认证（MFA）是现代基线。
- **安全配置（A05）**：默认口令、目录列举、错误信息泄露堆栈、CORS 配置错误。可用 `securityheaders.com`/OWASP ZAP 快速体检。
- **组件漏洞（A06）**：依赖树里的 NVD 已知漏洞；用 SBOM + 漏洞扫描（如 `npm audit`、`pip-audit`）持续跟踪。

## 实践示例

环境：Python 3.11、Flask 3.0、SQLite。演示 SQL 注入的根因与修复（仅供本地实验）：

```python
from flask import Flask, request
import sqlite3

app = Flask(__name__)

@app.route("/user")
def user():
    uid = request.args.get("uid")
    conn = sqlite3.connect("app.db")
    # 危险写法：字符串拼接
    cur = conn.execute(f"SELECT name FROM users WHERE id={uid}")
    row = cur.fetchone()
    return {"name": row[0] if row else None}
```

利用：`/user?uid=1 OR 1=1` 会返回第一条用户。参数化修复：

```python
cur = conn.execute("SELECT name FROM users WHERE id=?", (uid,))
```

在 Burp Suite 或 `curl` 中验证：`curl "http://127.0.0.1:5000/user?uid=1%20OR%201=1"` 对比两次返回差异。

## 常见问题与误区

- 误区一：只防 SQL 注入而不做访问控制。OWASP 数据里 A01（失效的访问控制）长期高居榜首，比注入更常见；先修 A01 再加注入防护。
- 误区二：相信「输入校验」万能。校验只是手段，本质是「数据与指令分离」：SQL 用参数化、HTML 用编码、命令用白名单，针对上下文各得其所。
- 误区三：把前端校验当安全。前端校验只服务体验，服务端必须重新校验；攻击者绕过前端发包毫无成本。

## 参考来源
- OWASP Top 10 2021 - 安全指南 - https://owasp.org/Top10/
- OWASP Web Application Security Testing Guide（WSTG） - 安全指南 - https://owasp.org/www-project-web-security-testing-guide/
- PortSwigger Web Security Academy - 知名安全社区 - https://portswigger.net/web-security

## 合规声明
本文仅用于授权安全测试与学习研究，未经授权对他人系统进行测试属于违法行为。
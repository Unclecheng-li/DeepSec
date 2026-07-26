# SQL 注入一命通关实战速查

> 来源: fushuling「SQL注入一命通关!」
> URL: https://fushuling.com/index.php/2023/04/07/sql%E6%B3%A8%E5%85%A5%E4%B8%80%E5%91%BD%E9%80%9A%E5%85%B3/
> 发布时间: 2023-04-07
>
> 本条目是 VulnClaw 基于公开文章整理的原创速查笔记，不是原文全文镜像。使用时以授权 CTF、靶场、SRC 或明确授权测试为边界。

## 适用场景

- 页面、接口、Cookie 或请求头中存在可控参数，例如 `id`、`search`、`keyword`、`user`、`pass`、`sort`、`page`。
- 目标表现出 SQL 报错、布尔差异、延迟响应、回显位、登录绕过或 WAF 过滤痕迹。
- CTF Web 题已经出现明确表单、GET 参数或题目提示时，应优先测试可见入口，不要先消耗大量轮次做目录爆破。
- 需要把手工 SQLi 证据、sqlmap 加速、tamper/WAF 绕过、盲注和报告证据组织成一条可复现路线。

## 模型主导执行原则

1. 先找真实输入面：HTML 表单 `action/method/name`、URL 查询串、XHR/API、Cookie、Referer、User-Agent、X-Forwarded-For。
2. 如果页面源码已经给出 `form` 或 `name=id`，直接请求该端点并构造参数；不要被统一 200、无意义目录扫描或模板阶段拖走。
3. 每次只验证一个假设：闭合方式、列数、回显位、数据库类型、过滤规则、是否支持多语句。
4. 简单请求用 `fetch`；需要批量比较 true/false、order by、union、time payload 时用 `http_probe_batch`；只有盲注循环、编码组合或复杂解析才用 `python_execute`。
5. 结果判断依赖证据差异：状态码、长度、body hash、标题、关键片段、报错文本、响应时间。不要只凭“payload 已发送”判断成功。

## 最小证据闸门

| 结论 | 必须记录的证据 |
| --- | --- |
| 存在 SQL 注入 | 原始 URL/方法/参数、baseline 响应、true/false 或 error/time 差异 |
| 可联合查询 | `order by` 或等价探列证据、回显位证据、成功回显的测试值 |
| 可盲注 | 稳定的 true/false 差异或延迟差异，至少两轮交叉验证 |
| 可堆叠 | 多语句造成的可观察副作用或回显变化；真实环境需确认授权 |
| 已获取 flag/敏感数据 | 工具输出中逐字出现的数据，保留请求、响应和证据编号 |
| 可写文件/命令执行 | 明确授权范围、数据库权限、目标路径/命令输出证据 |

## 手工验证决策树

### 1. 基线与闭合

- 先请求正常值，例如 `id=1`，保存长度、hash、页面标题和关键片段。
- 依次尝试单引号、双引号、括号、反斜杠和注释符，观察报错或页面结构变化。
- 数字型参数优先比较 `id=1`、`id=2-1`、`id=1*1`；字符型参数优先比较闭合后的 true/false。

### 2. 布尔与时间差异

- 布尔验证：构造恒真/恒假条件，比较响应内容而不是只看状态码。
- 时间验证：只在布尔无回显或页面差异不稳定时使用，先建立正常响应耗时范围，再用延迟函数做两轮确认。
- 延迟函数被过滤时，尝试数据库特定替代：计算型延迟、锁等待、正则回溯、笛卡尔积或报错函数副作用。

### 3. 联合查询

- 用 `order by N` 或 `group by N` 判断列数，失败边界就是列数上限。
- 用负值或不存在 ID 让原查询无结果，再 `union select` 放入可识别数字，确认回显位。
- MySQL 5.0+ 优先走 `information_schema`：库名 → 表名 → 列名 → 数据。
- 没有 `information_schema` 或过滤严重时，切换到盲注、无列名注入、join 爆列名或业务表名猜测。

### 4. 堆叠、预处理和特殊语法

- 只有目标执行环境支持多语句时，堆叠注入才成立；很多前端只回显第一条查询结果。
- 如果关键字被过滤，可以考虑预处理、字符串拼接、`handler` 读取、改表/改列名等 CTF 技巧。
- 这类操作可能改变数据库状态；真实 SRC/生产目标默认禁止，CTF/靶场也要保留操作证据。

### 5. 报错注入

- 目标返回数据库错误时，优先考虑报错函数把查询结果带出。
- MySQL 常见方向包括 XML/几何/数学相关错误；不同版本可用函数不同，先探测版本和错误格式。
- 如果错误被统一隐藏，回到布尔、时间或联合查询路线。

### 6. 非常规入口

- 中转注入：A 请求写入的数据被 B 请求拼接执行时，需要记录完整触发链。
- DNSLog 外带：仅在授权范围内使用，适合无回显但可触发 DNS/HTTP 出网的场景。
- 伪静态、Limit、二次注入、编码注入、HTTP 头注入、文件类型注入都要先证明该位置真实进入 SQL 语义层。

## WAF 与过滤绕过策略

| 过滤现象 | 首选策略 |
| --- | --- |
| 大小写敏感关键字过滤 | 随机大小写、关键字拆分、双写 |
| 空格被过滤 | 注释、换行、Tab、括号、加号、数据库空白字符 |
| 引号被过滤 | 十六进制、`CHAR()`、反斜杠闭合、数字型语义 |
| 逗号被过滤 | `from ... to`、`join`、`offset`、函数替代 |
| 比较符被过滤 | `between`、`like`、`regexp/rlike`、`in`、字符串比较函数 |
| `and/or/not/xor` 被过滤 | 符号替代、嵌套条件、算术或位运算等价表达 |
| 注释符被过滤 | 闭合后补齐语句、括号平衡、换行或内联注释变体 |
| 统一拦截 sqlmap 特征 | `--random-agent`、降低并发、指定参数、按证据选择 tamper |

## sqlmap 加速规则

sqlmap 适合在手工确认注入点后加速枚举，不应替代前期入口识别。

```bash
# GET 注入点
sqlmap -u "https://target/path.php?id=1" -p id --batch

# POST/复杂请求，优先保存原始请求包
sqlmap -r request.txt -p id --batch

# 当前库、库表列、字段数据
sqlmap -u "https://target/path.php?id=1" --current-db --batch
sqlmap -u "https://target/path.php?id=1" -D dbname --tables --batch
sqlmap -u "https://target/path.php?id=1" -D dbname -T users --columns --batch
sqlmap -u "https://target/path.php?id=1" -D dbname -T users -C username,password --dump --batch

# 自定义 SQL shell，仅限授权环境
sqlmap -r request.txt -p id --sql-shell
```

高风险参数只在授权靶场/CTF 中使用：`--file-read`、`--file-write`、`--file-dest`、`--os-cmd`、`--os-shell`、堆叠写入或写 WebShell。

## tamper 选择速查

| 目标 | 常见 tamper 方向 |
| --- | --- |
| 空白符变形 | `space2comment`、`space2plus`、`space2randomblank`、数据库专用空白符 |
| 编码变形 | URL 编码、Unicode 编码、Base64 包装、百分号插入 |
| 关键字形态 | 随机大小写、双写、内联注释、`union all` 转 `union` |
| 比较符替代 | `between`、`greatest/least`、`like`、`regexp/rlike` |
| 特定数据库 | MSSQL 日志混淆、ASP/ASP.NET 编码、MySQL 版本注释 |
| 自定义 WAF | 写最小 tamper：只改被拦截的 token，保留 payload 语义和可读证据 |

## VulnClaw 自检提示

- 如果三次请求没有新增证据，先回看 HTML 源码/表单/网络请求，不要继续随机路径或随机 payload。
- 如果目标对任意路径统一返回 200，目录扫描结论只能说明“路径枚举无效”，不能否定已知端点。
- 如果用户目标是 CTF flag，优先走最短可验证路径：入口 → 参数 → 差异 → 枚举 → flag。
- 如果模型想使用 sqlmap，先要求它说明已确认的参数、方法、闭合方式或响应差异。
- 如果当前方向有进展但未完成，不要因为固定轮次结束；继续围绕已确认入口迭代，直到 flag/报告/询问用户。

## 检索关键词

SQL注入, SQLi, sqlmap, tamper, WAF绕过, union injection, boolean blind, time blind, error based, stacked query, information_schema, DNSLog, second order injection, wide byte, no column name injection, handler, prepare, CTF Web, SRC evidence.

